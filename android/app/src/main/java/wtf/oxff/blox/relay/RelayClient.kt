package wtf.oxff.blox.relay

import java.io.Closeable
import java.io.IOException
import java.util.Base64
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.sse.EventSource
import okhttp3.sse.EventSourceListener
import okhttp3.sse.EventSources
import org.json.JSONObject
import uniffi.blox_ffi.Outgoing
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/** The relay's HTTP API (BLOX.md §8.2). */
class RelayClient(baseUrl: String, allowCleartext: Boolean) {
    private val base = baseUrl.trimEnd('/')

    init {
        require(base.startsWith("https://") || (allowCleartext && base.startsWith("http://"))) {
            "relay must use HTTPS"
        }
    }

    val host: String = base.substringAfter("://")

    // Read timeout well above the relay's 15 s ping interval.
    private val http = OkHttpClient.Builder().readTimeout(60, TimeUnit.SECONDS).build()

    suspend fun post(out: Outgoing) {
        val req = Request.Builder()
            .url("$base/v1/m/${out.mailboxId}")
            .post(out.body.toRequestBody(OCTET))
            .build()
        http.newCall(req).await().use { if (it.code != 202) throw IOException("relay returned ${it.code}") }
    }

    suspend fun ack(mailboxId: String, bearer: String, seq: Long) {
        val req = Request.Builder()
            .url("$base/v1/m/$mailboxId/$seq")
            .delete()
            .header("Authorization", "Bearer $bearer")
            .build()
        http.newCall(req).await().close()
    }

    /**
     * Reads a mailbox until closed, reconnecting with backoff. Deliveries may repeat
     * after a reconnect (at-least-once); the Rust session drops duplicates.
     */
    fun subscribe(
        mailboxId: String,
        bearer: String,
        onMessage: (seq: Long, body: ByteArray) -> Unit,
        onConnection: (connected: Boolean) -> Unit,
        onUnauthorized: () -> Unit,
    ): Closeable = Subscription(mailboxId, bearer, onMessage, onConnection, onUnauthorized).also { it.start() }

    private inner class Subscription(
        private val mailboxId: String,
        private val bearer: String,
        private val onMessage: (Long, ByteArray) -> Unit,
        private val onConnection: (Boolean) -> Unit,
        private val onUnauthorized: () -> Unit,
    ) : Closeable {
        private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        private var source: EventSource? = null
        private var loop: Job? = null

        fun start() {
            loop = scope.launch {
                var backoff = 250L
                while (true) {
                    val ended = connectOnce()
                    if (ended == End.UNAUTHORIZED) {
                        onUnauthorized()
                        return@launch
                    }
                    if (ended == End.CONNECTED_THEN_LOST) backoff = 250L
                    onConnection(false)
                    delay(backoff)
                    backoff = (backoff * 2).coerceAtMost(5_000L)
                }
            }
        }

        private suspend fun connectOnce(): End = suspendCancellableCoroutine { cont ->
            val req = Request.Builder()
                .url("$base/v1/m/$mailboxId")
                .header("Authorization", "Bearer $bearer")
                .header("Accept", "text/event-stream")
                .build()
            var opened = false
            source = EventSources.createFactory(http).newEventSource(req, object : EventSourceListener() {
                override fun onOpen(eventSource: EventSource, response: Response) {
                    opened = true
                    onConnection(true)
                }

                override fun onEvent(eventSource: EventSource, id: String?, type: String?, data: String) {
                    if (type != "msg") return
                    val json = JSONObject(data)
                    onMessage(json.getLong("seq"), Base64.getUrlDecoder().decode(json.getString("body")))
                }

                override fun onClosed(eventSource: EventSource) {
                    if (cont.isActive) cont.resume(if (opened) End.CONNECTED_THEN_LOST else End.FAILED)
                }

                override fun onFailure(eventSource: EventSource, t: Throwable?, response: Response?) {
                    val end = when {
                        response?.code == 401 -> End.UNAUTHORIZED
                        opened -> End.CONNECTED_THEN_LOST
                        else -> End.FAILED
                    }
                    if (cont.isActive) cont.resume(end)
                }
            })
            cont.invokeOnCancellation { source?.cancel() }
        }

        override fun close() {
            loop?.cancel()
            source?.cancel()
            scope.cancel()
        }
    }

    private enum class End { FAILED, CONNECTED_THEN_LOST, UNAUTHORIZED }

    private companion object {
        val OCTET = "application/octet-stream".toMediaType()
    }
}

private suspend fun Call.await(): Response = withContext(Dispatchers.IO) {
    suspendCancellableCoroutine { cont ->
        enqueue(object : Callback {
            override fun onResponse(call: Call, response: Response) = cont.resume(response)
            override fun onFailure(call: Call, e: IOException) = cont.resumeWithException(e)
        })
        cont.invokeOnCancellation { cancel() }
    }
}
