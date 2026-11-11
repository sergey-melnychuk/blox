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
import uniffi.blox_ffi.relayHost
import uniffi.blox_ffi.signRelayRequest
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/** The relay refused a request; `code` is the `{"error": code}` value (§8.2). */
class RelayException(val status: Int, val code: String?) : IOException("relay: $status ${code ?: ""}")

/**
 * The relay's HTTP API (BLOX.md §8.2) with signed requests (§4.4) and relay time (§4.8).
 * `base` is a normalized relay URL; signed paths start at `/v1/`.
 */
class RelayClient(val base: String, allowCleartext: Boolean) {
    init {
        require(base.startsWith("https://") || (allowCleartext && base.startsWith("http://"))) { "relay must use HTTPS" }
    }

    val host: String = relayHost(base)

    // Read timeout well above the relay's 15 s ping interval.
    private val http = OkHttpClient.Builder().readTimeout(60, TimeUnit.SECONDS).build()

    /** Relay clock minus local clock, in seconds. */
    @Volatile private var offset = 0L
    @Volatile private var synced = false

    /** Relay time (§4.8). */
    fun now(): ULong = (System.currentTimeMillis() / 1000 + offset).toULong()

    suspend fun syncTime() {
        val req = Request.Builder().url("$base/v1/info").get().build()
        http.newCall(req).await().use { res ->
            if (!res.isSuccessful) throw RelayException(res.code, null)
            val now = JSONObject(res.body.string()).getLong("now")
            offset = now - System.currentTimeMillis() / 1000
            synced = true
        }
    }

    /** POST an envelope with a connection token, signed by the signer's `K`. */
    suspend fun post(inbox: String, body: ByteArray, token: String, sigSecret: ByteArray) {
        signed("POST", "/v1/inbox/$inbox", body, sigSecret, mapOf("Blox-Token" to token)).close()
    }

    /** POST `bind` with the QR code's ticket (no signature). Throws [RelayException] on 409/401. */
    suspend fun postWithTicket(inbox: String, ticket: String, body: ByteArray) {
        val req = Request.Builder()
            .url("$base/v1/inbox/$inbox")
            .header("Blox-Ticket", ticket)
            .post(body.toRequestBody(OCTET))
            .build()
        http.newCall(req).await().use { res -> if (!res.isSuccessful) throw RelayException(res.code, errorCode(res)) }
    }

    suspend fun ack(inbox: String, seq: Long, sigSecret: ByteArray) {
        signed("DELETE", "/v1/inbox/$inbox/$seq", ByteArray(0), sigSecret, emptyMap()).close()
    }

    /** Revokes a token (§5.5); either party may. */
    suspend fun revoke(token: String, sigSecret: ByteArray) {
        signed("POST", "/v1/revoke", ByteArray(0), sigSecret, mapOf("Blox-Token" to token)).close()
    }

    private suspend fun signed(method: String, path: String, body: ByteArray, sigSecret: ByteArray, headers: Map<String, String>): Response {
        if (!synced) syncTime()
        repeat(2) { attempt ->
            val auth = signRelayRequest(sigSecret, method, path, now(), body)
            val builder = Request.Builder().url("$base$path").header("Authorization", auth)
            headers.forEach { (k, v) -> builder.header(k, v) }
            when (method) {
                "POST" -> builder.post(body.toRequestBody(OCTET))
                "DELETE" -> builder.delete()
                else -> builder.get()
            }
            val res = http.newCall(builder.build()).await()
            if (res.isSuccessful) return res
            val code = errorCode(res)
            res.close()
            if (code == "clock" && attempt == 0) {
                syncTime()
            } else {
                throw RelayException(res.code, code)
            }
        }
        error("unreachable")
    }

    private fun errorCode(res: Response): String? =
        runCatching { JSONObject(res.body.string()).getString("error") }.getOrNull()

    /**
     * Reads an inbox until closed, reconnecting with backoff and signing each connection
     * afresh. Deliveries may repeat after a reconnect (at least once); Rust recognises them.
     */
    fun subscribe(
        inbox: String,
        sigSecret: ByteArray,
        onMessage: (seq: Long, body: ByteArray) -> Unit,
        onConnection: (connected: Boolean) -> Unit,
    ): Closeable = Subscription(inbox, sigSecret, onMessage, onConnection).also { it.start() }

    private inner class Subscription(
        private val inbox: String,
        private val sigSecret: ByteArray,
        private val onMessage: (Long, ByteArray) -> Unit,
        private val onConnection: (Boolean) -> Unit,
    ) : Closeable {
        private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        private var source: EventSource? = null
        private var loop: Job? = null

        fun start() {
            loop = scope.launch {
                var backoff = 250L
                while (true) {
                    val end = runCatching { connectOnce() }.getOrDefault(End.FAILED)
                    if (end == End.CLOCK) runCatching { syncTime() }
                    if (end == End.CONNECTED_THEN_LOST) backoff = 250L
                    onConnection(false)
                    delay(backoff)
                    backoff = (backoff * 2).coerceAtMost(5_000L)
                }
            }
        }

        private suspend fun connectOnce(): End {
            if (!synced) syncTime()
            val path = "/v1/inbox/$inbox"
            val auth = signRelayRequest(sigSecret, "GET", path, now(), ByteArray(0))
            return suspendCancellableCoroutine { cont ->
                val req = Request.Builder()
                    .url("$base$path")
                    .header("Authorization", auth)
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
                        val code = response?.let { errorCode(it) }
                        val end = when {
                            code == "clock" -> End.CLOCK
                            opened -> End.CONNECTED_THEN_LOST
                            else -> End.FAILED
                        }
                        if (cont.isActive) cont.resume(end)
                    }
                })
                cont.invokeOnCancellation { source?.cancel() }
            }
        }

        override fun close() {
            loop?.cancel()
            source?.cancel()
            scope.cancel()
        }
    }

    private enum class End { FAILED, CONNECTED_THEN_LOST, CLOCK }

    private companion object {
        val OCTET = "application/octet-stream".toMediaType()
    }
}

suspend fun Call.await(): Response = withContext(Dispatchers.IO) {
    suspendCancellableCoroutine { cont ->
        enqueue(object : Callback {
            override fun onResponse(call: Call, response: Response) = cont.resume(response)
            override fun onFailure(call: Call, e: IOException) = cont.resumeWithException(e)
        })
        cont.invokeOnCancellation { cancel() }
    }
}
