package wtf.oxff.blox.session

import java.io.Closeable
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import uniffi.blox_ffi.CloseReason
import uniffi.blox_ffi.FfiException
import uniffi.blox_ffi.Incoming
import uniffi.blox_ffi.PendingRequest
import uniffi.blox_ffi.RejectReason
import uniffi.blox_ffi.Session
import uniffi.blox_ffi.UiDisplay
import wtf.oxff.blox.BuildConfig
import wtf.oxff.blox.relay.RelayClient
import wtf.oxff.blox.vault.AccountStore

/**
 * One signing session at a time (BLOX.md §5, §10.3). All protocol work happens in the
 * Rust [Session]; this class moves bytes to and from the relay and drives the UI state.
 */
class SessionController(private val accounts: AccountStore) {
    sealed interface State {
        data object Idle : State
        data object Joining : State
        data class Waiting(val info: Info) : State
        data class Reviewing(val info: Info, val request: PendingRequest, val display: UiDisplay) : State
        data class Ended(val message: String) : State
    }

    data class Info(val label: String, val relayHost: String, val connected: Boolean, val signed: Int, val rejected: Int)

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val _state = MutableStateFlow<State>(State.Idle)
    val state: StateFlow<State> = _state

    private var session: Session? = null
    private var relay: RelayClient? = null
    private var subscription: Closeable? = null
    private var info: Info? = null
    private val queue = ArrayDeque<PendingRequest>()
    private var idleTimer: Job? = null
    private var capTimer: Job? = null
    private var backgroundTimer: Job? = null

    fun join(uri: String) {
        if (session != null) return
        _state.value = State.Joining
        scope.launch {
            val s = try {
                Session.join(uri, accounts.addresses())
            } catch (e: FfiException) {
                _state.value = State.Ended("Invalid QR code: ${e.message}")
                return@launch
            }
            val r = try {
                RelayClient(s.relayUrl(), allowCleartext = BuildConfig.DEBUG)
            } catch (e: IllegalArgumentException) {
                s.close()
                _state.value = State.Ended("This QR code's relay does not use HTTPS")
                return@launch
            }
            session = s
            relay = r
            info = Info(s.label(), r.host, connected = false, signed = 0, rejected = 0)
            subscription = r.subscribe(
                s.mailboxId(),
                s.bearer(),
                onMessage = { seq, body -> scope.launch { onDelivery(seq, body) } },
                onConnection = { up -> scope.launch { updateInfo { it.copy(connected = up) } } },
                onUnauthorized = { scope.launch { finish("The relay rejected this session") } },
            )
            try {
                r.post(s.hello())
            } catch (e: Exception) {
                finish("Relay ${r.host} is unreachable")
                return@launch
            }
            capTimer = scope.launch {
                delay(MAX_SESSION_MS)
                end(CloseReason.TIMEOUT, "Session expired (15 min)")
            }
            restartIdle()
            showNext()
        }
    }

    private suspend fun onDelivery(seq: Long, body: ByteArray) {
        val s = session ?: return
        val r = relay ?: return
        val incoming = s.onEnvelope(body, nowSecs())
        runCatching { r.ack(s.mailboxId(), s.bearer(), seq) }
        when (incoming) {
            is Incoming.Request -> {
                queue.addLast(incoming.request)
                restartIdle()
                showNext()
            }
            is Incoming.AutoRejected -> {
                runCatching { r.post(incoming.reply) }
                updateInfo { it.copy(rejected = it.rejected + 1) }
            }
            is Incoming.Closed -> finish(
                when (incoming.reason) {
                    CloseReason.CONTESTED -> "Session aborted: another device joined. Someone may have seen the QR code."
                    CloseReason.TIMEOUT -> "The computer closed the session (timeout)"
                    else -> "The computer closed the session"
                },
            )
            Incoming.Ignored -> {}
        }
    }

    /** Signs the request under review. `phrase` is wiped here. */
    fun approve(request: PendingRequest, phrase: ByteArray) {
        val s = session ?: return phrase.fill(0)
        val index = accounts.indexOf(request.account())
        try {
            if (index == null) return
            val out = s.approve(request, phrase, index.toUInt())
            reply(request, out, approved = true)
        } catch (e: FfiException) {
            _state.value = State.Ended("Signing failed: ${e.message}")
        } finally {
            phrase.fill(0)
        }
    }

    fun reject(request: PendingRequest) {
        val s = session ?: return
        runCatching { reply(request, s.reject(request, RejectReason.USER), approved = false) }
    }

    private fun reply(request: PendingRequest, out: uniffi.blox_ffi.Outgoing, approved: Boolean) {
        val r = relay ?: return
        queue.remove(request)
        request.close()
        updateInfo { if (approved) it.copy(signed = it.signed + 1) else it.copy(rejected = it.rejected + 1) }
        scope.launch {
            runCatching { r.post(out) }.onFailure { finish("Could not reach the relay to send the answer") }
            restartIdle()
            showNext()
        }
    }

    /** The user tapped Done. */
    fun done() = end(CloseReason.DONE, null)

    fun onBackground() {
        if (session == null) return
        backgroundTimer = scope.launch {
            delay(BACKGROUND_MS)
            end(CloseReason.DONE, "Session ended: the app was in the background")
        }
    }

    fun onForeground() {
        backgroundTimer?.cancel()
    }

    /** Back to the home screen after an ended session. */
    fun dismiss() {
        if (session == null) _state.value = State.Idle
    }

    private fun end(reason: CloseReason, message: String?) {
        val s = session ?: return
        val r = relay
        val bye = s.end(reason)
        scope.launch {
            if (bye != null && r != null) runCatching { r.post(bye) }
            finish(message)
        }
    }

    /** Wipes all session state (§5.4). */
    private fun finish(message: String?) {
        idleTimer?.cancel()
        capTimer?.cancel()
        backgroundTimer?.cancel()
        subscription?.close()
        queue.forEach { it.close() }
        queue.clear()
        session?.close()
        session = null
        relay = null
        subscription = null
        info = null
        _state.value = if (message == null) State.Idle else State.Ended(message)
    }

    private fun restartIdle() {
        idleTimer?.cancel()
        idleTimer = scope.launch {
            delay(IDLE_MS)
            if (queue.isEmpty()) end(CloseReason.TIMEOUT, "Session ended after 2 minutes without requests")
        }
    }

    private fun showNext() {
        val i = info ?: return
        val next = queue.firstOrNull()
        _state.value = if (next == null) State.Waiting(i) else State.Reviewing(i, next, next.display())
    }

    private fun updateInfo(f: (Info) -> Info) {
        val i = info ?: return
        info = f(i)
        when (val st = _state.value) {
            is State.Waiting -> _state.value = State.Waiting(info!!)
            is State.Reviewing -> _state.value = st.copy(info = info!!)
            else -> {}
        }
    }

    private fun nowSecs(): ULong = (System.currentTimeMillis() / 1000).toULong()

    private companion object {
        const val IDLE_MS = 120_000L
        const val MAX_SESSION_MS = 15 * 60_000L
        const val BACKGROUND_MS = 30_000L
    }
}
