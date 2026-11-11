package wtf.oxff.blox.keystore

import java.io.Closeable
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import uniffi.blox_ffi.ApproveOutcome
import uniffi.blox_ffi.ConnectionRecord
import uniffi.blox_ffi.FfiException
import uniffi.blox_ffi.Inbox
import uniffi.blox_ffi.Incoming
import uniffi.blox_ffi.IncomingRequest
import uniffi.blox_ffi.OfferInfo
import uniffi.blox_ffi.RejectReason
import uniffi.blox_ffi.Response
import uniffi.blox_ffi.ReviewOutcome
import uniffi.blox_ffi.ReviewedRequest
import uniffi.blox_ffi.UiDisplay
import uniffi.blox_ffi.broadcastTransaction
import uniffi.blox_ffi.parseOffer
import uniffi.blox_ffi.relayHost
import wtf.oxff.blox.BloxApp
import wtf.oxff.blox.BuildConfig
import wtf.oxff.blox.relay.HttpEndpoint
import wtf.oxff.blox.relay.RelayClient
import wtf.oxff.blox.relay.RelayException
import wtf.oxff.blox.store.StoredAnswer
import wtf.oxff.blox.store.StoredConnection

/**
 * The keystore's side of connections and requests (BLOX.md §5, §10.4–§10.8). Protocol work
 * happens in Rust ([Inbox], [IncomingRequest]); this class moves bytes, keeps the stores and
 * drives the UI state.
 *
 * While the app is in the foreground it holds one reader per (relay, signer) that has
 * connections there; 30 s after going to the background it closes them (§10.6).
 */
class Keystore(private val app: BloxApp) {
    /** One request on the review queue. */
    data class Pending(
        val requestId: String,
        val connectionId: String,
        val label: String,
        val signerId: String,
        val relay: String,
        val seq: Long,
        val request: IncomingRequest,
        val state: ReviewState,
    )

    sealed interface ReviewState {
        data object Loading : ReviewState
        data class Ready(val review: ReviewedRequest, val display: UiDisplay) : ReviewState
        data class WouldFail(val message: String) : ReviewState
        data class Unreachable(val message: String) : ReviewState
        /** The site withdrew it (§6.5); Approve is disabled. */
        data object Withdrawn : ReviewState
        data class Done(val response: Response) : ReviewState
    }

    sealed interface ConnectState {
        data object Idle : ConnectState
        /** The QR code names a relay that isn't on the list (§10.3). */
        data class RelayConsent(val uri: String, val offer: OfferInfo) : ConnectState
        data class Choose(val uri: String, val offer: OfferInfo) : ConnectState
        data class Working(val label: String) : ConnectState
        data class Connected(val label: String, val account: String) : ConnectState
        data class Failed(val message: String) : ConnectState
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val _pending = MutableStateFlow<List<Pending>>(emptyList())
    val pending: StateFlow<List<Pending>> = _pending
    private val _status = MutableStateFlow("")
    val status: StateFlow<String> = _status
    private val _connect = MutableStateFlow<ConnectState>(ConnectState.Idle)
    val connect: StateFlow<ConnectState> = _connect
    private val _notice = MutableStateFlow<String?>(null)
    val notice: StateFlow<String?> = _notice

    private class Reader(val relay: RelayClient, val signerId: String, val inbox: Inbox, val sig: ByteArray) {
        var sub: Closeable? = null
        var online = false
    }

    private val readers = mutableMapOf<Pair<String, String>, Reader>()
    private val relays = mutableMapOf<String, RelayClient>()
    /** Last nonce sent per (chain, address) since the app started (§10.4). */
    private val lastSent = mutableMapOf<Pair<Long, String>, ULong>()
    private val waitingBound = mutableMapOf<String, CompletableDeferred<ConnectionRecord>>()
    private var backgroundJob: Job? = null
    private var ticker: Job? = null

    // ---- lifecycle --------------------------------------------------------------------

    fun onForeground() {
        backgroundJob?.cancel()
        startReaders()
        if (ticker?.isActive != true) {
            ticker = scope.launch {
                while (true) {
                    expireOld()
                    delay(5_000)
                }
            }
        }
    }

    fun onBackground() {
        backgroundJob = scope.launch {
            delay(BACKGROUND_MS)
            stopReaders()
            ticker?.cancel()
        }
    }

    private fun relay(url: String): RelayClient =
        relays.getOrPut(url) { RelayClient(url, allowCleartext = BuildConfig.DEBUG) }

    private fun startReaders() {
        val now = System.currentTimeMillis() / 1000
        val live = app.connections.prune(now)
        live.map { it.record.relay to it.signerId }.distinct().forEach { (relay, signer) ->
            runCatching { reader(relay, signer) }
        }
        updateStatus()
    }

    private fun stopReaders() {
        readers.values.forEach {
            it.sub?.close()
            it.sig.fill(0)
            it.inbox.destroy()
        }
        readers.clear()
        updateStatus()
    }

    /** The reader for `signerId` on `relayUrl`, started if needed. */
    private fun reader(relayUrl: String, signerId: String): Reader {
        readers[relayUrl to signerId]?.let { return it }
        val signer = requireNotNull(app.vault.get(signerId))
        val (sig, kem) = app.vault.transportSecrets(signerId)
        val records = app.connections.forSigner(signerId).filter { it.record.relay == relayUrl }.map { it.record }
        val inbox = try {
            Inbox(relayUrl, sig, kem, signer.address, records)
        } finally {
            kem.fill(0)
        }
        val r = Reader(relay(relayUrl), signerId, inbox, sig)
        readers[relayUrl to signerId] = r
        r.sub = r.relay.subscribe(
            inbox.inboxId(),
            sig,
            onMessage = { seq, body -> scope.launch { onDelivery(r, seq, body) } },
            onConnection = { up -> scope.launch { r.online = up; updateStatus() } },
        )
        return r
    }

    private fun updateStatus() {
        _status.value = when {
            readers.isEmpty() -> ""
            readers.values.all { it.online } -> "Up to date"
            else -> {
                val hosts = readers.values.map { it.relay.host }.distinct()
                "Checking ${hosts.size} relay${if (hosts.size == 1) "" else "s"}…"
            }
        }
    }

    // ---- deliveries -------------------------------------------------------------------

    private suspend fun onDelivery(r: Reader, seq: Long, body: ByteArray) {
        when (val incoming = r.inbox.onEnvelope(body, r.relay.now())) {
            is Incoming.Connected -> {
                app.connections.add(r.signerId, incoming.connection)
                ack(r, seq)
                waitingBound.remove(incoming.connection.requesterInbox)?.complete(incoming.connection)
                audit("connected", incoming.connection, r)
            }
            is Incoming.Request -> onRequest(r, seq, incoming.request)
            is Incoming.Redelivered -> {
                val stored = app.answers.get(incoming.requestId)
                if (stored != null) {
                    runCatching { r.relay.post(stored.inbox, stored.body, stored.token, r.sig) }
                        .onSuccess { ack(r, seq) }
                }
                // Still pending: leave it on the relay.
            }
            is Incoming.Cancelled -> {
                val p = _pending.value.firstOrNull { it.requestId == incoming.requestId }
                if (p != null && p.state !is ReviewState.Done) {
                    ack(r, p.seq)
                    setState(p.requestId, ReviewState.Withdrawn)
                    scope.launch {
                        delay(3_000)
                        remove(p.requestId)
                    }
                }
                ack(r, seq)
            }
            is Incoming.Unbound -> {
                val c = app.connections.get(incoming.connectionId)
                app.connections.remove(incoming.connectionId)
                ack(r, seq)
                _notice.value = "${c?.record?.label ?: "A site"} disconnected"
                c?.let { audit("disconnected by site", it.record, r) }
            }
            Incoming.Dropped -> ack(r, seq)
        }
    }

    private fun onRequest(r: Reader, seq: Long, request: IncomingRequest) {
        val stored = app.answers.get(request.id())
        if (stored != null) {
            // Answered before a restart: answer the same way, never sign twice (§10.6).
            scope.launch {
                runCatching { r.relay.post(stored.inbox, stored.body, stored.token, r.sig) }.onSuccess { ack(r, seq) }
            }
            return
        }
        if (_pending.value.any { it.requestId == request.id() }) return
        app.connections.touch(request.connectionId())
        val p = Pending(
            requestId = request.id(),
            connectionId = request.connectionId(),
            label = request.connectionLabel(),
            signerId = r.signerId,
            relay = r.relay.base,
            seq = seq,
            request = request,
            state = ReviewState.Loading,
        )
        _pending.value = _pending.value + p
        scope.launch { review(p) }
    }

    /** Reviews (fills) a request off the main thread (§10.4). Also "Retry". */
    fun review(p: Pending) {
        setState(p.requestId, ReviewState.Loading)
        scope.launch {
            val signer = app.vault.get(p.signerId) ?: return@launch
            val r = readers[p.relay to p.signerId] ?: return@launch
            val chain = p.request.chainId()?.toLong()
            val ep = chain?.let { app.settings.endpointFor(it) }
            val outcome = withContext(Dispatchers.IO) {
                p.request.review(
                    signer.label,
                    ep?.let { HttpEndpoint(it.url) },
                    ep?.let { relayHost(it.url) },
                    chain?.let { lastSent[it to signer.address] },
                    r.relay.now(),
                )
            }
            when (outcome) {
                is ReviewOutcome.Ready -> setState(p.requestId, ReviewState.Ready(outcome.review, outcome.review.display()))
                is ReviewOutcome.Reject -> answer(p, Response.Rejected(outcome.reason))
                is ReviewOutcome.WouldFail -> setState(p.requestId, ReviewState.WouldFail(outcome.message))
                is ReviewOutcome.Unreachable -> setState(p.requestId, ReviewState.Unreachable(outcome.message))
            }
        }
    }

    /**
     * Signs an approved request (§10.8). `phrase` is the biometric-unlocked recovery phrase;
     * it is wiped here.
     */
    suspend fun approve(p: Pending, phrase: ByteArray) {
        val ready = current(p.requestId) as? ReviewState.Ready ?: return phrase.fill(0)
        val outcome = try {
            ready.review.approve(phrase, 0u)
        } finally {
            phrase.fill(0)
        }
        when (outcome) {
            is ApproveOutcome.Answer -> answer(p, outcome.response)
            is ApproveOutcome.Broadcast -> {
                val signer = app.vault.get(p.signerId) ?: return
                val chain = ready.review.chainId()
                // Record before broadcasting: a redelivery after a crash gets this answer.
                store(p, outcome.ifInterrupted)
                val ep = app.settings.endpointFor(chain.toLong())
                val resp = if (ep == null) {
                    outcome.ifInterrupted
                } else {
                    withContext(Dispatchers.IO) {
                        broadcastTransaction(HttpEndpoint(ep.url), chain, signer.address, outcome.raw, outcome.txHash)
                    }
                }
                if (resp is Response.Sent) lastSent[chain.toLong() to signer.address] = outcome.nonce
                answer(p, resp)
            }
        }
    }

    fun reject(p: Pending) {
        val reason = if (current(p.requestId) is ReviewState.WouldFail) RejectReason.WOULD_FAIL else RejectReason.USER
        scope.launch { answer(p, Response.Rejected(reason)) }
    }

    /** Seals, stores, sends, acknowledges, logs. */
    private suspend fun answer(p: Pending, response: Response) {
        val r = readers[p.relay to p.signerId] ?: return
        try {
            val stored = store(p, response)
            r.relay.post(stored.inbox, stored.body, stored.token, r.sig)
            ack(r, p.seq)
        } catch (e: Exception) {
            _notice.value = "Could not send the answer: ${e.message}"
        }
        setState(p.requestId, ReviewState.Done(response))
        app.connections.get(p.connectionId)?.let { audit("request", it.record, r, p, response) }
        scope.launch {
            delay(4_000)
            remove(p.requestId)
        }
    }

    private fun store(p: Pending, response: Response): StoredAnswer {
        val r = requireNotNull(readers[p.relay to p.signerId])
        val out = r.inbox.answer(p.connectionId, p.requestId, response, r.relay.now())
        val a = StoredAnswer(p.connectionId, out.inbox, out.token, out.body)
        app.answers.put(p.requestId, a)
        return a
    }

    private fun expireOld() {
        _pending.value.forEach { p ->
            val r = readers[p.relay to p.signerId] ?: return@forEach
            val waiting = p.state !is ReviewState.Done && p.state !is ReviewState.Withdrawn
            if (waiting && p.request.expiresAt() < r.relay.now()) {
                scope.launch { answer(p, Response.Rejected(RejectReason.EXPIRED)) }
            }
        }
    }

    private suspend fun ack(r: Reader, seq: Long) {
        runCatching { r.relay.ack(r.inbox.inboxId(), seq, r.sig) }
    }

    private fun current(id: String) = _pending.value.firstOrNull { it.requestId == id }?.state

    private fun setState(id: String, state: ReviewState) {
        _pending.value = _pending.value.map { if (it.requestId == id) it.copy(state = state) else it }
    }

    private fun remove(id: String) {
        _pending.value = _pending.value.filter { it.requestId != id }
    }

    fun dismissNotice() {
        _notice.value = null
    }

    // ---- connecting -------------------------------------------------------------------

    /** A QR code was scanned (§5.2 steps 1–2). */
    fun scanned(uri: String) {
        val offer = try {
            parseOffer(uri)
        } catch (e: FfiException) {
            _connect.value = ConnectState.Failed("This isn't a Blox QR code")
            return
        }
        if (!BuildConfig.DEBUG && !offer.relay.startsWith("https://")) {
            _connect.value = ConnectState.Failed("This QR code's relay doesn't use HTTPS")
            return
        }
        _connect.value = if (app.settings.isKnownRelay(offer.relay)) {
            ConnectState.Choose(uri, offer)
        } else {
            ConnectState.RelayConsent(uri, offer)
        }
    }

    fun allowRelay(s: ConnectState.RelayConsent) {
        app.settings.addRelay(s.offer.relay)
        _connect.value = ConnectState.Choose(s.uri, s.offer)
    }

    fun cancelConnect() {
        _connect.value = ConnectState.Idle
    }

    /**
     * Approved on the connect screen (§5.2 steps 4–6). `phrase` is the signer's unlocked
     * recovery phrase; it is wiped here.
     */
    suspend fun connect(s: ConnectState.Choose, signerId: String, days: Int, phrase: ByteArray) {
        _connect.value = ConnectState.Working(s.offer.label)
        try {
            val relay = relay(s.offer.relay)
            relay.syncTime()
            val r = reader(s.offer.relay, signerId)
            val now = relay.now()
            val bind = try {
                r.inbox.acceptOffer(s.uri, phrase, 0u, now, now + (days * 86_400L).toULong())
            } finally {
                phrase.fill(0)
            }
            val bound = CompletableDeferred<ConnectionRecord>()
            waitingBound[bind.requesterInbox] = bound
            try {
                relay.postWithTicket(bind.requesterInbox, bind.ticket, bind.body)
            } catch (e: RelayException) {
                waitingBound.remove(bind.requesterInbox)
                r.inbox.abandonConnect(bind.requesterInbox)
                _connect.value = ConnectState.Failed(
                    when (e.status) {
                        409 -> "This QR code was already used. Someone may have seen it."
                        401 -> "This QR code has expired — start again on the site"
                        else -> "The relay refused the connection (${e.status})"
                    },
                )
                return
            }
            val record = withTimeoutOrNull(BOUND_TIMEOUT_MS) { bound.await() }
            if (record == null) {
                waitingBound.remove(bind.requesterInbox)
                r.inbox.abandonConnect(bind.requesterInbox)?.let { token ->
                    runCatching { relay.revoke(token, r.sig) }
                }
                _connect.value = ConnectState.Failed("The site didn't confirm the connection")
                return
            }
            _connect.value = ConnectState.Connected(record.label, record.account)
        } catch (e: Exception) {
            phrase.fill(0)
            _connect.value = ConnectState.Failed("Could not connect: ${e.message}")
        }
    }

    // ---- ending connections and signers -----------------------------------------------

    /** The user disconnects a site (§5.5): unbind, revoke, forget. */
    suspend fun disconnect(c: StoredConnection) {
        try {
            val r = reader(c.record.relay, c.signerId)
            val out = r.inbox.unbind(c.record.id, r.relay.now())
            runCatching { r.relay.post(out.inbox, out.body, out.token, r.sig) }
            runCatching { r.relay.revoke(c.record.token, r.sig) }
            audit("disconnected", c.record, r)
        } catch (_: Exception) {
            // Offline: forgetting it is what enforces the end (§5.5).
        }
        app.connections.remove(c.record.id)
    }

    /** Removing a signer ends its connections first (best effort), then deletes its keys (§10.2). */
    suspend fun removeSigner(signerId: String) {
        app.connections.forSigner(signerId).forEach { disconnect(it) }
        readers.keys.filter { it.second == signerId }.forEach { key ->
            readers.remove(key)?.let {
                it.sub?.close()
                it.sig.fill(0)
                it.inbox.destroy()
            }
        }
        _pending.value = _pending.value.filter { it.signerId != signerId }
        app.vault.remove(signerId)
        updateStatus()
    }

    /** Removing a relay ends the connections that use it (§10.3). */
    suspend fun removeRelay(url: String) {
        app.connections.all().filter { it.record.relay == url }.forEach { disconnect(it) }
        app.settings.removeRelay(url)
    }

    private fun audit(event: String, c: ConnectionRecord, r: Reader, p: Pending? = null, response: Response? = null) {
        val signer = app.vault.get(r.signerId)
        app.audit.add(
            mapOf(
                "event" to event,
                "connection" to c.label,
                "relay" to r.relay.host,
                "signer" to signer?.label,
                "account" to c.account,
                "origin" to p?.request?.originUrl(),
                "kind" to p?.request?.kind(),
                "chain" to p?.request?.chainId()?.toLong(),
                "outcome" to response?.let { describe(it) },
                "tx_hash" to when (response) {
                    is Response.Sent -> response.txHash
                    is Response.SignedTx -> response.txHash
                    is Response.Failed -> response.txHash
                    else -> null
                },
            ),
        )
    }

    private companion object {
        const val BACKGROUND_MS = 30_000L
        const val BOUND_TIMEOUT_MS = 120_000L
    }
}

/** A short description of an answer, for the screen and the audit log. */
fun describe(r: Response): String = when (r) {
    is Response.Sent -> "Sent · ${r.txHash}"
    is Response.SignedTx -> "Signed, returned to the site · ${r.txHash}"
    is Response.Signed -> "Signed"
    is Response.Failed -> "Failed: ${r.error}"
    is Response.Rejected -> when (r.reason) {
        RejectReason.USER -> "Rejected"
        RejectReason.EXPIRED -> "Expired"
        RejectReason.UNSUPPORTED -> "Refused: unsupported request"
        RejectReason.DECODE_FAILED -> "Refused: cannot decode"
        RejectReason.NO_ENDPOINT -> "Refused: no endpoint for this network (add one in Settings)"
        RejectReason.WOULD_FAIL -> "Rejected: it would fail"
    }
}
