package wtf.oxff.blox

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.blox_ffi.ApproveOutcome
import uniffi.blox_ffi.ConnectionRecord
import uniffi.blox_ffi.EndpointRpc
import uniffi.blox_ffi.Inbox
import uniffi.blox_ffi.Incoming
import uniffi.blox_ffi.IncomingRequest
import uniffi.blox_ffi.Response
import uniffi.blox_ffi.ReviewOutcome
import uniffi.blox_ffi.RpcFailure
import uniffi.blox_ffi.broadcastTransaction
import uniffi.blox_ffi.deriveEvmAddresses
import uniffi.blox_ffi.normalizeRelayUrl
import uniffi.blox_ffi.parseOffer
import uniffi.blox_ffi.relayHost
import uniffi.blox_ffi.signRelayRequest

/**
 * The Rust core through the generated Kotlin bindings, on a device, against the wire-format
 * vectors (`test-vectors/proto-v1.json`): JNA loading, byte arrays, records, sealed classes,
 * objects and the `EndpointRpc` foreign trait. The protocol itself is tested in Rust.
 */
@RunWith(AndroidJUnit4::class)
class BindingsVectorsTest {
    private val v: JSONObject = InstrumentationRegistry.getInstrumentation().context.assets
        .open("proto-v1.json").use { JSONObject(it.readBytes().decodeToString()) }
    private val keys = v.getJSONObject("keys")
    private val token = v.getJSONObject("token")
    private val account = v.getJSONObject("statement").getString("account")

    @Test
    fun relayUrls() {
        val urls = v.getJSONArray("relay_urls")
        for (i in 0 until urls.length()) {
            val u = urls.getJSONArray(i)
            assertEquals(u.getString(1), normalizeRelayUrl(u.getString(0)))
        }
        assertEquals("relay.example.com", relayHost("https://relay.example.com"))
    }

    @Test
    fun requestSignature() {
        val s = v.getJSONObject("request_signature")
        assertEquals("requester", s.getString("signer"))
        val auth = signRelayRequest(
            b64(keys.getString("requester_sig_secret")),
            s.getString("method"),
            s.getString("path"),
            s.getLong("ts").toULong(),
            hex(s.getString("body_hex")),
        )
        assertEquals(s.getString("authorization"), auth)
    }

    @Test
    fun offer() {
        val o = parseOffer(v.getJSONObject("offer").getString("uri"))
        assertEquals(v.getJSONObject("offer").getString("label"), o.label)
        assertEquals(token.getString("relay"), o.relay)
        assertEquals("relay.example.com", o.relayHost)
    }

    @Test
    fun mnemonicGivesTheStatementAccount() {
        assertEquals(account, deriveEvmAddresses(MNEMONIC.toByteArray(), 0u, 1u).single())
    }

    @Test
    fun acceptOfferBindsToTheOffersRequester() {
        val inbox = inbox(emptyList())
        val bind = inbox.acceptOffer(v.getJSONObject("offer").getString("uri"), MNEMONIC.toByteArray(), 0u, NOW, NOW + 86_400u)
        assertEquals(keys.getString("requester_sig"), bind.requesterInbox)
        assertEquals(keys.getString("ticket"), bind.ticket)
        assertEquals(account, bind.account)
        // Giving up returns the half-signed token to revoke.
        assertTrue(inbox.abandonConnect(bind.requesterInbox)!!.isNotEmpty())
        inbox.destroy()
    }

    /** Opens the vectors' `sign_request`, reviews it with a Kotlin endpoint, signs, broadcasts, answers. */
    @Test
    fun requestRoundTrip() {
        val record = ConnectionRecord(
            id = token.getString("token_id"),
            token = token.getString("countersigned"),
            label = "Example",
            account = account,
            relay = token.getString("relay"),
            requesterInbox = keys.getString("requester_sig"),
            issuedAt = token.getLong("issued_at").toULong(),
            expiresAt = token.getLong("expires_at").toULong(),
        )
        val inbox = inbox(listOf(record))
        assertEquals(keys.getString("keystore_sig"), inbox.inboxId())

        val env = (0 until v.getJSONArray("envelopes").length())
            .map { v.getJSONArray("envelopes").getJSONObject(it) }
            .single { it.getString("recipient") == "keystore" }
        val plain = JSONObject(env.getString("plaintext_utf8"))
        val body = b64(env.getString("envelope"))

        val req: IncomingRequest = when (val got = inbox.onEnvelope(body, NOW)) {
            is Incoming.Request -> got.request
            else -> throw AssertionError("expected a request, got $got")
        }
        assertEquals(plain.getString("id"), req.id())
        assertEquals(record.id, req.connectionId())
        assertEquals("Example", req.connectionLabel())
        assertEquals("evm.send", req.kind())
        assertEquals(8453uL, req.chainId())
        assertEquals(plain.getJSONObject("body").getLong("expires_at").toULong(), req.expiresAt())

        // The same envelope again is a redelivery, not a second request.
        val again = inbox.onEnvelope(body, NOW)
        assertTrue("expected a redelivery, got $again", again is Incoming.Redelivered && again.requestId == req.id())

        val endpoint = FakeEndpoint()
        val review = when (val r = req.review("Main", endpoint, "rpc.example", null, NOW)) {
            is ReviewOutcome.Ready -> r.review
            else -> throw AssertionError("expected ready, got $r")
        }
        assertEquals(8453uL, review.chainId())
        assertTrue(review.display().title.isNotEmpty())
        assertTrue("eth_estimateGas" in endpoint.calls)

        val signed = when (val a = review.approve(MNEMONIC.toByteArray(), 0u)) {
            is ApproveOutcome.Broadcast -> a
            else -> throw AssertionError("expected a broadcast, got $a")
        }
        assertEquals(0uL, signed.nonce)
        assertTrue(signed.ifInterrupted is Response.Failed)

        val sent = broadcastTransaction(endpoint, 8453u, account, signed.raw, signed.txHash)
        assertEquals(Response.Sent("eip155:8453:$account", signed.txHash), sent)

        // A JSON-RPC error thrown in Kotlin reaches Rust as `failed` with the endpoint's message.
        endpoint.refuseBroadcast = true
        val failed = broadcastTransaction(endpoint, 8453u, account, signed.raw, signed.txHash)
        assertTrue("expected failed, got $failed", failed is Response.Failed && failed.error.contains("nonce too low"))

        val out = inbox.answer(req.connectionId(), req.id(), sent, NOW)
        assertEquals(keys.getString("requester_sig"), out.inbox)
        assertEquals(record.token, out.token)
        assertTrue(out.body.isNotEmpty())

        review.destroy()
        req.destroy()
        inbox.destroy()
    }

    private fun inbox(records: List<ConnectionRecord>) = Inbox(
        token.getString("relay"),
        b64(keys.getString("keystore_sig_secret")),
        deriveX25519(keys.getString("keystore_kem_ikm_utf8").toByteArray()),
        account,
        records,
    )

    /** Base mainnet, as an endpoint would answer; records the methods called. */
    private class FakeEndpoint : EndpointRpc {
        val calls = mutableListOf<String>()
        var refuseBroadcast = false

        override fun call(method: String, paramsJson: String): String {
            calls += method
            return when (method) {
                "eth_chainId" -> "\"0x2105\""
                "eth_getTransactionCount" -> "\"0x0\""
                "eth_estimateGas" -> "\"0x5208\""
                "eth_getBlockByNumber" -> """{"baseFeePerGas":"0x3b9aca00"}"""
                "eth_maxPriorityFeePerGas" -> "\"0x1\""
                "eth_getBalance" -> "\"0xde0b6b3a7640000\""
                "eth_sendRawTransaction" ->
                    if (refuseBroadcast) throw RpcFailure.Rpc(-32000, "nonce too low") else "\"0x${"0".repeat(63)}1\""
                else -> throw RpcFailure.Rpc(-32601, "method not found")
            }
        }
    }

    private companion object {
        const val MNEMONIC = "test test test test test test test test test test test junk"
        /** One second after the vectors' request was sent. */
        const val NOW: ULong = 1_762_776_002uL

        fun b64(s: String): ByteArray = Base64.getUrlDecoder().decode(s)

        fun hex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

        fun hmac(key: ByteArray, data: ByteArray): ByteArray =
            Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key, "HmacSHA256")) }.doFinal(data)

        /**
         * RFC 9180 DeriveKeyPair for DHKEM(X25519, HKDF-SHA256), as the vectors' keys were
         * made: sk = LabeledExpand(LabeledExtract("", "dkp_prk", ikm), "sk", "", 32).
         */
        fun deriveX25519(ikm: ByteArray): ByteArray {
            val suite = "KEM".toByteArray() + byteArrayOf(0x00, 0x20)
            val label = "HPKE-v1".toByteArray() + suite
            val prk = hmac(ByteArray(32), label + "dkp_prk".toByteArray() + ikm)
            val info = byteArrayOf(0x00, 0x20) + label + "sk".toByteArray()
            return hmac(prk, info + byteArrayOf(0x01))
        }
    }
}
