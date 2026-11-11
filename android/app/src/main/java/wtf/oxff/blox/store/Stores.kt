package wtf.oxff.blox.store

import android.content.Context
import java.io.File
import java.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import uniffi.blox_ffi.ConnectionRecord
import uniffi.blox_ffi.normalizeRelayUrl

const val DEFAULT_RELAY = "https://relay.example.com"

data class EndpointConfig(val chainId: Long, val name: String, val url: String)

/**
 * Chain endpoints and relays (BLOX.md §10.3). Never taken from a request; not secret, so
 * stored unencrypted in app-private storage.
 */
class Settings(context: Context) {
    private val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)

    fun endpoints(): List<EndpointConfig> {
        val arr = JSONArray(prefs.getString("endpoints", "[]"))
        return List(arr.length()) { i ->
            val o = arr.getJSONObject(i)
            EndpointConfig(o.getLong("chain"), o.getString("name"), o.getString("url"))
        }
    }

    fun endpointFor(chainId: Long): EndpointConfig? = endpoints().firstOrNull { it.chainId == chainId }

    /** One endpoint per chain; replaces an existing one. Check it with eth_chainId first. */
    fun putEndpoint(e: EndpointConfig) {
        val list = endpoints().filter { it.chainId != e.chainId } + e
        val arr = JSONArray()
        list.sortedBy { it.chainId }.forEach { arr.put(JSONObject().put("chain", it.chainId).put("name", it.name).put("url", it.url)) }
        prefs.edit().putString("endpoints", arr.toString()).apply()
    }

    fun removeEndpoint(chainId: Long) {
        val arr = JSONArray()
        endpoints().filter { it.chainId != chainId }.forEach { arr.put(JSONObject().put("chain", it.chainId).put("name", it.name).put("url", it.url)) }
        prefs.edit().putString("endpoints", arr.toString()).apply()
    }

    /** Normalized relay URLs the user allowed. The default relay is always listed. */
    fun relays(): List<String> {
        val arr = JSONArray(prefs.getString("relays", "[]"))
        return listOf(DEFAULT_RELAY) + List(arr.length()) { arr.getString(it) }.filter { it != DEFAULT_RELAY }
    }

    fun isKnownRelay(url: String): Boolean = relays().contains(url)

    fun addRelay(url: String) {
        val n = normalizeRelayUrl(url)
        if (isKnownRelay(n)) return
        val arr = JSONArray()
        (relays().drop(1) + n).forEach { arr.put(it) }
        prefs.edit().putString("relays", arr.toString()).apply()
    }

    fun removeRelay(url: String) {
        val arr = JSONArray()
        relays().drop(1).filter { it != url }.forEach { arr.put(it) }
        prefs.edit().putString("relays", arr.toString()).apply()
    }
}

/** A connection and what the app knows about it locally. */
data class StoredConnection(
    val signerId: String,
    val record: ConnectionRecord,
    val connectedAt: Long,
    val lastRequestAt: Long?,
)

/** Connections (§10.2: stored unencrypted, so messages can be checked without unlocking). */
class Connections(context: Context) {
    private val prefs = context.getSharedPreferences("connections", Context.MODE_PRIVATE)

    fun all(): List<StoredConnection> {
        val arr = JSONArray(prefs.getString("list", "[]"))
        return List(arr.length()) { i -> fromJson(arr.getJSONObject(i)) }
    }

    fun forSigner(signerId: String) = all().filter { it.signerId == signerId }

    fun get(id: String) = all().firstOrNull { it.record.id == id }

    fun add(signerId: String, record: ConnectionRecord) =
        save(all().filter { it.record.id != record.id } + StoredConnection(signerId, record, System.currentTimeMillis(), null))

    fun remove(id: String) = save(all().filter { it.record.id != id })

    fun touch(id: String) = save(all().map { if (it.record.id == id) it.copy(lastRequestAt = System.currentTimeMillis()) else it })

    /** Drops expired connections (§5.5); returns what remains. */
    fun prune(nowSecs: Long): List<StoredConnection> {
        val live = all().filter { it.record.expiresAt.toLong() > nowSecs }
        save(live)
        return live
    }

    private fun save(list: List<StoredConnection>) {
        val arr = JSONArray()
        list.forEach { arr.put(toJson(it)) }
        prefs.edit().putString("list", arr.toString()).apply()
    }

    private fun toJson(c: StoredConnection) = JSONObject()
        .put("signer", c.signerId)
        .put("connectedAt", c.connectedAt)
        .put("lastRequestAt", c.lastRequestAt ?: JSONObject.NULL)
        .put("id", c.record.id)
        .put("token", c.record.token)
        .put("label", c.record.label)
        .put("account", c.record.account)
        .put("relay", c.record.relay)
        .put("requesterInbox", c.record.requesterInbox)
        .put("issuedAt", c.record.issuedAt.toLong())
        .put("expiresAt", c.record.expiresAt.toLong())

    private fun fromJson(o: JSONObject) = StoredConnection(
        signerId = o.getString("signer"),
        record = ConnectionRecord(
            id = o.getString("id"),
            token = o.getString("token"),
            label = o.getString("label"),
            account = o.getString("account"),
            relay = o.getString("relay"),
            requesterInbox = o.getString("requesterInbox"),
            issuedAt = o.getLong("issuedAt").toULong(),
            expiresAt = o.getLong("expiresAt").toULong(),
        ),
        connectedAt = o.getLong("connectedAt"),
        lastRequestAt = if (o.isNull("lastRequestAt")) null else o.getLong("lastRequestAt"),
    )
}

/** A sealed answer, to post again if its request is delivered again. */
data class StoredAnswer(val connectionId: String, val inbox: String, val token: String, val body: ByteArray)

/**
 * Answers by request id, kept 10 minutes (§10.6): stored before they are sent, so a request
 * delivered again after a crash or a lost acknowledgement is answered the same way and never
 * signed twice.
 */
class Answers(context: Context) {
    private val prefs = context.getSharedPreferences("answers", Context.MODE_PRIVATE)

    fun get(requestId: String): StoredAnswer? {
        val o = prefs.getString(requestId, null)?.let(::JSONObject) ?: return null
        return StoredAnswer(o.getString("conn"), o.getString("inbox"), o.getString("token"), Base64.getDecoder().decode(o.getString("body")))
    }

    fun put(requestId: String, a: StoredAnswer) {
        val now = System.currentTimeMillis()
        val edit = prefs.edit()
        prefs.all.forEach { (k, v) ->
            val at = runCatching { JSONObject(v as String).getLong("at") }.getOrDefault(0L)
            if (now - at > RETENTION_MS) edit.remove(k)
        }
        val o = JSONObject()
            .put("conn", a.connectionId)
            .put("inbox", a.inbox)
            .put("token", a.token)
            .put("body", Base64.getEncoder().encodeToString(a.body))
            .put("at", now)
        // commit(): the answer must be on disk before it is sent or a transaction broadcast.
        edit.putString(requestId, o.toString()).commit()
    }

    private companion object {
        const val RETENTION_MS = 10 * 60_000L
    }
}

/**
 * The local audit log (§10.9), as JSON lines. Never uploaded; exported through the share
 * sheet. Removing a signer keeps its entries.
 */
class AuditLog(context: Context) {
    private val file = File(context.filesDir, "audit.jsonl")

    @Synchronized
    fun add(entry: Map<String, Any?>) {
        val o = JSONObject().put("time", System.currentTimeMillis())
        entry.forEach { (k, v) -> o.put(k, v ?: JSONObject.NULL) }
        file.appendText(o.toString() + "\n")
    }

    fun entries(limit: Int = 200): List<JSONObject> =
        if (!file.exists()) emptyList() else file.readLines().takeLast(limit).reversed().map(::JSONObject)

    fun file(): File = file
}
