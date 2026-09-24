package wtf.oxff.blox.vault

import android.content.Context
import org.json.JSONArray

/**
 * Derived EVM addresses, in derivation order (index = position). Not secret: stored
 * in plain preferences so accounts can be listed and requests checked without unlocking.
 */
class AccountStore(context: Context) {
    private val prefs = context.getSharedPreferences("accounts", Context.MODE_PRIVATE)

    fun addresses(): List<String> {
        val json = prefs.getString(KEY, null) ?: return emptyList()
        val arr = JSONArray(json)
        return List(arr.length()) { arr.getString(it) }
    }

    fun save(addresses: List<String>) {
        prefs.edit().putString(KEY, JSONArray(addresses).toString()).apply()
    }

    /** Derivation index of `address`, or null if it isn't ours. */
    fun indexOf(address: String): Int? =
        addresses().indexOfFirst { it.equals(address, ignoreCase = true) }.takeIf { it >= 0 }

    fun clear() {
        prefs.edit().clear().apply()
    }

    private companion object {
        const val KEY = "evm"
    }
}
