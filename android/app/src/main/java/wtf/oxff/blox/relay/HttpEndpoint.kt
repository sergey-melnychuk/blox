package wtf.oxff.blox.relay

import java.io.IOException
import java.util.concurrent.TimeUnit
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import uniffi.blox_ffi.EndpointRpc
import uniffi.blox_ffi.RpcFailure

/**
 * A chain endpoint the user configured (BLOX.md §10.3), for Rust's filler (§10.4). Rust calls
 * this from background threads; the calls block.
 */
class HttpEndpoint(private val url: String) : EndpointRpc {
    override fun call(method: String, paramsJson: String): String {
        val body = """{"jsonrpc":"2.0","id":1,"method":${JSONObject.quote(method)},"params":$paramsJson}"""
        val req = Request.Builder().url(url).post(body.toRequestBody(JSON)).build()
        val text = try {
            http.newCall(req).execute().use { res ->
                if (!res.isSuccessful && res.code != 400 && res.code != 500) {
                    throw RpcFailure.Unreachable("HTTP ${res.code}")
                }
                res.body.string()
            }
        } catch (e: IOException) {
            throw RpcFailure.Unreachable(e.message ?: "unreachable")
        }
        val json = try {
            JSONObject(text)
        } catch (e: Exception) {
            throw RpcFailure.Unreachable("not a JSON-RPC answer")
        }
        json.optJSONObject("error")?.let { err ->
            throw RpcFailure.Rpc(err.optLong("code"), err.optString("message", "error"))
        }
        // The `result` as JSON text: wrap it in an array to serialize any JSON value, then unwrap.
        val wrapped = JSONArray().put(json.opt("result") ?: JSONObject.NULL).toString()
        return wrapped.substring(1, wrapped.length - 1)
    }

    private companion object {
        val JSON = "application/json".toMediaType()
        val http: OkHttpClient = OkHttpClient.Builder()
            .callTimeout(20, TimeUnit.SECONDS)
            .build()
    }
}
