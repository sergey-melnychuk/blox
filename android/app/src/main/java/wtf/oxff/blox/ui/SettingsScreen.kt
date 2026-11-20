package wtf.oxff.blox.ui

import android.content.Intent
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.blox_ffi.chainName
import uniffi.blox_ffi.endpointChainId
import uniffi.blox_ffi.relayHost
import wtf.oxff.blox.BloxApp
import wtf.oxff.blox.BuildConfig
import wtf.oxff.blox.relay.HttpEndpoint
import wtf.oxff.blox.store.EndpointConfig

/** Chain endpoints and relays (§10.3), and the audit log export (§10.9). */
@Composable
fun SettingsScreen(app: BloxApp, onBack: () -> Unit) {
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    var refresh by remember { mutableIntStateOf(0) }
    val endpoints = remember(refresh) { app.settings.endpoints() }
    val relays = remember(refresh) { app.settings.relays() }
    var chain by remember { mutableStateOf("") }
    var url by remember { mutableStateOf("") }
    var relayUrl by remember { mutableStateOf("") }
    var message by remember { mutableStateOf<Pair<String, Tone>?>(null) }
    var checking by remember { mutableStateOf(false) }

    fun allowed(u: String) = u.startsWith("https://") || (BuildConfig.DEBUG && u.startsWith("http://"))
    val scheme = if (BuildConfig.DEBUG) "Must start with https:// or http://" else "Must start with https://"

    BloxScreen("Settings", onBack = onBack) {
        message?.let { (text, tone) -> Notice(text, tone, onClick = { message = null }) }

        Section("Endpoints") {
            if (endpoints.isEmpty()) Item("None")
            Rows(endpoints) { e ->
                Item(
                    e.name,
                    overline = "eip155:${e.chainId}",
                    supporting = relayHost(e.url),
                    monoSupporting = true,
                    trailing = {
                        IconButton(onClick = {
                            app.settings.removeEndpoint(e.chainId)
                            refresh++
                        }) { Icon(Icons.Filled.Close, contentDescription = "Remove ${e.name}") }
                    },
                )
            }
            RowDivider()
            SectionBody {
                Field(
                    chain,
                    { chain = it.filter(Char::isDigit) },
                    "Chain id",
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                )
                Field(
                    url,
                    { url = it.trim() },
                    "URL",
                    mono = true,
                    isError = url.isNotEmpty() && !allowed(url),
                    supporting = if (url.isNotEmpty() && !allowed(url)) scheme else null,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, autoCorrectEnabled = false),
                )
                SecondaryButton("Add", enabled = chain.isNotEmpty() && allowed(url) && !checking, onClick = {
                    val id = chain.toLongOrNull() ?: return@SecondaryButton
                    checking = true
                    scope.launch {
                        val actual = runCatching { withContext(Dispatchers.IO) { endpointChainId(HttpEndpoint(url)) } }
                        checking = false
                        message = actual.fold(
                            onSuccess = {
                                if (it.toLong() == id) {
                                    app.settings.putEndpoint(EndpointConfig(id, chainName(id.toULong()) ?: "Chain $id", url))
                                    chain = ""
                                    url = ""
                                    refresh++
                                    "Endpoint added" to Tone.Info
                                } else {
                                    "That endpoint is on chain $it, not $id" to Tone.Danger
                                }
                            },
                            onFailure = { "Could not reach the endpoint: ${it.message}" to Tone.Danger },
                        )
                    }
                })
            }
        }

        Section("Relays", footer = "Removing a relay ends the connections that use it.") {
            Rows(relays) { r ->
                Item(
                    relayHost(r),
                    supporting = null,
                    trailing = {
                        IconButton(onClick = {
                            scope.launch {
                                app.keystore.removeRelay(r)
                                refresh++
                            }
                        }) { Icon(Icons.Filled.Close, contentDescription = "Remove ${relayHost(r)}") }
                    },
                )
            }
            RowDivider()
            SectionBody {
                Field(
                    relayUrl,
                    { relayUrl = it.trim() },
                    "URL",
                    mono = true,
                    isError = relayUrl.isNotEmpty() && !allowed(relayUrl),
                    supporting = if (relayUrl.isNotEmpty() && !allowed(relayUrl)) scheme else null,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, autoCorrectEnabled = false),
                )
                SecondaryButton("Add", enabled = allowed(relayUrl), onClick = {
                    message = runCatching {
                        app.settings.addRelay(relayUrl)
                        relayUrl = ""
                        refresh++
                        "Relay added" to Tone.Info
                    }.getOrElse { "Not a valid relay URL" to Tone.Danger }
                })
            }
        }

        Section {
            Item(
                "Export audit log",
                trailing = { Icon(Icons.Filled.Share, contentDescription = null) },
                onClick = {
                    val text = runCatching { app.audit.file().readText() }.getOrDefault("")
                    val send = Intent(Intent.ACTION_SEND).setType("application/json").putExtra(Intent.EXTRA_TEXT, text)
                    context.startActivity(Intent.createChooser(send, "Export audit log"))
                },
            )
        }
    }
}
