package wtf.oxff.blox.ui

import android.content.Intent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.blox_ffi.chainName
import uniffi.blox_ffi.endpointChainId
import uniffi.blox_ffi.relayHost
import wtf.oxff.blox.BloxApp
import wtf.oxff.blox.BuildConfig
import wtf.oxff.blox.relay.HttpEndpoint
import wtf.oxff.blox.store.DEFAULT_RELAY
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
    var message by remember { mutableStateOf<String?>(null) }

    fun allowed(u: String) = u.startsWith("https://") || (BuildConfig.DEBUG && u.startsWith("http://"))

    Column(Modifier.padding(24.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        TextButton(onClick = onBack) { Text("‹ Back") }
        Text("Settings", style = MaterialTheme.typography.headlineMedium)
        message?.let { Text(it, color = MaterialTheme.colorScheme.tertiary) }

        Text("Network endpoints", style = MaterialTheme.typography.titleMedium)
        Text("Transactions are filled and sent through these. Requests never choose them.", style = MaterialTheme.typography.bodySmall)
        endpoints.forEach { e ->
            Card(Modifier.fillMaxWidth()) {
                Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("${e.name} (eip155:${e.chainId})")
                        Text(relayHost(e.url), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                    }
                    TextButton(onClick = {
                        app.settings.removeEndpoint(e.chainId)
                        refresh++
                    }) { Text("Remove") }
                }
            }
        }
        OutlinedTextField(chain, { chain = it.filter(Char::isDigit) }, label = { Text("Chain id (e.g. 8453)") }, singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number))
        OutlinedTextField(url, { url = it.trim() }, label = { Text("Endpoint URL") }, singleLine = true, modifier = Modifier.fillMaxWidth())
        Button(
            enabled = chain.isNotEmpty() && allowed(url),
            onClick = {
                val id = chain.toLongOrNull() ?: return@Button
                scope.launch {
                    val actual = runCatching { withContext(Dispatchers.IO) { endpointChainId(HttpEndpoint(url)) } }
                    message = actual.fold(
                        onSuccess = {
                            if (it.toLong() == id) {
                                app.settings.putEndpoint(EndpointConfig(id, chainName(id.toULong()) ?: "Chain $id", url))
                                chain = ""
                                url = ""
                                refresh++
                                "Endpoint added"
                            } else {
                                "That endpoint is on chain $it, not $id"
                            }
                        },
                        onFailure = { "Could not reach the endpoint: ${it.message}" },
                    )
                }
            },
        ) { Text("Check and add") }
        if (!BuildConfig.DEBUG) Text("Endpoints must use HTTPS.", style = MaterialTheme.typography.bodySmall)

        Text("Relays", style = MaterialTheme.typography.titleMedium)
        relays.forEach { r ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(relayHost(r), Modifier.weight(1f), fontFamily = FontFamily.Monospace)
                if (r != DEFAULT_RELAY) {
                    TextButton(onClick = {
                        scope.launch {
                            app.keystore.removeRelay(r)
                            refresh++
                        }
                    }) { Text("Remove") }
                }
            }
        }
        Text("Removing a relay ends the connections that use it.", style = MaterialTheme.typography.bodySmall)
        OutlinedTextField(relayUrl, { relayUrl = it.trim() }, label = { Text("Relay URL") }, singleLine = true, modifier = Modifier.fillMaxWidth())
        OutlinedButton(enabled = allowed(relayUrl), onClick = {
            message = runCatching {
                app.settings.addRelay(relayUrl)
                relayUrl = ""
                refresh++
                "Relay added"
            }.getOrElse { "Not a valid relay URL" }
        }) { Text("Add relay") }

        Text("Activity", style = MaterialTheme.typography.titleMedium)
        OutlinedButton(onClick = {
            val text = runCatching { app.audit.file().readText() }.getOrDefault("")
            val send = Intent(Intent.ACTION_SEND).setType("application/json").putExtra(Intent.EXTRA_TEXT, text)
            context.startActivity(Intent.createChooser(send, "Export audit log"))
        }) { Text("Export audit log") }
    }
}
