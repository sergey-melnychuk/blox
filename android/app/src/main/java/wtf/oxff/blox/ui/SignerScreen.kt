package wtf.oxff.blox.ui

import android.security.keystore.KeyPermanentlyInvalidatedException
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
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
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import java.text.DateFormat
import java.util.Date
import kotlinx.coroutines.launch
import uniffi.blox_ffi.relayHost
import wtf.oxff.blox.BloxApp
import wtf.oxff.blox.MainActivity
import wtf.oxff.blox.vault.unlock

/** A signer (§10.6): its connections, its phrase, and removing it (§10.2). */
@Composable
fun SignerScreen(activity: MainActivity, app: BloxApp, signerId: String, onBack: () -> Unit) {
    val signer = app.vault.get(signerId) ?: return onBack()
    val scope = rememberCoroutineScope()
    var refresh by remember { mutableIntStateOf(0) }
    val connections = remember(refresh) { app.connections.forSigner(signerId) }
    var phrase by remember { mutableStateOf<String?>(null) }
    var removing by remember { mutableStateOf(false) }
    var restoring by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val fmt = remember { DateFormat.getDateInstance(DateFormat.MEDIUM) }

    Column(Modifier.padding(24.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        TextButton(onClick = onBack) { Text("‹ Back") }
        Text(signer.label, style = MaterialTheme.typography.headlineMedium)
        Text(signer.address, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
        securityText(app.vault.securityLevel(signerId))?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }

        Text("Connections", style = MaterialTheme.typography.titleMedium)
        if (connections.isEmpty()) Text("No sites are connected to this signer.", style = MaterialTheme.typography.bodySmall)
        connections.forEach { c ->
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("${c.record.label} (claimed)", style = MaterialTheme.typography.titleSmall)
                    Text("via ${relayHost(c.record.relay)}", style = MaterialTheme.typography.bodySmall)
                    Text(
                        "Connected ${fmt.format(Date(c.connectedAt))} · expires ${fmt.format(Date(c.record.expiresAt.toLong() * 1000))}",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    c.lastRequestAt?.let { Text("Last request ${fmt.format(Date(it))}", style = MaterialTheme.typography.bodySmall) }
                    TextButton(onClick = {
                        scope.launch {
                            app.keystore.disconnect(c)
                            refresh++
                        }
                    }) { Text("Disconnect") }
                }
            }
        }

        Text("Recovery phrase", style = MaterialTheme.typography.titleMedium)
        phrase?.let { p ->
            p.split(" ").forEachIndexed { i, w -> Text("${i + 1}. $w", fontFamily = FontFamily.Monospace) }
            OutlinedButton(onClick = { phrase = null }, Modifier.fillMaxWidth()) { Text("Hide") }
        } ?: OutlinedButton(onClick = {
            scope.launch {
                try {
                    val cipher = activity.unlock(app.vault.decryptCipher(signerId), "Show the recovery phrase") ?: return@launch
                    val bytes = app.vault.open(signerId, cipher)
                    phrase = String(bytes)
                    bytes.fill(0)
                } catch (e: KeyPermanentlyInvalidatedException) {
                    error = "Your phone's security settings changed. Restore this signer from its recovery phrase."
                    restoring = true
                } catch (e: Exception) {
                    error = "Could not unlock: ${e.message}"
                }
            }
        }, Modifier.fillMaxWidth()) { Text("Show recovery phrase") }

        if (restoring) {
            Text("Restore “${signer.label}”: enter its recovery phrase. It must give ${signer.address}.")
            PhraseInput(
                action = "Restore",
                onPhrase = { bytes ->
                    scope.launch {
                        try {
                            val cipher = activity.unlock(app.vault.beginRestore(signerId), "Protect “${signer.label}”") ?: return@launch
                            app.vault.completeRestore(signerId, cipher, bytes)
                            restoring = false
                            error = null
                        } catch (e: Exception) {
                            error = e.message
                        } finally {
                            bytes.fill(0)
                        }
                    }
                },
                onBack = { restoring = false },
                onError = { error = it },
            )
        } else {
            TextButton(onClick = { restoring = true }) { Text("Restore from recovery phrase…") }
        }

        if (!removing) {
            TextButton(onClick = { removing = true }) { Text("Remove this signer…") }
        } else {
            val code = signer.address.takeLast(4)
            var typed by remember { mutableStateOf("") }
            Text(
                "Removing “${signer.label}” deletes its key from this phone and ends its connections. " +
                    "Its funds are lost unless you have the recovery phrase.",
                color = MaterialTheme.colorScheme.error,
            )
            OutlinedTextField(
                value = typed,
                onValueChange = { typed = it.trim() },
                label = { Text("Type $code to confirm") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Characters, autoCorrectEnabled = false),
            )
            Button(
                enabled = typed.equals(code, ignoreCase = true),
                colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error),
                modifier = Modifier.fillMaxWidth(),
                onClick = {
                    scope.launch {
                        val authed = try {
                            activity.unlock(app.vault.decryptCipher(signerId), "Remove ${signer.label}") != null
                        } catch (e: KeyPermanentlyInvalidatedException) {
                            true // the seed is unreadable already; removing loses nothing more
                        }
                        if (!authed) return@launch
                        app.keystore.removeSigner(signerId)
                        onBack()
                    }
                },
            ) { Text("Remove signer") }
            OutlinedButton(onClick = { removing = false }, Modifier.fillMaxWidth()) { Text("Cancel") }
        }
    }
}
