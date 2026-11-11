package wtf.oxff.blox.ui

import android.security.keystore.KeyPermanentlyInvalidatedException
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import wtf.oxff.blox.BloxApp
import wtf.oxff.blox.MainActivity
import wtf.oxff.blox.keystore.Keystore.ConnectState
import wtf.oxff.blox.vault.unlock

private val REMEMBER_FOR = listOf(1 to "1 day", 30 to "30 days", 90 to "90 days")

/** The connect flow (§5.2): relay consent, signer and duration, biometric, then waiting for `bound`. */
@Composable
fun ConnectScreen(activity: MainActivity, app: BloxApp, state: ConnectState, onDone: () -> Unit) {
    val scope = rememberCoroutineScope()
    Column(Modifier.padding(24.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        when (state) {
            ConnectState.Idle -> {}
            is ConnectState.RelayConsent -> {
                Text("Use this relay?", style = MaterialTheme.typography.headlineSmall)
                Text(state.offer.relayHost, fontFamily = FontFamily.Monospace)
                Text(
                    "“${state.offer.label}” (claimed) wants to connect through a relay that isn't on your list. " +
                        "The relay can see when you use Blox, but can't read or change anything.",
                )
                Button(onClick = { app.keystore.allowRelay(state) }, Modifier.fillMaxWidth()) { Text("Use this relay") }
                OutlinedButton(onClick = onDone, Modifier.fillMaxWidth()) { Text("Cancel") }
            }
            is ConnectState.Choose -> {
                val signers = app.vault.list()
                var signerId by remember { mutableStateOf(signers.firstOrNull()?.id) }
                var days by remember { mutableIntStateOf(30) }
                var error by remember { mutableStateOf<String?>(null) }
                Text("${state.offer.label} (claimed) wants to connect", style = MaterialTheme.typography.headlineSmall)
                Text("Relay: ${state.offer.relayHost}", style = MaterialTheme.typography.bodySmall)
                Text("It will be able to send you requests. Each one still needs your approval.", style = MaterialTheme.typography.bodyMedium)
                Text("Signer", style = MaterialTheme.typography.titleSmall)
                signers.forEach { s ->
                    Row(Modifier.fillMaxWidth().selectable(selected = s.id == signerId, onClick = { signerId = s.id }), verticalAlignment = Alignment.CenterVertically) {
                        RadioButton(selected = s.id == signerId, onClick = { signerId = s.id })
                        Column {
                            Text(s.label)
                            Text(s.address, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
                Text("Remember for", style = MaterialTheme.typography.titleSmall)
                REMEMBER_FOR.forEach { (d, text) ->
                    Row(Modifier.selectable(selected = d == days, onClick = { days = d }), verticalAlignment = Alignment.CenterVertically) {
                        RadioButton(selected = d == days, onClick = { days = d })
                        Text(text)
                    }
                }
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                Button(
                    enabled = signerId != null,
                    modifier = Modifier.fillMaxWidth(),
                    onClick = {
                        val id = signerId ?: return@Button
                        scope.launch {
                            try {
                                val cipher = activity.unlock(app.vault.decryptCipher(id), "Connect ${state.offer.label}") ?: return@launch
                                app.keystore.connect(state, id, days, app.vault.open(id, cipher))
                            } catch (e: KeyPermanentlyInvalidatedException) {
                                error = "Your phone's security settings changed. Restore this signer from its recovery phrase."
                            } catch (e: Exception) {
                                error = "Could not unlock the signer: ${e.message}"
                            }
                        }
                    },
                ) { Text("Approve") }
                OutlinedButton(onClick = onDone, Modifier.fillMaxWidth()) { Text("Reject") }
            }
            is ConnectState.Working -> Row(verticalAlignment = Alignment.CenterVertically) {
                CircularProgressIndicator()
                Text("  Connecting ${state.label}…")
            }
            is ConnectState.Connected -> {
                Text("Connected to ${state.label}", style = MaterialTheme.typography.headlineSmall)
                Text(state.account, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                Text("Its requests will appear on the home screen when you open Blox.")
                Button(onClick = onDone, Modifier.fillMaxWidth()) { Text("OK") }
            }
            is ConnectState.Failed -> {
                Text(state.message, style = MaterialTheme.typography.titleMedium)
                Button(onClick = onDone, Modifier.fillMaxWidth()) { Text("OK") }
            }
        }
    }
}
