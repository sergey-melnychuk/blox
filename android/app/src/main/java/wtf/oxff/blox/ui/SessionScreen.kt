package wtf.oxff.blox.ui

import android.security.keystore.KeyPermanentlyInvalidatedException
import androidx.compose.foundation.clickable
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
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import uniffi.blox_ffi.PendingRequest
import uniffi.blox_ffi.UiDisplay
import wtf.oxff.blox.BloxApp
import wtf.oxff.blox.MainActivity
import wtf.oxff.blox.session.SessionController.Info
import wtf.oxff.blox.session.SessionController.State
import wtf.oxff.blox.vault.unlock

@Composable
fun SessionScreen(activity: MainActivity, app: BloxApp, state: State) {
    Column(
        Modifier.padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        when (state) {
            State.Idle -> {}
            State.Joining -> Row(verticalAlignment = Alignment.CenterVertically) {
                CircularProgressIndicator()
                Text("  Joining…")
            }
            is State.Waiting -> {
                Header(state.info)
                Text("Waiting for a request from your computer…")
                Button(onClick = { app.session.done() }, Modifier.fillMaxWidth()) { Text("Done") }
            }
            is State.Reviewing -> {
                Header(state.info)
                Review(activity, app, state.request, state.display)
            }
            is State.Ended -> {
                Text(state.message, style = MaterialTheme.typography.titleMedium)
                Button(onClick = { app.session.dismiss() }, Modifier.fillMaxWidth()) { Text("OK") }
            }
        }
    }
}

@Composable
private fun Header(info: Info) {
    Text("Connected to ${info.label}", style = MaterialTheme.typography.titleLarge)
    Text(
        "${info.relayHost} · ${if (info.connected) "online" else "reconnecting…"} · " +
            "${info.signed} signed · ${info.rejected} rejected",
        style = MaterialTheme.typography.bodySmall,
    )
}

@Composable
private fun Review(activity: MainActivity, app: BloxApp, request: PendingRequest, display: UiDisplay) {
    val scope = rememberCoroutineScope()
    var error by remember(request) { mutableStateOf<String?>(null) }
    val typed = remember(request) { display.dangers.map { mutableStateOf("") } }
    var acknowledged by remember(request) { mutableStateOf(false) }

    Text(display.title, style = MaterialTheme.typography.headlineSmall)
    display.originClient?.let {
        Text("Claims to be from: $it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
    }

    display.dangers.forEachIndexed { i, d ->
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(d.message, color = MaterialTheme.colorScheme.onErrorContainer)
                d.confirm?.let { code ->
                    OutlinedTextField(
                        value = typed[i].value,
                        onValueChange = { typed[i].value = it.trim() },
                        label = { Text("Type $code to continue") },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Characters, autoCorrectEnabled = false),
                    )
                }
            }
        }
    }
    val needsAck = display.dangers.any { it.confirm == null }
    if (needsAck) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = acknowledged, onCheckedChange = { acknowledged = it })
            Text("I understand the risk")
        }
    }
    display.warnings.forEach { Text("⚠ $it", color = MaterialTheme.colorScheme.tertiary) }

    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            display.fields.forEach { f ->
                var expanded by remember(f) { mutableStateOf(false) }
                Column(Modifier.clickable(enabled = f.full != null) { expanded = !expanded }) {
                    Text(f.label, style = MaterialTheme.typography.labelMedium)
                    Text(
                        if (expanded) f.full ?: f.value else f.value,
                        fontFamily = FontFamily.Monospace,
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
        }
    }
    display.decoded?.let {
        Card(Modifier.fillMaxWidth()) {
            Text(it, Modifier.padding(16.dp), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
        }
    }
    error?.let { Text(it, color = MaterialTheme.colorScheme.error) }

    val confirmed = display.dangers.withIndex().all { (i, d) -> d.confirm == null || typed[i].value.equals(d.confirm, ignoreCase = true) } &&
        (!needsAck || acknowledged)
    Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
        OutlinedButton(onClick = { app.session.reject(request) }, Modifier.weight(1f)) { Text("Reject") }
        Button(
            enabled = confirmed,
            modifier = Modifier.weight(1f),
            onClick = {
                scope.launch {
                    try {
                        val cipher = activity.unlock(app.vault.decryptCipher(), "Approve ${display.title.lowercase()}")
                            ?: return@launch
                        app.session.approve(request, app.vault.open(cipher))
                    } catch (e: KeyPermanentlyInvalidatedException) {
                        error = "Your phone's security settings changed. Restore from your recovery phrase."
                    } catch (e: Exception) {
                        error = "Could not unlock the key: ${e.message}"
                    }
                }
            },
        ) { Text("Approve") }
    }
}
