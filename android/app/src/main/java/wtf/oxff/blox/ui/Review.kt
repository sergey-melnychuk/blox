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
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
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
import uniffi.blox_ffi.UiDisplay
import wtf.oxff.blox.BloxApp
import wtf.oxff.blox.MainActivity
import wtf.oxff.blox.keystore.Keystore.Pending
import wtf.oxff.blox.keystore.Keystore.ReviewState
import wtf.oxff.blox.keystore.describe
import wtf.oxff.blox.vault.unlock

/** One connection's requests, oldest first, one at a time (§10.5, §10.6). */
@Composable
fun ReviewScreen(activity: MainActivity, app: BloxApp, connectionId: String, onBack: () -> Unit) {
    val all by app.keystore.pending.collectAsState()
    val items = all.filter { it.connectionId == connectionId }
    LaunchedEffect(items.isEmpty()) { if (items.isEmpty()) onBack() }
    val p = items.firstOrNull() ?: return
    val signer = app.vault.get(p.signerId)

    Column(Modifier.padding(24.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        TextButton(onClick = onBack) { Text("‹ Back") }
        Text(p.label, style = MaterialTheme.typography.titleLarge)
        val origin = listOfNotNull(p.request.originName(), p.request.originUrl()).joinToString(" · ")
        if (origin.isNotEmpty()) {
            Text("Claims to be from: $origin", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
        }
        if (items.size > 1) {
            Text(
                "${p.label} sent ${items.size} requests. If you retried on the site, the older one may be a duplicate.",
                color = MaterialTheme.colorScheme.tertiary,
            )
        }
        when (val st = p.state) {
            ReviewState.Loading -> Row(verticalAlignment = Alignment.CenterVertically) {
                CircularProgressIndicator()
                Text("  Preparing…")
            }
            is ReviewState.Ready -> Ready(activity, app, p, st.display, signer?.label ?: "")
            is ReviewState.WouldFail -> {
                Text("This transaction would fail", style = MaterialTheme.typography.headlineSmall, color = MaterialTheme.colorScheme.error)
                Text(st.message, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                Button(onClick = { app.keystore.reject(p) }, Modifier.fillMaxWidth()) { Text("Reject") }
            }
            is ReviewState.Unreachable -> {
                Text("The network endpoint can't be reached", style = MaterialTheme.typography.titleMedium)
                Text(st.message, style = MaterialTheme.typography.bodySmall)
                Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                    OutlinedButton(onClick = { app.keystore.reject(p) }, Modifier.weight(1f)) { Text("Reject") }
                    Button(onClick = { app.keystore.review(p) }, Modifier.weight(1f)) { Text("Retry") }
                }
            }
            ReviewState.Withdrawn -> Text("The site withdrew this request.", style = MaterialTheme.typography.titleMedium)
            is ReviewState.Done -> Text(describe(st.response), style = MaterialTheme.typography.titleMedium)
        }
    }
}

@Composable
private fun Ready(activity: MainActivity, app: BloxApp, p: Pending, display: UiDisplay, signerLabel: String) {
    val scope = rememberCoroutineScope()
    var error by remember(p.requestId) { mutableStateOf<String?>(null) }
    var busy by remember(p.requestId) { mutableStateOf(false) }
    val typed = remember(p.requestId) { display.dangers.map { mutableStateOf("") } }
    var acknowledged by remember(p.requestId) { mutableStateOf(false) }

    Text(display.title, style = MaterialTheme.typography.headlineSmall)
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
                    Text(if (expanded) f.full ?: f.value else f.value, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyMedium)
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
        OutlinedButton(onClick = { app.keystore.reject(p) }, enabled = !busy, modifier = Modifier.weight(1f)) { Text("Reject") }
        Button(
            enabled = confirmed && !busy,
            modifier = Modifier.weight(1f),
            onClick = {
                scope.launch {
                    busy = true
                    try {
                        val cipher = activity.unlock(app.vault.decryptCipher(p.signerId), "Approve with $signerLabel", display.title)
                            ?: return@launch
                        app.keystore.approve(p, app.vault.open(p.signerId, cipher))
                    } catch (e: KeyPermanentlyInvalidatedException) {
                        error = "Your phone's security settings changed. Restore this signer from its recovery phrase."
                    } catch (e: Exception) {
                        error = "Could not sign: ${e.message}"
                    } finally {
                        busy = false
                    }
                }
            },
        ) { Text("Approve") }
    }
}
