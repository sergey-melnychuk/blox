package wtf.oxff.blox.ui

import android.security.keystore.KeyPermanentlyInvalidatedException
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
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
import wtf.oxff.blox.BloxApp
import wtf.oxff.blox.MainActivity
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
    val scope = rememberCoroutineScope()

    // Per request: typed confirmations, the acknowledgement, and the approval in flight.
    var error by remember(p.requestId) { mutableStateOf<String?>(null) }
    var busy by remember(p.requestId) { mutableStateOf(false) }
    var acknowledged by remember(p.requestId) { mutableStateOf(false) }
    val ready = p.state as? ReviewState.Ready
    val typed = remember(p.requestId, ready != null) { ready?.display?.dangers?.map { mutableStateOf("") } ?: emptyList() }

    val bottom: (@Composable ColumnScope.() -> Unit)? = when (val st = p.state) {
        is ReviewState.Ready -> {
            val display = st.display
            val needsAck = display.dangers.any { it.confirm == null }
            val confirmed = display.dangers.withIndex().all { (i, d) -> d.confirm == null || typed.getOrNull(i)?.value.equals(d.confirm, ignoreCase = true) } &&
                (!needsAck || acknowledged)
            ({
                ButtonPair(
                    "Reject", { app.keystore.reject(p) },
                    "Approve", {
                        scope.launch {
                            busy = true
                            try {
                                val cipher = activity.unlock(app.vault.decryptCipher(p.signerId), "Approve with ${signer?.label ?: ""}", display.title)
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
                    primaryEnabled = confirmed && !busy,
                    secondaryEnabled = !busy,
                )
            })
        }
        is ReviewState.WouldFail -> ({ PrimaryButton("Reject", { app.keystore.reject(p) }) })
        is ReviewState.Unreachable -> ({ ButtonPair("Reject", { app.keystore.reject(p) }, "Retry", { app.keystore.review(p) }) })
        else -> null
    }

    BloxScreen(p.label, onBack = onBack, bottom = bottom) {
        val origin = listOfNotNull(p.request.originName(), p.request.originUrl()).joinToString(" · ")
        Section {
            InfoRow("From", "${p.label} (claimed)")
            if (origin.isNotEmpty()) {
                RowDivider()
                InfoRow("Page", origin)
            }
            RowDivider()
            InfoRow("Signer", signer?.let { "${it.label} · ${shortAddress(it.address)}" } ?: "")
        }
        if (items.size > 1) {
            Notice("${items.size} requests: the older one may be a duplicate.", Tone.Warning)
        }
        when (val st = p.state) {
            ReviewState.Loading -> Busy("Preparing…")
            is ReviewState.Ready -> {
                val display = st.display
                Text(display.title, style = MaterialTheme.typography.headlineSmall)
                display.dangers.forEachIndexed { i, d ->
                    Notice(d.message, Tone.Danger, extra = d.confirm?.let { code ->
                        {
                            Field(
                                typed.getOrNull(i)?.value ?: "",
                                { v -> typed.getOrNull(i)?.value = v.trim() },
                                "Type $code to continue",
                                mono = true,
                                keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Characters, autoCorrectEnabled = false),
                            )
                        }
                    })
                }
                if (display.dangers.any { it.confirm == null }) {
                    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = acknowledged, onCheckedChange = { acknowledged = it })
                        Text("I understand the risk", Modifier.padding(start = 4.dp))
                    }
                }
                display.warnings.forEach { Notice(it, Tone.Warning) }
                Section {
                    Rows(display.fields) { f ->
                        var expanded by remember(f) { mutableStateOf(false) }
                        InfoRow(
                            f.label,
                            if (expanded) f.full ?: f.value else f.value,
                            mono = true,
                            onClick = f.full?.let { { expanded = !expanded } },
                        )
                    }
                }
                display.decoded?.let {
                    Section("Decoded") {
                        Text(it, Modifier.padding(16.dp), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                    }
                }
                error?.let { Notice(it, Tone.Danger) }
            }
            is ReviewState.WouldFail -> Notice(st.message, Tone.Danger, title = "Would fail")
            is ReviewState.Unreachable -> Notice(st.message, Tone.Warning, title = "Endpoint unreachable")
            ReviewState.Withdrawn -> Notice("Withdrawn by the site")
            is ReviewState.Done -> Notice(describe(st.response))
        }
    }
}
