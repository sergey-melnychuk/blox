package wtf.oxff.blox.ui

import android.security.keystore.KeyPermanentlyInvalidatedException
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.text.input.KeyboardCapitalization
import java.text.DateFormat
import java.util.Date
import kotlinx.coroutines.launch
import uniffi.blox_ffi.relayHost
import wtf.oxff.blox.BloxApp
import wtf.oxff.blox.MainActivity
import wtf.oxff.blox.vault.unlock

/** A signer (§10.6): its connections, its phrase, restoring and removing it (§10.2). */
@Composable
fun SignerScreen(activity: MainActivity, app: BloxApp, signerId: String, onBack: () -> Unit) {
    val signer = app.vault.get(signerId) ?: return onBack()
    val scope = rememberCoroutineScope()
    var refresh by remember { mutableIntStateOf(0) }
    val connections = remember(refresh) { app.connections.forSigner(signerId) }
    // The unlocked phrase while it's shown: bytes only (SecretPhrase), wiped on Hide or leaving.
    var phrase by remember { mutableStateOf<ByteArray?>(null) }
    var removing by remember { mutableStateOf(false) }
    var restoring by remember { mutableStateOf(false) }
    var restoreText by remember { mutableStateOf("") }
    var typed by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    val fmt = remember { DateFormat.getDateInstance(DateFormat.MEDIUM) }
    val level = app.vault.securityLevel(signerId)

    fun hide() {
        phrase?.fill(0)
        phrase = null
    }
    DisposableEffect(Unit) { onDispose { hide() } }

    BloxScreen(signer.label, onBack = onBack) {
        Section {
            InfoRow("Address", signer.address, mono = true)
            RowDivider()
            InfoRow("Key", securityLong(level))
            RowDivider()
            InfoRow("Phrase", if (signer.imported) "Imported" else "Created here")
        }
        error?.let { Notice(it, Tone.Danger, onClick = { error = null }) }

        Section("Connections") {
            if (connections.isEmpty()) Item("None")
            Rows(connections) { c ->
                Item(
                    "${c.record.label} (claimed)",
                    overline = relayHost(c.record.relay),
                    supporting = listOfNotNull(
                        "${fmt.format(Date(c.connectedAt))} – ${fmt.format(Date(c.record.expiresAt.toLong() * 1000))}",
                        c.lastRequestAt?.let { "Last request ${fmt.format(Date(it))}" },
                    ).joinToString("\n"),
                    trailing = {
                        SmallTextButton("Disconnect", {
                            scope.launch {
                                app.keystore.disconnect(c)
                                refresh++
                            }
                        }, color = MaterialTheme.colorScheme.error)
                    },
                )
            }
        }

        Section("Recovery phrase") {
            val shown = phrase
            if (shown != null) {
                SecretPhrase(shown)
                SectionBody { SecondaryButton("Hide", ::hide) }
            } else {
                Item(
                    "Show",
                    leading = { Icon(Icons.Filled.Lock, contentDescription = null) },
                    onClick = {
                        scope.launch {
                            try {
                                val cipher = activity.unlock(app.vault.decryptCipher(signerId), "Show the recovery phrase") ?: return@launch
                                phrase = app.vault.open(signerId, cipher)
                            } catch (e: KeyPermanentlyInvalidatedException) {
                                error = "Your phone's security settings changed. Restore this signer from its recovery phrase."
                                restoring = true
                            } catch (e: Exception) {
                                error = "Could not unlock: ${e.message}"
                            }
                        }
                    },
                )
            }
            RowDivider()
            if (!restoring) {
                Item("Restore", leading = { Icon(Icons.Filled.Refresh, contentDescription = null) }, onClick = { restoring = true })
            } else {
                SectionBody {
                    PhraseField(restoreText, { restoreText = it })
                    ButtonPair("Cancel", {
                        restoring = false
                        restoreText = ""
                    }, "Restore", {
                        val bytes = parsePhrase(restoreText)
                        if (bytes == null) {
                            error = "Not a valid recovery phrase"
                            return@ButtonPair
                        }
                        scope.launch {
                            try {
                                val cipher = activity.unlock(app.vault.beginRestore(signerId), "Protect “${signer.label}”") ?: return@launch
                                app.vault.completeRestore(signerId, cipher, bytes)
                                restoring = false
                                restoreText = ""
                                error = null
                            } catch (e: Exception) {
                                error = e.message
                            } finally {
                                bytes.fill(0)
                            }
                        }
                    }, primaryEnabled = restoreText.isNotBlank())
                }
            }
        }

        Section {
            if (!removing) {
                Item(
                    "Remove",
                    headlineColor = MaterialTheme.colorScheme.error,
                    leading = { Icon(Icons.Filled.Delete, contentDescription = null, tint = MaterialTheme.colorScheme.error) },
                    onClick = { removing = true },
                )
            } else {
                val code = signer.address.takeLast(4)
                SectionBody {
                    Notice("Without the recovery phrase, the funds are lost.", Tone.Danger)
                    Field(
                        typed,
                        { typed = it.trim() },
                        "Type $code",
                        mono = true,
                        keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Characters, autoCorrectEnabled = false),
                    )
                    ButtonPair("Cancel", {
                        removing = false
                        typed = ""
                    }, "Remove", {
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
                    }, primaryEnabled = typed.equals(code, ignoreCase = true), danger = true)
                }
            }
        }
    }
}
