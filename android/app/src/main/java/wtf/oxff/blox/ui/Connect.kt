package wtf.oxff.blox.ui

import android.security.keystore.KeyPermanentlyInvalidatedException
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.selection.selectable
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.RadioButton
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import kotlinx.coroutines.launch
import wtf.oxff.blox.BloxApp
import wtf.oxff.blox.MainActivity
import wtf.oxff.blox.keystore.Keystore.ConnectState
import wtf.oxff.blox.vault.unlock

private val REMEMBER_FOR = listOf(1 to "1 day", 30 to "30 days", 90 to "90 days")

/** The connect flow (§5.2): relay consent, signer and duration, biometric, then waiting for `bound`. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConnectScreen(activity: MainActivity, app: BloxApp, state: ConnectState, onDone: () -> Unit) {
    val scope = rememberCoroutineScope()
    when (state) {
        ConnectState.Idle -> {}
        is ConnectState.RelayConsent -> BloxScreen(
            "Relay",
            onBack = onDone,
            bottom = { ButtonPair("Cancel", onDone, "Use this relay", { app.keystore.allowRelay(state) }) },
        ) {
            Section {
                InfoRow("Relay", state.offer.relayHost, mono = true)
                RowDivider()
                InfoRow("Site", "${state.offer.label} (claimed)")
            }
        }

        is ConnectState.Choose -> {
            val signers = app.vault.list()
            var signerId by remember { mutableStateOf(signers.firstOrNull()?.id) }
            var days by remember { mutableIntStateOf(30) }
            var error by remember { mutableStateOf<String?>(null) }
            BloxScreen(
                "Connect",
                onBack = onDone,
                bottom = {
                    ButtonPair(
                        "Reject", onDone,
                        "Approve", {
                            val id = signerId ?: return@ButtonPair
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
                        primaryEnabled = signerId != null,
                    )
                },
            ) {
                Section {
                    InfoRow("Site", "${state.offer.label} (claimed)")
                    RowDivider()
                    InfoRow("Relay", state.offer.relayHost, mono = true)
                }
                Section("Signer") {
                    Rows(signers) { s ->
                        Item(
                            s.label,
                            modifier = Modifier.selectable(selected = s.id == signerId, onClick = { signerId = s.id }),
                            supporting = s.address,
                            monoSupporting = true,
                            leading = { RadioButton(selected = s.id == signerId, onClick = null) },
                        )
                    }
                }
                Section("Remember for") {
                    SectionBody {
                        SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                            REMEMBER_FOR.forEachIndexed { i, (d, text) ->
                                SegmentedButton(
                                    selected = d == days,
                                    onClick = { days = d },
                                    shape = SegmentedButtonDefaults.itemShape(i, REMEMBER_FOR.size),
                                ) { Text(text) }
                            }
                        }
                    }
                }
                error?.let { Notice(it, Tone.Danger) }
            }
        }

        is ConnectState.Working -> BloxScreen("Connect") { Busy("Connecting ${state.label}…") }

        is ConnectState.Connected -> BloxScreen("Connected", bottom = { PrimaryButton("Done", onDone) }) {
            Section {
                InfoRow("Site", "${state.label} (claimed)")
                RowDivider()
                InfoRow("Account", state.account, mono = true)
            }
        }

        is ConnectState.Failed -> BloxScreen("Connect", onBack = onDone, bottom = { PrimaryButton("OK", onDone) }) {
            Notice(state.message, Tone.Danger)
        }
    }
}
