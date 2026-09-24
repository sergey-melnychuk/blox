package wtf.oxff.blox.ui

import android.app.KeyguardManager
import android.content.Context
import android.security.keystore.KeyPermanentlyInvalidatedException
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
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
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import uniffi.blox_ffi.deriveEvmAddresses
import uniffi.blox_ffi.generateMnemonic
import uniffi.blox_ffi.validateMnemonic
import wtf.oxff.blox.BloxApp
import wtf.oxff.blox.MainActivity
import wtf.oxff.blox.vault.unlock

private sealed interface Step {
    data object Choose : Step
    class Show(val phrase: ByteArray) : Step
    class Confirm(val phrase: ByteArray, val positions: List<Int>) : Step
    data object Import : Step
}

/**
 * Create or import a recovery phrase, then seal it in the vault (§10.2).
 *
 * The phrase has to become a String to be displayed or typed; those copies are
 * short-lived UI state. The ByteArray copies are wiped as soon as the vault holds it.
 */
@Composable
fun Onboarding(activity: MainActivity, app: BloxApp, onDone: () -> Unit) {
    var step by remember { mutableStateOf<Step>(Step.Choose) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    val secure = remember { (activity.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager).isDeviceSecure }

    fun seal(phrase: ByteArray) = scope.launch {
        try {
            app.vault.createKey()
            val cipher = activity.unlock(app.vault.encryptCipher(), "Protect your key") ?: return@launch
            app.vault.store(cipher, phrase)
            // FFI calls copy the bytes into Rust (which wipes its copy); `phrase` is wiped below.
            app.accounts.save(deriveEvmAddresses(phrase, 0u, 1u))
            phrase.fill(0)
            onDone()
        } catch (e: KeyPermanentlyInvalidatedException) {
            error = "Your screen lock changed. Try again."
        } catch (e: Exception) {
            error = "Could not store the key: ${e.message}"
        }
    }

    Column(
        Modifier.padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("Set up Blox", style = MaterialTheme.typography.headlineMedium)
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        if (!secure) {
            Text("Set a screen lock (PIN, pattern or password) first. Blox uses it to protect your key.")
            return@Column
        }
        when (val s = step) {
            Step.Choose -> {
                Text("Your key is created from a recovery phrase. Anyone with the phrase controls your funds.")
                Button(onClick = { step = Step.Show(generateMnemonic(12u)) }, Modifier.fillMaxWidth()) {
                    Text("Create a new key")
                }
                OutlinedButton(onClick = { step = Step.Import }, Modifier.fillMaxWidth()) {
                    Text("Import a recovery phrase")
                }
            }
            is Step.Show -> {
                Text("Write these 12 words down, in order, on paper. Don't photograph them.")
                val words = String(s.phrase).split(" ")
                words.forEachIndexed { i, w ->
                    Text("${i + 1}. $w", fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.titleMedium)
                }
                Button(onClick = {
                    step = Step.Confirm(s.phrase, words.indices.shuffled().take(3).sorted())
                }, Modifier.fillMaxWidth()) { Text("I wrote them down") }
            }
            is Step.Confirm -> {
                val words = remember(s) { String(s.phrase).split(" ") }
                val answers = remember(s) { s.positions.map { mutableStateOf("") } }
                Text("Check your backup: enter these words.")
                s.positions.forEachIndexed { k, pos ->
                    OutlinedTextField(
                        value = answers[k].value,
                        onValueChange = { answers[k].value = it.trim().lowercase() },
                        label = { Text("Word ${pos + 1}") },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(autoCorrectEnabled = false, keyboardType = KeyboardType.Password),
                    )
                }
                val ok = s.positions.withIndex().all { (k, pos) -> answers[k].value == words[pos] }
                Button(onClick = { seal(s.phrase) }, enabled = ok, modifier = Modifier.fillMaxWidth()) { Text("Continue") }
                OutlinedButton(onClick = { step = Step.Show(s.phrase) }, Modifier.fillMaxWidth()) { Text("Show the words again") }
            }
            Step.Import -> {
                var text by remember { mutableStateOf("") }
                OutlinedTextField(
                    value = text,
                    onValueChange = { text = it.lowercase() },
                    label = { Text("Recovery phrase") },
                    minLines = 3,
                    keyboardOptions = KeyboardOptions(autoCorrectEnabled = false, keyboardType = KeyboardType.Password),
                    modifier = Modifier.fillMaxWidth(),
                )
                Button(onClick = {
                    val phrase = text.trim().split(Regex("\\s+")).joinToString(" ").toByteArray()
                    if (validateMnemonic(phrase)) {
                        text = ""
                        seal(phrase)
                    } else {
                        phrase.fill(0)
                        error = "That isn't a valid recovery phrase."
                    }
                }, Modifier.fillMaxWidth()) { Text("Import") }
                OutlinedButton(onClick = { step = Step.Choose }, Modifier.fillMaxWidth()) { Text("Back") }
            }
        }
    }
}
