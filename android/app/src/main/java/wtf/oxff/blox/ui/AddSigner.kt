package wtf.oxff.blox.ui

import android.app.KeyguardManager
import android.content.Context
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
import uniffi.blox_ffi.generateMnemonic
import uniffi.blox_ffi.validateMnemonic
import wtf.oxff.blox.BloxApp
import wtf.oxff.blox.BuildConfig
import wtf.oxff.blox.MainActivity
import wtf.oxff.blox.vault.unlock

private sealed interface Step {
    data object Choose : Step
    class Show(val phrase: ByteArray) : Step
    class Confirm(val phrase: ByteArray, val positions: List<Int>) : Step
    /** Debug builds only (anvil's test phrase); v2 for release builds (§10.2, §12.5). */
    data object Import : Step
}

/**
 * Adds a signer (§10.2): a new phrase with a backup check (3 words), sealed under the
 * signer's own wrapping key. The phrase becomes a String only to be displayed or typed; the
 * ByteArray copies are wiped once the vault holds it.
 */
@Composable
fun AddSigner(activity: MainActivity, app: BloxApp, onDone: () -> Unit, canCancel: Boolean) {
    var step by remember { mutableStateOf<Step>(Step.Choose) }
    var label by remember { mutableStateOf(if (app.vault.list().isEmpty()) "Main" else "") }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    val secure = remember { (activity.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager).isDeviceSecure }

    // The phrase is wiped once it is stored; after a cancelled prompt or an error it stays,
    // so the user can try again from the same screen.
    fun seal(phrase: ByteArray) = scope.launch {
        val (id, cipher) = try {
            app.vault.newSigner()
        } catch (e: Exception) {
            error = "Could not create a key: ${e.message}"
            return@launch
        }
        try {
            val unlocked = activity.unlock(cipher, "Protect “${label.trim()}”")
            if (unlocked == null) {
                app.vault.abandon(id)
                return@launch
            }
            app.vault.add(id, label.trim(), unlocked, phrase)
            phrase.fill(0)
            onDone()
        } catch (e: Exception) {
            app.vault.abandon(id)
            error = e.message ?: "Could not store the signer"
        }
    }

    Column(Modifier.padding(24.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text("Add a signer", style = MaterialTheme.typography.headlineMedium)
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        if (!secure) {
            Text("Set a screen lock (PIN, pattern or password) first. Blox uses it to protect your keys.")
            return@Column
        }
        when (val s = step) {
            Step.Choose -> {
                Text("A signer is a key made from a recovery phrase. Anyone with the phrase controls its funds.")
                OutlinedTextField(value = label, onValueChange = { label = it.take(32) }, label = { Text("Name (e.g. Savings)") }, singleLine = true)
                Button(
                    onClick = { step = Step.Show(generateMnemonic(12u)) },
                    enabled = label.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Create a new signer") }
                if (BuildConfig.DEBUG) {
                    OutlinedButton(onClick = { step = Step.Import }, enabled = label.isNotBlank(), modifier = Modifier.fillMaxWidth()) {
                        Text("Import a phrase (debug builds)")
                    }
                }
                if (canCancel) OutlinedButton(onClick = onDone, modifier = Modifier.fillMaxWidth()) { Text("Cancel") }
            }
            is Step.Show -> {
                Text("Write these 12 words down, in order, on paper. Don't photograph them.")
                val words = String(s.phrase).split(" ")
                words.forEachIndexed { i, w ->
                    Text("${i + 1}. $w", fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.titleMedium)
                }
                Button(onClick = { step = Step.Confirm(s.phrase, words.indices.shuffled().take(3).sorted()) }, Modifier.fillMaxWidth()) {
                    Text("I wrote them down")
                }
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
            Step.Import -> PhraseInput(
                action = "Import",
                onPhrase = { phrase -> seal(phrase) },
                onBack = { step = Step.Choose },
                onError = { error = it },
            )
        }
    }
}

/** Typing a phrase (debug import, and restoring a listed signer in any build). */
@Composable
fun PhraseInput(action: String, onPhrase: (ByteArray) -> Unit, onBack: () -> Unit, onError: (String) -> Unit) {
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
            onPhrase(phrase)
        } else {
            phrase.fill(0)
            onError("That isn't a valid recovery phrase.")
        }
    }, Modifier.fillMaxWidth()) { Text(action) }
    OutlinedButton(onClick = onBack, Modifier.fillMaxWidth()) { Text("Back") }
}
