package wtf.oxff.blox.ui

import android.app.KeyguardManager
import android.content.Context
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.text.input.KeyboardType
import kotlinx.coroutines.launch
import uniffi.blox_ffi.generateMnemonic
import uniffi.blox_ffi.validateMnemonic
import wtf.oxff.blox.BloxApp
import wtf.oxff.blox.MainActivity
import wtf.oxff.blox.vault.unlock

private sealed interface Step {
    data object Choose : Step
    class Show(val phrase: ByteArray) : Step
    class Confirm(val phrase: ByteArray, val positions: List<Int>) : Step
    /** An existing phrase, typed in: portable, but only as safe as wherever it has been (§10.2). */
    data object Import : Step
}

/**
 * Adds a signer (§10.2), one of two ways:
 * - **Create**: a new phrase made on this phone, then a backup check (3 words) that can be skipped.
 * - **Import**: an existing phrase typed in. Less safe (it has been elsewhere), but portable.
 *
 * Either way the phrase is sealed under the signer's own wrapping key. A new phrase stays a
 * ByteArray (drawn by [SecretPhrase], checked by [wordMatches]) and is wiped once stored or
 * abandoned. A typed phrase is a String in the text field; that can't be avoided.
 */
@Composable
fun AddSigner(activity: MainActivity, app: BloxApp, onDone: () -> Unit, canCancel: Boolean) {
    var step by remember { mutableStateOf<Step>(Step.Choose) }
    var label by remember { mutableStateOf(if (app.vault.list().isEmpty()) "Main" else "") }
    var error by remember { mutableStateOf<String?>(null) }
    var phraseText by remember { mutableStateOf("") }
    val scope = rememberCoroutineScope()
    val secure = remember { (activity.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager).isDeviceSecure }

    // Leaving the screen any way at all wipes a new phrase that wasn't stored.
    DisposableEffect(Unit) {
        onDispose {
            when (val s = step) {
                is Step.Show -> s.phrase.fill(0)
                is Step.Confirm -> s.phrase.fill(0)
                else -> {}
            }
        }
    }

    // The phrase is wiped once it is stored; after a cancelled prompt or an error it stays,
    // so the user can try again from the same screen.
    fun seal(phrase: ByteArray, imported: Boolean) = scope.launch {
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
            app.vault.add(id, label.trim(), unlocked, phrase, imported)
            phrase.fill(0)
            onDone()
        } catch (e: Exception) {
            app.vault.abandon(id)
            error = e.message ?: "Could not store the signer"
        } finally {
            if (imported) phrase.fill(0) // typed again on a retry
        }
    }

    fun back() {
        error = null
        when (val s = step) {
            Step.Choose -> onDone()
            is Step.Show -> {
                s.phrase.fill(0) // a new phrase is made next time
                step = Step.Choose
            }
            is Step.Confirm -> step = Step.Show(s.phrase)
            Step.Import -> {
                phraseText = ""
                step = Step.Choose
            }
        }
    }
    val onBack: (() -> Unit)? = if (step == Step.Choose && !canCancel) null else ::back
    BackHandler(enabled = step != Step.Choose) { back() }

    if (!secure) {
        BloxScreen("Signer", onBack = if (canCancel) onDone else null) {
            Notice("Set a screen lock first.", Tone.Warning)
        }
        return
    }

    when (val s = step) {
        Step.Choose -> BloxScreen(
            "Signer",
            onBack = onBack,
            bottom = {
                ButtonPair(
                    "Import", {
                        error = null
                        step = Step.Import
                    },
                    "Create", {
                        error = null
                        step = Step.Show(generateMnemonic(12u))
                    },
                    primaryEnabled = label.isNotBlank(),
                    secondaryEnabled = label.isNotBlank(),
                )
            },
        ) {
            Field(label, { label = it.take(32) }, "Name")
            error?.let { Notice(it, Tone.Danger) }
        }

        is Step.Show -> BloxScreen(
            "Recovery phrase",
            onBack = onBack,
            bottom = {
                PrimaryButton("Next", {
                    step = Step.Confirm(s.phrase, wordRanges(s.phrase).indices.shuffled().take(3).sorted())
                })
            },
        ) {
            Section { SecretPhrase(s.phrase) }
        }

        is Step.Confirm -> {
            val ranges = remember(s) { wordRanges(s.phrase) }
            val answers = remember(s) { s.positions.map { mutableStateOf("") } }
            val ok = s.positions.withIndex().all { (k, pos) -> wordMatches(s.phrase, ranges[pos], answers[k].value) }
            BloxScreen(
                "Check backup",
                onBack = onBack,
                bottom = {
                    ButtonPair("Skip", { seal(s.phrase, imported = false) }, "Continue", { seal(s.phrase, imported = false) }, primaryEnabled = ok)
                },
            ) {
                s.positions.forEachIndexed { k, pos ->
                    Field(
                        answers[k].value,
                        { answers[k].value = it.trim().lowercase() },
                        "Word ${pos + 1}",
                        mono = true,
                        keyboardOptions = KeyboardOptions(autoCorrectEnabled = false, keyboardType = KeyboardType.Password),
                    )
                }
                error?.let { Notice(it, Tone.Danger) }
            }
        }

        Step.Import -> BloxScreen(
            "Import",
            onBack = onBack,
            bottom = {
                PrimaryButton("Import", {
                    val phrase = parsePhrase(phraseText)
                    if (phrase == null) {
                        error = "Not a valid recovery phrase"
                    } else {
                        error = null
                        phraseText = ""
                        seal(phrase, imported = true)
                    }
                }, enabled = phraseText.isNotBlank())
            },
        ) {
            PhraseField(phraseText, { phraseText = it })
            error?.let { Notice(it, Tone.Danger) }
        }
    }
}

/** Typing a recovery phrase (import, and restoring a listed signer). */
@Composable
fun PhraseField(text: String, onText: (String) -> Unit) {
    val n = text.trim().split(Regex("\\s+")).count { it.isNotEmpty() }
    Field(
        text,
        { onText(it.lowercase()) },
        "Recovery phrase",
        singleLine = false,
        minLines = 3,
        mono = true,
        supporting = if (n > 0) plural(n, "word") else null,
        keyboardOptions = KeyboardOptions(autoCorrectEnabled = false, keyboardType = KeyboardType.Password),
    )
}

/** The phrase as normalized bytes, or null (and nothing left behind) if it isn't valid. */
fun parsePhrase(text: String): ByteArray? {
    val phrase = text.trim().split(Regex("\\s+")).joinToString(" ").toByteArray()
    if (validateMnemonic(phrase)) return phrase // Rust wipes its copy
    phrase.fill(0)
    return null
}
