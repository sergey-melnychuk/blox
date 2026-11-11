package wtf.oxff.blox.vault

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.io.File
import java.security.KeyStore
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import org.json.JSONArray
import org.json.JSONObject
import uniffi.blox_ffi.deriveEvmAddresses
import uniffi.blox_ffi.generateTransportKeys

/** A signer's public facts, stored unencrypted so signers can be listed without unlocking (§10.2). */
data class SignerInfo(
    val id: String,
    val label: String,
    /** Checksummed EVM address at m/44'/60'/0'/0/0. */
    val address: String,
    /** Android Keystore alias of this signer's own wrapping key. */
    val alias: String,
    /** Seed file, relative to noBackupFilesDir. */
    val file: String,
    /**
     * The phrase was typed in rather than made on this phone: it is only as safe as wherever
     * else it was ever written or stored (§10.2).
     */
    val imported: Boolean = false,
)

/**
 * The signers' seeds and transport keys (BLOX.md §10.2).
 *
 * - Each seed is encrypted (AES-256-GCM) under **its own** Android Keystore key that needs a
 *   fresh authentication for every use: the Cipher only works after BiometricPrompt unlocked
 *   it, so approving and decrypting are one step.
 * - Transport keys (`K`/`k`) are encrypted under one key, [TRANSPORT_ALIAS], that needs no
 *   authentication, so inboxes can be read when the app opens. They can't sign anything.
 * - Removing a signer deletes its wrapping key first, which makes the seed unreadable even if
 *   the file survives on flash storage.
 */
class SignerVault(private val context: Context) {
    private val root = context.noBackupFilesDir
    private val prefs = context.getSharedPreferences("signers", Context.MODE_PRIVATE)
    private val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    init {
        migrateSingleSeed()
    }

    fun list(): List<SignerInfo> {
        val arr = JSONArray(prefs.getString(KEY, "[]"))
        return List(arr.length()) { i ->
            val o = arr.getJSONObject(i)
            SignerInfo(
                o.getString("id"), o.getString("label"), o.getString("address"), o.getString("alias"), o.getString("file"),
                o.optBoolean("imported", false),
            )
        }
    }

    fun get(id: String): SignerInfo? = list().firstOrNull { it.id == id }

    private fun save(list: List<SignerInfo>) {
        val arr = JSONArray()
        list.forEach {
            arr.put(
                JSONObject().put("id", it.id).put("label", it.label).put("address", it.address).put("alias", it.alias)
                    .put("file", it.file).put("imported", it.imported),
            )
        }
        prefs.edit().putString(KEY, arr.toString()).apply()
    }

    fun rename(id: String, label: String) = save(list().map { if (it.id == id) it.copy(label = label) else it })

    /** Step 1 of adding a signer: a new wrapping key, and a cipher for BiometricPrompt to unlock. */
    fun newSigner(): Pair<String, Cipher> {
        val id = UUID.randomUUID().toString()
        val alias = "$SEED_ALIAS_PREFIX$id"
        createAuthKey(alias)
        return id to encryptCipher(alias)
    }

    /** Drops the wrapping key of a signer that was never added (a cancelled prompt). */
    fun abandon(id: String) {
        if (get(id) == null) keyStore.deleteEntry("$SEED_ALIAS_PREFIX$id")
    }

    /**
     * Step 2: encrypts `phrase` with the unlocked cipher, creates the transport keys and lists
     * the signer. `imported` marks a phrase typed in rather than made here. The caller wipes `phrase`.
     * @throws IllegalStateException if a signer with the same address exists.
     */
    fun add(id: String, label: String, unlocked: Cipher, phrase: ByteArray, imported: Boolean): SignerInfo {
        val address = deriveEvmAddresses(phrase, 0u, 1u).first()
        if (list().any { it.address.equals(address, ignoreCase = true) }) {
            keyStore.deleteEntry("$SEED_ALIAS_PREFIX$id")
            throw IllegalStateException("This signer is already on the phone")
        }
        val info = SignerInfo(id, label, address, "$SEED_ALIAS_PREFIX$id", "seeds/$id.bin", imported)
        writeSeed(info, unlocked, phrase)
        writeTransportKeys(id)
        save(list() + info)
        return info
    }

    /**
     * Restores a signer the keystore already lists after its wrapping key was invalidated
     * (e.g. the screen lock was removed). Allowed in release builds: the restored address
     * must match (§10.2). Returns the cipher to unlock; then call [completeRestore].
     */
    fun beginRestore(id: String): Cipher {
        val info = requireNotNull(get(id))
        createAuthKey(info.alias)
        return encryptCipher(info.alias)
    }

    fun completeRestore(id: String, unlocked: Cipher, phrase: ByteArray) {
        val info = requireNotNull(get(id))
        val address = deriveEvmAddresses(phrase, 0u, 1u).first()
        check(address.equals(info.address, ignoreCase = true)) { "This phrase belongs to another account" }
        writeSeed(info, unlocked, phrase)
    }

    /**
     * A Cipher to decrypt `id`'s phrase. Must be unlocked by BiometricPrompt before use.
     * @throws KeyPermanentlyInvalidatedException if the screen lock was removed: restore.
     */
    fun decryptCipher(id: String): Cipher {
        val info = requireNotNull(get(id))
        val blob = File(root, info.file).readBytes()
        val iv = blob.copyOfRange(0, IV_LEN)
        return Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.DECRYPT_MODE, key(info.alias), GCMParameterSpec(128, iv)) }
    }

    /** Decrypts the phrase with an unlocked cipher. The caller must wipe the result. */
    fun open(id: String, unlocked: Cipher): ByteArray {
        val info = requireNotNull(get(id))
        val blob = File(root, info.file).readBytes()
        return unlocked.doFinal(blob, IV_LEN, blob.size - IV_LEN)
    }

    /** `(K secret, k secret)`; the caller wipes both when done. */
    fun transportSecrets(id: String): Pair<ByteArray, ByteArray> {
        val blob = File(root, "transport/$id.bin").readBytes()
        val cipher = Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.DECRYPT_MODE, key(TRANSPORT_ALIAS), GCMParameterSpec(128, blob.copyOfRange(0, IV_LEN)))
        }
        val both = cipher.doFinal(blob, IV_LEN, blob.size - IV_LEN)
        return try {
            both.copyOfRange(0, 32) to both.copyOfRange(32, 64)
        } finally {
            both.fill(0)
        }
    }

    /** Deletes the wrapping key first, then the files and the listing. */
    fun remove(id: String) {
        val info = get(id) ?: return
        keyStore.deleteEntry(info.alias)
        File(root, info.file).delete()
        File(root, "transport/$id.bin").delete()
        save(list().filter { it.id != id })
    }

    /** Where the signer's wrapping key actually lives, for display and a software-only warning. */
    fun securityLevel(id: String): SecurityLevel? = runCatching {
        val k = key(requireNotNull(get(id)).alias)
        val info = SecretKeyFactory.getInstance(k.algorithm, KEYSTORE).getKeySpec(k, KeyInfo::class.java) as KeyInfo
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> SecurityLevel.STRONGBOX
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> SecurityLevel.TEE
                else -> SecurityLevel.SOFTWARE
            }
        } else {
            @Suppress("DEPRECATION")
            if (info.isInsideSecureHardware) SecurityLevel.TEE else SecurityLevel.SOFTWARE
        }
    }.getOrNull()

    enum class SecurityLevel { STRONGBOX, TEE, SOFTWARE }

    // ---- internals ------------------------------------------------------------------

    private fun writeSeed(info: SignerInfo, unlocked: Cipher, phrase: ByteArray) {
        val ct = unlocked.doFinal(phrase)
        val file = File(root, info.file).apply { parentFile?.mkdirs() }
        val tmp = File(file.parentFile, file.name + ".tmp")
        tmp.writeBytes(unlocked.iv + ct)
        check(tmp.renameTo(file)) { "could not write the seed" }
    }

    private fun writeTransportKeys(id: String) {
        if (!keyStore.containsAlias(TRANSPORT_ALIAS)) createPlainKey(TRANSPORT_ALIAS)
        val t = generateTransportKeys()
        val both = t.sigSecret + t.kemSecret
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key(TRANSPORT_ALIAS)) }
            val ct = cipher.doFinal(both)
            File(root, "transport").mkdirs()
            File(root, "transport/$id.bin").writeBytes(cipher.iv + ct)
        } finally {
            both.fill(0)
            t.sigSecret.fill(0)
            t.kemSecret.fill(0)
        }
    }

    private fun key(alias: String): SecretKey = keyStore.getKey(alias, null) as SecretKey

    private fun encryptCipher(alias: String): Cipher =
        Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key(alias)) }

    private fun createAuthKey(alias: String) {
        keyStore.deleteEntry(alias)
        generate(alias, auth = true)
    }

    private fun createPlainKey(alias: String) = generate(alias, auth = false)

    private fun generate(alias: String, auth: Boolean) {
        try {
            generate(alias, auth, strongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
        } catch (_: StrongBoxUnavailableException) {
            generate(alias, auth, strongBox = false)
        }
    }

    private fun generate(alias: String, auth: Boolean, strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setIsStrongBoxBacked(strongBox)
            .apply {
                if (!auth) return@apply
                setUserAuthenticationRequired(true)
                // Enrolling a new biometric already needs the device PIN; invalidating would only lock users out.
                setInvalidatedByBiometricEnrollment(false)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    // Timeout 0 = every use needs its own authentication.
                    setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
                } else {
                    @Suppress("DEPRECATION")
                    setUserAuthenticationValidityDurationSeconds(-1)
                }
            }
            .build()
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE).apply { init(spec) }.generateKey()
    }

    /**
     * Adopts the single seed of earlier builds (`seed.bin` under `blox.seed.wrap.v1`) as the
     * signer "Main", so existing installs keep their key.
     */
    private fun migrateSingleSeed() {
        if (prefs.contains(KEY)) return
        val legacy = File(root, "seed.bin")
        val oldAccounts = context.getSharedPreferences("accounts", Context.MODE_PRIVATE)
        val address = oldAccounts.getString("evm", null)?.let { JSONArray(it).optString(0) }
        if (!legacy.exists() || !keyStore.containsAlias(LEGACY_ALIAS) || address.isNullOrEmpty()) {
            save(emptyList())
            return
        }
        val id = "legacy"
        writeTransportKeys(id)
        save(listOf(SignerInfo(id, "Main", address, LEGACY_ALIAS, "seed.bin")))
        oldAccounts.edit().clear().apply()
    }

    private companion object {
        const val KEYSTORE = "AndroidKeyStore"
        const val KEY = "list"
        const val SEED_ALIAS_PREFIX = "blox.seed.wrap.v1."
        const val LEGACY_ALIAS = "blox.seed.wrap.v1"
        const val TRANSPORT_ALIAS = "blox.transport.wrap.v1"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val IV_LEN = 12
    }
}
