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
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * The recovery phrase, encrypted at rest (BLOX.md §10.2).
 *
 * The Android Keystore can't hold secp256k1 keys, so the phrase is encrypted with an
 * AES-256-GCM key that lives in StrongBox or the TEE. That key needs a fresh
 * authentication for every use: the Cipher from [decryptCipher] only works after
 * BiometricPrompt has unlocked it, so approving and decrypting are one step.
 */
class SeedVault(context: Context) {
    private val file = File(context.noBackupFilesDir, "seed.bin")
    private val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    fun exists(): Boolean = file.exists() && keyStore.containsAlias(ALIAS)

    /** Creates a new wrapping key, replacing any old one. */
    fun createKey() {
        keyStore.deleteEntry(ALIAS)
        try {
            generate(strongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
        } catch (_: StrongBoxUnavailableException) {
            generate(strongBox = false)
        }
    }

    private fun generate(strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            // Enrolling a new biometric already needs the device PIN; invalidating would only lock users out.
            .setInvalidatedByBiometricEnrollment(false)
            .setIsStrongBoxBacked(strongBox)
            .apply {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    // Timeout 0 = every use needs its own authentication.
                    setUserAuthenticationParameters(
                        0,
                        KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
                    )
                } else {
                    @Suppress("DEPRECATION")
                    setUserAuthenticationValidityDurationSeconds(-1)
                }
            }
            .build()
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE).apply { init(spec) }.generateKey()
    }

    private fun key(): SecretKey = keyStore.getKey(ALIAS, null) as SecretKey

    /** Where the wrapping key actually lives, for display (and a warning if software-only). */
    fun securityLevel(): SecurityLevel {
        val info = SecretKeyFactory.getInstance(key().algorithm, KEYSTORE).getKeySpec(key(), KeyInfo::class.java) as KeyInfo
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> SecurityLevel.STRONGBOX
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> SecurityLevel.TEE
                else -> SecurityLevel.SOFTWARE
            }
        } else {
            @Suppress("DEPRECATION")
            if (info.isInsideSecureHardware) SecurityLevel.TEE else SecurityLevel.SOFTWARE
        }
    }

    /** A Cipher to encrypt a new phrase. Must be unlocked by BiometricPrompt before use. */
    fun encryptCipher(): Cipher = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key()) }

    /**
     * A Cipher to decrypt the phrase. Must be unlocked by BiometricPrompt before use.
     * @throws KeyPermanentlyInvalidatedException if the screen lock was removed: restore from the phrase.
     */
    fun decryptCipher(): Cipher {
        val blob = file.readBytes()
        val iv = blob.copyOfRange(0, IV_LEN)
        return Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, iv)) }
    }

    /** Encrypts and stores `phrase` with an unlocked cipher. The caller wipes `phrase`. */
    fun store(unlocked: Cipher, phrase: ByteArray) {
        val ct = unlocked.doFinal(phrase)
        val tmp = File(file.parentFile, "seed.bin.tmp")
        tmp.writeBytes(unlocked.iv + ct)
        check(tmp.renameTo(file)) { "could not write seed" }
    }

    /** Decrypts the phrase with an unlocked cipher. The caller must wipe the result. */
    fun open(unlocked: Cipher): ByteArray {
        val blob = file.readBytes()
        return unlocked.doFinal(blob, IV_LEN, blob.size - IV_LEN)
    }

    fun wipe() {
        file.delete()
        keyStore.deleteEntry(ALIAS)
    }

    enum class SecurityLevel { STRONGBOX, TEE, SOFTWARE }

    private companion object {
        const val KEYSTORE = "AndroidKeyStore"
        const val ALIAS = "blox.seed.wrap.v1"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val IV_LEN = 12
    }
}
