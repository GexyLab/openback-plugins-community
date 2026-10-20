package io.openback.appauth.android

import android.annotation.SuppressLint
import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.GeneralSecurityException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The default [TokenStorage] on Android: values encrypted with AES-256-GCM under a key generated in the **Android
 * Keystore** (never exportable, hardware-backed where the device has it), stored in a private SharedPreferences file.
 * The key name and the entry's name are the associated data, so a value cannot be moved to another entry.
 *
 * If the key is lost (app data restored on another device, Keystore reset), the entries cannot be decrypted: they are
 * dropped and the user signs in again. Exclude [prefsName] from Auto Backup (see the README).
 * Writes use `commit()` on purpose: a rotated refresh token must be on disk before it is used.
 */
@SuppressLint("ApplySharedPref")
public class KeystoreTokenStorage @JvmOverloads constructor(
    context: Context,
    private val prefsName: String = "openback_app_auth",
    private val keyAlias: String = "io.openback.appauth.v1",
) : TokenStorage {
    private val prefs: SharedPreferences = context.applicationContext.getSharedPreferences(prefsName, Context.MODE_PRIVATE)
    private val lock = Any()

    private fun secretKey(): SecretKey {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (ks.getKey(keyAlias, null) as? SecretKey)?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        gen.init(
            KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        return gen.generateKey()
    }

    private fun aad(entry: String): ByteArray = "$keyAlias|$entry".toByteArray(Charsets.UTF_8)

    override fun get(key: String): String? = synchronized(lock) {
        val stored = prefs.getString(key, null) ?: return null
        try {
            val raw = Base64.decode(stored, Base64.NO_WRAP)
            if (raw.size < IV_BYTES + TAG_BITS / 8) throw GeneralSecurityException("short value")
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, secretKey(), GCMParameterSpec(TAG_BITS, raw, 0, IV_BYTES))
            cipher.updateAAD(aad(key))
            String(cipher.doFinal(raw, IV_BYTES, raw.size - IV_BYTES), Charsets.UTF_8)
        } catch (e: GeneralSecurityException) {
            prefs.edit().remove(key).commit()     // undecryptable (key lost): drop it
            null
        } catch (e: IllegalArgumentException) {
            prefs.edit().remove(key).commit()
            null
        }
    }

    override fun set(key: String, value: String): Unit = synchronized(lock) {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey())              // the Keystore picks a random 12-byte IV
        cipher.updateAAD(aad(key))
        val iv = cipher.iv
        val sealed = cipher.doFinal(value.toByteArray(Charsets.UTF_8))
        val out = ByteArray(iv.size + sealed.size)
        System.arraycopy(iv, 0, out, 0, iv.size)
        System.arraycopy(sealed, 0, out, iv.size, sealed.size)
        if (!prefs.edit().putString(key, Base64.encodeToString(out, Base64.NO_WRAP)).commit()) {
            throw IllegalStateException("Could not write the session")
        }
    }

    override fun remove(key: String): Unit = synchronized(lock) {
        prefs.edit().remove(key).commit()
        Unit
    }

    private companion object {
        const val KEYSTORE = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val IV_BYTES = 12
        const val TAG_BITS = 128
    }
}
