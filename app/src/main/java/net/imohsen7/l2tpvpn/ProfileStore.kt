package net.imohsen7.l2tpvpn

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import net.imohsen7.l2tpvpn.core.VpnProfile
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Encrypts the profile locally with an AES-256 key held by Android Keystore. */
internal object ProfileStore {
    private const val PREFS = "encrypted_vpn_profile"
    private const val KEY_ALIAS = "custom_l2tp_profile_aes_v1"

    fun save(context: Context, server: String, username: String, password: String, psk: String) {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val values = mapOf("server" to server.trim(), "username" to username, "password" to password, "psk" to psk)
        val editor = prefs.edit().clear()
        values.forEach { (k,v) -> editor.putString(k, encrypt(v)) }
        check(editor.commit()) { "ذخیرهٔ پروفایل ناموفق بود" }
    }

    fun load(context: Context): VpnProfile? {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val encServer = prefs.getString("server", null) ?: return null
        return VpnProfile(
            decrypt(encServer),
            prefs.getString("username", null)?.let(::decrypt) ?: "",
            prefs.getString("password", null)?.let(::decrypt) ?: "",
            prefs.getString("psk", null)?.let(::decrypt) ?: ""
        )
    }

    private fun encrypt(value: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getKey())
        val encrypted = cipher.doFinal(value.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(cipher.iv + encrypted, Base64.NO_WRAP)
    }

    private fun decrypt(value: String): String {
        val all = Base64.decode(value, Base64.NO_WRAP)
        require(all.size >= 12 + 16) { "Encrypted VPN profile is invalid" }
        val iv = all.copyOfRange(0, 12)
        val data = all.copyOfRange(12, all.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, getKey(), GCMParameterSpec(128, iv))
        return String(cipher.doFinal(data), Charsets.UTF_8)
    }

    private fun getKey(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .build())
        return generator.generateKey()
    }
}
