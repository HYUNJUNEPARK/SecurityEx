package com.example.securityex.util

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * ESP : EncryptedSharedPreference
 */
class ESPManager {
    companion object {
        const val PREFERENCE_NAME = "encrypted_pref"
        private var instance: ESPManager? = null
        private lateinit var context: Context
        private lateinit var prefs: SharedPreferences
        private lateinit var prefsEditor: SharedPreferences.Editor

        fun getInstance(_context: Context): ESPManager? {
            if (instance == null) {
                context = _context
                instance = ESPManager()
            }
            return instance
        }
    }

    init {
        prefs = EncryptedSharedPreferences.create(
            context,
            PREFERENCE_NAME,
            generateMasterKey(), //java.io.FileNotFoundException: can't read keyset; the pref value __androidx_security_crypto_encrypted_prefs_value_keyset__ does not exist
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV, //The scheme to use for encrypting keys.
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM //The scheme to use for encrypting values.
        )
        prefsEditor = prefs.edit()
    }

    private fun generateMasterKey(): MasterKey {
        return MasterKey
            .Builder(context, MasterKey.DEFAULT_MASTER_KEY_ALIAS)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
    }

    fun getString(key: String, defValue: String?): String {
        return prefs.getString(key, defValue)!!
    }

    fun putString(key: String, value: String?) {
        prefsEditor.apply {
            putString(key, value)
            apply()
        }
    }

    fun getInt(key: String, defValue: Int): Int {
        return prefs.getInt(key, defValue)
    }

    fun putInt(key: String, value: Int?) {
        prefsEditor.apply {
            putInt(key, value!!)
            apply()
        }
    }

    fun getBoolean(key: String, defValue: Boolean): Boolean {
        return prefs.getBoolean(key, defValue)
    }

    fun putBoolean(key: String, value: Boolean) {
        prefsEditor.apply {
            putBoolean(key, value)
            apply()
        }
    }

    fun remove(key: String) {
        prefsEditor.apply {
            remove(key)
            apply()
        }
    }

    fun removeAll() {
        prefsEditor.apply {
            clear()
            apply()
        }
    }

    fun getKeyIdList(): List<String> {
        val keys:Map<String, *> = prefs.all
        val keyList:MutableList<String> = mutableListOf()
        for ((key, value) in keys.entries) {
            keyList.add(key)
        }
        return keyList
    }
}