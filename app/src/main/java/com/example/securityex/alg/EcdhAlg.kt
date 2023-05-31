package com.example.securityex.alg

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.system.Os.remove
import android.util.Base64
import android.util.Log
import androidx.annotation.RequiresApi
import com.example.securityex.consts.AppConst.KEY_PROVIDER
import com.example.securityex.consts.AppConst.KEY_STORE_ALIAS
import com.example.securityex.consts.AppConst.TAG
import com.example.securityex.util.DataTypeConverter
import com.example.securityex.util.ESPManager
import java.io.FileNotFoundException
import java.math.BigInteger
import java.security.*
import java.security.interfaces.ECPublicKey
import java.security.spec.*
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class EcdhAlg {
    companion object {
        private var instance: EcdhAlg? = null
        private lateinit var espm: ESPManager
        private lateinit var context: Context

        fun getInstance(context: Context): EcdhAlg? {
            if (instance == null) {
                espm = ESPManager.getInstance(context)!!
                Companion.context = context
                instance = EcdhAlg()
            }
            return instance
        }
    }

    private val androidKeyStore = KeyStore.getInstance(KEY_PROVIDER).apply { load(null) }
    private val iv: ByteArray = ByteArray(16) //CBC(Cipher Block Chaining)Mode 에서 첫번째 암호문 대신 사용되는 IV(Initial Vector)로 0으로 초기화

    /**
     * ECKeyPair 가 keystore 에 있는지 확인한다.
     * @return ECKeyPair 가 있다면 true, 없거나 예외 상황 false
     */
    private fun isECKeyPairOnKeyStore(): Boolean {
        return try {
            val keyStoreEntry: KeyStore.Entry? = androidKeyStore.getEntry(KEY_STORE_ALIAS, null)
            keyStoreEntry != null
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }

    /**
     * ECKeyPair(privateKey/publicKey)를 생성하고 keystore 에 보관한다.
     * API 31 이상
     */
    @RequiresApi(Build.VERSION_CODES.S)
    fun generateECKeyPair() {
        try {
            if (isECKeyPairOnKeyStore()) return //이미 ECKeyPair 가 저장되어 있음

            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                KEY_PROVIDER
            )
            val parameterSpec = KeyGenParameterSpec.Builder(
                KEY_STORE_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_AGREE_KEY
            ).run {
                setUserAuthenticationRequired(false)
                ECGenParameterSpec("secp256r1")
                build()
            }
            keyPairGenerator.initialize(parameterSpec)
            keyPairGenerator.generateKeyPair()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    //keystore 에서 publicKey 를 가져온다.
    @RequiresApi(Build.VERSION_CODES.S)
    fun getECPublicKey(): String? {
        try {
            if (!isECKeyPairOnKeyStore()) generateECKeyPair() //키가 저장되어 있지 않다면 생성 후 가져온다.

            /**
             * 첫번째 인덱스의 숫자가 0인 경우, 맨 앞 인덱스에 0 이 추가되어 byte[33]이 나오게 됨
             * 이런 경우 불필요한 인덱스를 잘라내 byte[32] 를 맞춰주는 작업이 필요하다.
             */
            val publicKey = androidKeyStore.getCertificate(KEY_STORE_ALIAS).publicKey as ECPublicKey
            val trimKeyLength: (ByteArray) -> ByteArray = { affineXY ->
                if (affineXY[0] == 0.toByte()) {
                    affineXY.copyOfRange(1, 33)
                } else {
                    affineXY.copyOfRange(0, 32)
                }
            }
            val affineX = trimKeyLength(publicKey.w.affineX.toByteArray())
            val affineY = trimKeyLength(publicKey.w.affineY.toByteArray())

            //PublicKey Uncompressed Form (byte[65] = [0x04(1byte)][affineX(32byte)][affineY(32byte)])
            val ecPublicKey: ByteArray = byteArrayOf(0x04) + affineX + affineY
            return Base64.encodeToString(ecPublicKey, Base64.NO_WRAP) //ByteArray -> String
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

    /**
     * SharedSecretKey 을 생성하고 ESP 저장. 그리고 키식별자(keyId)를 반환한다.
     * @param publicKey 상대방의 publicKey
     * @param secureRandom 키식별자와 MessageDigest 에서 사용되는 난수
     * @return 키식별자(keyId)
     */
    fun generateSharedSecretKey(publicKey: String, secureRandom: String): String? {
        try {
            val keyId: String = secureRandom
            val random: ByteArray = Base64.decode(secureRandom, Base64.NO_WRAP)


            val _friendPublicKey: ByteArray = Base64.decode(publicKey, Base64.NO_WRAP)//byteArray -> publicKey
            val friendPublicKey: PublicKey = byteArrayToPublicKey(_friendPublicKey)!!

            val myPrivateKey: PrivateKey
            androidKeyStore.getEntry(KEY_STORE_ALIAS, null).let { keyStoreEntry ->
                myPrivateKey = (keyStoreEntry as KeyStore.PrivateKeyEntry).privateKey
            }

            //sharedSecretKey
            val sharedSecretKeyBytes = KeyAgreement.getInstance("ECDH").apply {
                init(myPrivateKey)
                doPhase(friendPublicKey, true)
            }.generateSecret()

            //hash(SHA256)
            val hash = MessageDigest.getInstance(KeyProperties.DIGEST_SHA256).apply {
                update(sharedSecretKeyBytes)
            }.digest(random)

            //keySpec
            val secretKeySpec = SecretKeySpec(
                hash,
                KeyProperties.KEY_ALGORITHM_AES
            )

            //sharedSecretKey(String)
            val sharedSecretKeyString = Base64.encodeToString(
                /*encodingKeySpec*/ secretKeySpec.encoded,
                /*padding*/ Base64.NO_WRAP
            )

            //ESP 에 sharedSecretKey 저장
            espm.putString(keyId, sharedSecretKeyString)

            return keyId
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

//    /**
//     * keystore 와 ESP 를 초기화한다.
//     */
//    fun reset() {
//        try {
//            androidKeyStore.deleteEntry(KEY_STORE_ALIAS)
//            espm.removeAll()
//        } catch (e: Exception) {
//            e.printStackTrace()
//        }
//    }

//    /**
//     * 난수를 생성한다.
//     * @param size 난수 길이
//     */
//    fun generateRandom(size: Int): String? {
//        try {
//            return Base64.encodeToString(
//                /*secureRandomBytes*/
//                ByteArray(size).apply {
//                    SecureRandom().nextBytes(this)
//                },
//                /*padding*/
//                Base64.NO_WRAP
//            )
//        } catch (e: Exception) {
//            e.printStackTrace()
//            return null
//        }
//    }

//    /**
//     * @param keyId ESP 에 저장된 sharedSecretKey 의 식별자
//     * @return 삭제 성공 여부. 지워졌다면 true, 아니라면 false
//     */
//    fun deleteSharedSecretKey(keyId: String): Boolean {
//        espm.apply {
//            try {
//                remove(keyId)
//            } catch (e: Exception) {
//                return false
//            }
//            //정상적으로 지워졌는지 확인 후 Boolean 반환한다.
//            getString(keyId, "").let { result ->
//                return result.isEmpty()
//            }
//        }
//    }

//    /**
//     * 메시지를 암호화한다.
//     * @param message 암호화 시킬 메시지
//     * @param keyId
//     * @return 암호화된 메시지
//     */
//    fun encrypt(message: String, keyId: String): String? {
//        try {
//            //SharedSecretKey
//            val encodingSharedSecretKey: String? = espm.getString(keyId, "").ifEmpty {
//                return null
//            }
//            val decodingSharedSecretKey = Base64.decode(encodingSharedSecretKey, Base64.NO_WRAP)
//
//            //KeySpec
//            val secretKeySpec = SecretKeySpec(
//                decodingSharedSecretKey,
//                0,
//                decodingSharedSecretKey.size,
//                KeyProperties.KEY_ALGORITHM_AES
//            )
//
//            //Cipher
//            val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
//            cipher.init(
//                Cipher.ENCRYPT_MODE,
//                secretKeySpec,
//                IvParameterSpec(iv)
//            )
//
//            //encryptedMessage(ByteArray) -> encodingEncryptedMessage(String, Base64 encoding)
//            return Base64.encodeToString(
//                /*encryptedMessage(ByteArray)*/ cipher.doFinal(message.toByteArray()),
//                /*padding*/ Base64.NO_WRAP
//            )
//        } catch (e: Exception) {
//            e.printStackTrace()
//            return null
//        }
//    }

//    /**
//     * 메시지를 복호화한다.
//     * @param encryptedMessage 암호화 시킬 메시지
//     * @param keyId sharedSecretKey 식별자
//     * @return 복호화된 메시지
//     */
//    fun decrypt(encryptedMessage: String, keyId: String): String? {
//        try {
//            //SharedSecretKey
//            val encodingSharedSecretKey: String? = espm.getString(keyId, "").ifEmpty {
//                return null
//            }
//            val decodingSharedSecretKey = Base64.decode(encodingSharedSecretKey, Base64.NO_WRAP)
//
//            //SecretKeySpec
//            val secretKeySpec = SecretKeySpec(
//                decodingSharedSecretKey,
//                0,
//                decodingSharedSecretKey.size,
//                KeyProperties.KEY_ALGORITHM_AES
//            )
//
//            //cipher
//            val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
//            cipher.init(
//                Cipher.DECRYPT_MODE,
//                secretKeySpec,
//                IvParameterSpec(iv)
//            )
//
//            //encodingEncryptedMessage(String) -> decodingEncryptedMessage(ByteArray)
//            val decodingEncryptedMessage = Base64.decode(
//                /*encodingEncryptedMessage(String)*/ encryptedMessage,
//                /*padding*/ Base64.NO_WRAP
//            )
//
//            //decodingEncryptedMessage(ByteArray) -> decryptedMessage(ByteArray)
//            val decryptedMessage = cipher.doFinal(decodingEncryptedMessage)
//
//            //ByteArray -> String
//            return String(decryptedMessage)
//        } catch (e: Exception) {
//            e.printStackTrace()
//            return null
//        }
//    }



    /**
     * ByteArray 타입 Uncompressed form 으로 publicKey 생성
     * ByteArray affineX, affineY 로 ECPoint 를 생성해 PublicKey 로 복원한다.
     * @param keyByteArray PublicKey ByteArray(Uncompressed Form)
     * @return ECPublicKey
     */
    private fun byteArrayToPublicKey(keyByteArray: ByteArray): PublicKey? {
        try {
            //ByteArray -> String
            val _affineX = DataTypeConverter.byteArrayToString(keyByteArray, 1, 32)
            val _affineY = DataTypeConverter.byteArrayToString(keyByteArray, 33, 32)

            //String -> BigInteger
            val affineX = BigInteger(_affineX, 16)
            val affineY = BigInteger(_affineY, 16)

            //AlgorithmParameters
            val algorithmParameters =
                AlgorithmParameters.getInstance(KeyProperties.KEY_ALGORITHM_EC)
            algorithmParameters.init(ECGenParameterSpec("secp256r1"))

            //ECParameterSpec
            val parameterSpec = algorithmParameters.getParameterSpec(ECParameterSpec::class.java)

            //KeySpec
            val publicKeySpec = ECPublicKeySpec(
                /*ECPoint*/
                ECPoint(affineX, affineY),
                /*ECParameterSpec*/
                parameterSpec
            )

            //publicKey -> ECPublicKey
            return KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC).generatePublic(publicKeySpec) as ECPublicKey
        } catch (e: Exception) {
            e.printStackTrace()
            return null
        }
    }
}