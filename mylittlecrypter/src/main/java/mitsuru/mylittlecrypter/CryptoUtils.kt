package mitsuru.mylittlecrypter

import android.util.Base64
import java.io.UnsupportedEncodingException
import java.math.BigInteger
import java.nio.charset.Charset
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class Cryptograph(private val salt: String) {

    private fun bin2hex(data: ByteArray): String {
        return String.format("%0" + data.size * 2 + "X", BigInteger(1, data))
    }

    @Throws(UnsupportedEncodingException::class, NoSuchAlgorithmException::class)
    private fun getSha256(str: String): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.reset()
        return Arrays.copyOf(bin2hex(digest.digest(str.toByteArray(charset("UTF-8")))).toLowerCase().toByteArray(), 16)
    }

    fun encryptAES(content: String, key: String): String {
        var encryptedBytes = ByteArray(0)
        try {
            val byteContent = content.toByteArray(charset("UTF-8"))
            val enCodeFormat = getSha256(key)
            val secretKeySpec = SecretKeySpec(enCodeFormat, "AES")
            val initParam = salt.toByteArray()
            val ivParameterSpec = IvParameterSpec(initParam)
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec)
            encryptedBytes = cipher.doFinal(byteContent)
        } catch (e: Exception) {
        }
        return String(Base64.encode(encryptedBytes, Base64.DEFAULT))
    }

    fun decryptAES(content: String, key: String?): String {
        if (key != null) {
            try {
                val enCodeFormat = getSha256(key)
                val secretKey = SecretKeySpec(enCodeFormat, "AES")
                val initParam = salt.toByteArray()
                val ivParameterSpec = IvParameterSpec(initParam)
                val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
                cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec)
                val result = cipher.doFinal(Base64.decode(content.toByteArray(), Base64.DEFAULT))
                return String(result, Charset.availableCharsets()["UTF-8"]!!)
            } catch (e: Exception) {
            }

        }
        return content
    }
}