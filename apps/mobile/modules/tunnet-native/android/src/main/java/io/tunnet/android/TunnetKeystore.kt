package io.tunnet.android

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import java.security.InvalidKeyException
import java.security.KeyStore
import java.security.UnrecoverableKeyException
import javax.crypto.AEADBadTagException
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class SealOp(
    val kind: Int,
    val blob: ByteArray = ByteArray(0),
    val message: String = "",
)

internal interface WrappingKeyAccess {
    fun existing(): SecretKey?
    fun getOrCreate(): SecretKey
}

private class AndroidWrappingKeys : WrappingKeyAccess {
    override fun existing(): SecretKey? {
        val store = KeyStore.getInstance(TunnetKeystore.PROVIDER)
        store.load(null)
        return store.getKey(TunnetKeystore.ALIAS, null) as? SecretKey
    }

    override fun getOrCreate(): SecretKey {
        existing()?.let {
            TunnetKeystore.logInfo("wrapping key reused")
            return it
        }
        return TunnetKeystore.generateWrappingKey(strongBoxPreferred = true) { strongBox ->
            val spec = KeyGenParameterSpec.Builder(
                TunnetKeystore.ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .setUserAuthenticationRequired(false)
                .apply {
                    if (strongBox) {
                        if (Build.VERSION.SDK_INT >= 28) {
                            setIsStrongBoxBacked(true)
                        }
                    }
                }
                .build()
            val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, TunnetKeystore.PROVIDER)
            generator.init(spec)
            generator.generateKey()
        }
    }
}

/**
 * One non-exportable AES-256-GCM wrapping key. Rust owns DEKs and identity files.
 */
object TunnetKeystore {
    private const val TAG = "TunnetKeystore"
    const val ALIAS = "io.tunnet.wrap.v1"
    const val PROVIDER = "AndroidKeyStore"
    const val OK = 0
    const val KEY_UNAVAILABLE = 1
    const val KEY_INVALIDATED = 2
    const val CIPHERTEXT_INVALID = 3
    const val DECRYPT_FAILED = 4
    const val OPERATION_FAILED = 5
    const val UNSUPPORTED = 6

    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_BITS = 128
    internal const val GCM_IV_BYTES = 12

    @JvmStatic
    fun wrap(plain: ByteArray): SealOp = wrapWith(AndroidWrappingKeys(), plain)

    @JvmStatic
    fun unwrap(wrapped: ByteArray): SealOp = unwrapWith(AndroidWrappingKeys(), wrapped)

    internal fun wrapWith(access: WrappingKeyAccess, plain: ByteArray): SealOp = operate {
        val key = access.getOrCreate()
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        if (iv.size != GCM_IV_BYTES) {
            return@operate SealOp(OPERATION_FAILED, message = "unexpected GCM IV length")
        }
        SealOp(OK, blob = iv + cipher.doFinal(plain))
    }

    internal fun unwrapWith(access: WrappingKeyAccess, wrapped: ByteArray): SealOp = operate {
        if (wrapped.size < GCM_IV_BYTES + 16) {
            return@operate SealOp(CIPHERTEXT_INVALID, message = "wrapped DEK too short")
        }
        val key = access.existing()
            ?: return@operate SealOp(KEY_UNAVAILABLE, message = "wrapping key missing")
        val iv = wrapped.copyOfRange(0, GCM_IV_BYTES)
        val body = wrapped.copyOfRange(GCM_IV_BYTES, wrapped.size)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        SealOp(OK, blob = cipher.doFinal(body))
    }

    internal fun generateWrappingKey(
        strongBoxPreferred: Boolean,
        sdkInt: Int = Build.VERSION.SDK_INT,
        generate: (strongBox: Boolean) -> SecretKey,
    ): SecretKey {
        if (!strongBoxPreferred || sdkInt < 28) {
            return generate(false)
        }
        return try {
            val key = generate(true)
            logInfo("wrapping key created (StrongBox)")
            key
        } catch (error: Exception) {
            if (error.javaClass.simpleName != "StrongBoxUnavailableException") {
                throw error
            }
            logInfo("StrongBox unavailable; wrapping key created without StrongBox")
            generate(false)
        }
    }

    internal fun kindOf(error: Throwable): Int {
        var current: Throwable? = error
        while (current != null) {
            when (current) {
                is KeyPermanentlyInvalidatedException -> return KEY_INVALIDATED
                is UnrecoverableKeyException -> return KEY_UNAVAILABLE
                is AEADBadTagException, is BadPaddingException -> return DECRYPT_FAILED
                is IllegalBlockSizeException, is IndexOutOfBoundsException -> return CIPHERTEXT_INVALID
                is InvalidKeyException -> return KEY_INVALIDATED
            }
            current = current.cause
        }
        return OPERATION_FAILED
    }

    internal fun logInfo(message: String) {
        runCatching { android.util.Log.i(TAG, message) }
    }

    private fun operate(block: () -> SealOp): SealOp {
        return try {
            block()
        } catch (error: Throwable) {
            SealOp(kindOf(error), message = error::class.java.simpleName)
        }
    }
}
