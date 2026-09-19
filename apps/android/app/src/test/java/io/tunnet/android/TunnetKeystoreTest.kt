package io.tunnet.android

import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.StrongBoxUnavailableException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.UnrecoverableKeyException
import javax.crypto.AEADBadTagException
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class TunnetKeystoreTest {
    @Test
    fun aliasIsStableAndVersioned() {
        assertEquals("io.tunnet.wrap.v1", TunnetKeystore.ALIAS)
    }

    @Test
    fun createThenReuseSameSoftwareKey() {
        val access = SoftwareKeys()
        val first = access.getOrCreate()
        val second = access.getOrCreate()
        assertEquals(first, second)
        val wrapped = TunnetKeystore.wrapWith(access, byteArrayOf(1, 2, 3, 4)).also { assertOk(it) }
        val opened = TunnetKeystore.unwrapWith(access, wrapped.blob).also { assertOk(it) }
        assertArrayEquals(byteArrayOf(1, 2, 3, 4), opened.blob)
    }

    @Test
    fun malformedCiphertextIsInvalidNotACrash() {
        val access = SoftwareKeys()
        access.getOrCreate()
        val result = TunnetKeystore.unwrapWith(access, byteArrayOf(1, 2, 3))
        assertEquals(TunnetKeystore.CIPHERTEXT_INVALID, result.kind)
        assertTrue(result.blob.isEmpty())
    }

    @Test
    fun missingKeyDoesNotCreateOnUnwrap() {
        val access = SoftwareKeys()
        val wrapped = ByteArray(TunnetKeystore.GCM_IV_BYTES + 16)
        val result = TunnetKeystore.unwrapWith(access, wrapped)
        assertEquals(TunnetKeystore.KEY_UNAVAILABLE, result.kind)
        assertEquals(null, access.existing())
    }

    @Test
    fun deletedKeyUnwrapsAsUnavailable() {
        val access = SoftwareKeys()
        val wrapped = TunnetKeystore.wrapWith(access, ByteArray(32)).also { assertOk(it) }
        access.delete()
        val result = TunnetKeystore.unwrapWith(access, wrapped.blob)
        assertEquals(TunnetKeystore.KEY_UNAVAILABLE, result.kind)
    }

    @Test
    fun wrongKeyFailsAuthentication() {
        val a = SoftwareKeys()
        val wrapped = TunnetKeystore.wrapWith(a, ByteArray(32) { 7 }).also { assertOk(it) }
        val b = SoftwareKeys()
        b.getOrCreate()
        val result = TunnetKeystore.unwrapWith(b, wrapped.blob)
        assertEquals(TunnetKeystore.DECRYPT_FAILED, result.kind)
        assertNotEquals(TunnetKeystore.OK, result.kind)
    }

    @Test
    fun strongBoxUnavailableFallsBackToTeeGenerate() {
        var tee = false
        val key = TunnetKeystore.generateWrappingKey(
            strongBoxPreferred = true,
            sdkInt = 28,
        ) { strongBox ->
            if (strongBox) {
                throw StrongBoxUnavailableException()
            }
            tee = true
            softwareAesKey()
        }
        assertTrue(tee)
        assertEquals("AES", key.algorithm)
    }

    @Test
    fun mapsInvalidationAndMissingKey() {
        assertEquals(
            TunnetKeystore.KEY_INVALIDATED,
            TunnetKeystore.kindOf(KeyPermanentlyInvalidatedException()),
        )
        assertEquals(
            TunnetKeystore.KEY_UNAVAILABLE,
            TunnetKeystore.kindOf(UnrecoverableKeyException()),
        )
        assertEquals(
            TunnetKeystore.DECRYPT_FAILED,
            TunnetKeystore.kindOf(AEADBadTagException()),
        )
    }

    private fun assertOk(op: SealOp) {
        assertEquals(op.message, TunnetKeystore.OK, op.kind)
    }

    private class SoftwareKeys : WrappingKeyAccess {
        private var key: SecretKey? = null

        override fun existing(): SecretKey? = key

        override fun getOrCreate(): SecretKey {
            val existing = key
            if (existing != null) {
                return existing
            }
            val created = softwareAesKey()
            key = created
            return created
        }

        fun delete() {
            key = null
        }
    }
}

private fun softwareAesKey(): SecretKey {
    val generator = KeyGenerator.getInstance("AES")
    generator.init(256)
    return generator.generateKey()
}
