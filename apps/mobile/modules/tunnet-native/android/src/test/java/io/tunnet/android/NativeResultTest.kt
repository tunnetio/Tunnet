package io.tunnet.android

import io.tunnet.android.wire.ErrorKind
import io.tunnet.android.wire.NativeResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeResultTest {
    @Test
    fun successDoesNotCarryAnErrorKind() {
        val bytes = NativeResult.newBuilder().setOk(true).build().toByteArray()
        val parsed = NativeResult.parseFrom(bytes)
        assertTrue(parsed.ok)
        assertEquals(ErrorKind.ERROR_KIND_UNSPECIFIED, parsed.kind)
    }

    @Test
    fun failureBranchesOnKindNotMessage() {
        val bytes = NativeResult.newBuilder()
            .setOk(false)
            .setKind(ErrorKind.ERROR_KIND_INVALID_REQUEST)
            .setMessage("invite code is empty")
            .build()
            .toByteArray()
        val parsed = NativeResult.parseFrom(bytes)
        assertFalse(parsed.ok)
        assertEquals(ErrorKind.ERROR_KIND_INVALID_REQUEST, parsed.kind)
    }

    @Test
    fun unknownKindIsPreservedAsUnrecognized() {
        val bytes = NativeResult.newBuilder()
            .setOk(false)
            .setKindValue(99)
            .setMessage("display only")
            .build()
            .toByteArray()
        val parsed = NativeResult.parseFrom(bytes)
        assertEquals(ErrorKind.UNRECOGNIZED, parsed.kind)
        assertEquals(99, parsed.kindValue)
    }
}
