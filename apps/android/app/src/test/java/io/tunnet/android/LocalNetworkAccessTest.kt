package io.tunnet.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LocalNetworkAccessTest {
    @Test
    fun belowApi37LanIsAvailableWithoutARuntimePrompt() {
        val state = LocalNetworkAccess.state(sdkInt = 36, granted = false)
        assertEquals(LocalNetworkAccess.State.NotRequired, state)
        assertTrue(LocalNetworkAccess.isAvailable(state))
        assertFalse(LocalNetworkAccess.shouldRequest(state))
    }

    @Test
    fun api37GrantedIsAvailable() {
        val state = LocalNetworkAccess.state(sdkInt = 37, granted = true)
        assertEquals(LocalNetworkAccess.State.Granted, state)
        assertTrue(LocalNetworkAccess.isAvailable(state))
        assertFalse(LocalNetworkAccess.shouldRequest(state))
    }

    @Test
    fun api37DeniedIsDegradedNotAHardFailure() {
        val state = LocalNetworkAccess.state(sdkInt = 37, granted = false)
        assertEquals(LocalNetworkAccess.State.Denied, state)
        assertFalse(LocalNetworkAccess.isAvailable(state))
        assertTrue(LocalNetworkAccess.shouldRequest(state))
    }

    @Test
    fun deniedThenGrantedBecomesAvailable() {
        var granted = false
        assertFalse(LocalNetworkAccess.isAvailable(LocalNetworkAccess.state(37, granted)))
        granted = true
        assertTrue(LocalNetworkAccess.isAvailable(LocalNetworkAccess.state(37, granted)))
    }
}
