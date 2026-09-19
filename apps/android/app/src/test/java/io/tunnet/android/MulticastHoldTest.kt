package io.tunnet.android

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MulticastHoldTest {
    @Test
    fun discoveryDemandOnWifiWithLanHolds() {
        assertTrue(MulticastHold.shouldHold(demand = true, lanPermitted = true, wifiPresent = true))
    }

    @Test
    fun discoveryStopReleases() {
        assertFalse(MulticastHold.shouldHold(demand = false, lanPermitted = true, wifiPresent = true))
    }

    @Test
    fun lanAvailableButNoDemandDoesNotHold() {
        assertFalse(MulticastHold.shouldHold(demand = false, lanPermitted = true, wifiPresent = true))
    }

    @Test
    fun permissionUnavailableDoesNotHold() {
        assertFalse(MulticastHold.shouldHold(demand = true, lanPermitted = false, wifiPresent = true))
    }

    @Test
    fun permissionRevokedWhileActiveReleases() {
        assertTrue(MulticastHold.shouldHold(demand = true, lanPermitted = true, wifiPresent = true))
        assertFalse(MulticastHold.shouldHold(demand = true, lanPermitted = false, wifiPresent = true))
    }

    @Test
    fun cellularOnlyDoesNotHold() {
        assertFalse(MulticastHold.shouldHold(demand = true, lanPermitted = true, wifiPresent = false))
    }

    @Test
    fun noNetworkDoesNotHold() {
        assertFalse(MulticastHold.shouldHold(demand = true, lanPermitted = true, wifiPresent = false))
    }

    @Test
    fun wifiLostWhileDemandedReleases() {
        assertTrue(MulticastHold.shouldHold(demand = true, lanPermitted = true, wifiPresent = true))
        assertFalse(MulticastHold.shouldHold(demand = true, lanPermitted = true, wifiPresent = false))
    }

    @Test
    fun cellularThenWifiCanHoldAgain() {
        assertFalse(MulticastHold.shouldHold(demand = true, lanPermitted = true, wifiPresent = false))
        assertTrue(MulticastHold.shouldHold(demand = true, lanPermitted = true, wifiPresent = true))
    }
}
