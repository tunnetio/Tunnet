package io.tunnet.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class HostLifecycleTest {
    @Test
    fun connectPersistsWantedAndIsSticky() {
        val d = decide(VpnHostPolicy.ACTION_CONNECT, wanted = false)
        assertEquals(VpnHostPolicy.Command.Attach, d.command)
        assertTrue(d.sticky)
        assertTrue(d.wanted)
    }

    @Test
    fun duplicateConnectStaysAttach() {
        val first = decide(VpnHostPolicy.ACTION_CONNECT, wanted = false)
        val second = decide(VpnHostPolicy.ACTION_CONNECT, wanted = first.wanted)
        assertEquals(VpnHostPolicy.Command.Attach, second.command)
        assertTrue(second.wanted)
        assertTrue(second.sticky)
    }

    @Test
    fun disconnectClearsWantedAndIsNotSticky() {
        val d = decide(VpnHostPolicy.ACTION_DISCONNECT, wanted = true)
        assertEquals(VpnHostPolicy.Command.Stop, d.command)
        assertFalse(d.sticky)
        assertFalse(d.wanted)
    }

    @Test
    fun duplicateDisconnectStaysStop() {
        val first = decide(VpnHostPolicy.ACTION_DISCONNECT, wanted = true)
        val second = decide(VpnHostPolicy.ACTION_DISCONNECT, wanted = first.wanted)
        assertEquals(VpnHostPolicy.Command.Stop, second.command)
        assertFalse(second.wanted)
        assertFalse(second.sticky)
    }

    @Test
    fun explicitDisconnectSurvivesActivityRecreation() {
        val wanted = MemoryFlagStore(true)
        wanted.set(decide(VpnHostPolicy.ACTION_DISCONNECT, wanted = wanted.get()).wanted)
        assertFalse(wanted.get())
        // Opening the Activity does not issue CONNECT.
        assertFalse(wanted.get())
    }

    @Test
    fun stickyNullIntentReconnectsOnlyWhenWanted() {
        val running = VpnHostPolicy.decide(null, null, wanted = true)
        assertEquals(VpnHostPolicy.Command.Attach, running.command)
        assertTrue(running.sticky)
        assertNull(running.invite)

        val stopped = VpnHostPolicy.decide(null, null, wanted = false)
        assertEquals(VpnHostPolicy.Command.Stop, stopped.command)
        assertFalse(stopped.sticky)
        assertFalse(stopped.wanted)
    }

    @Test
    fun joinWhileStoppedCarriesInviteOnConnect() {
        val d = VpnHostPolicy.decide(
            VpnHostPolicy.ACTION_CONNECT,
            "  invite-code  ",
            wanted = false,
        )
        assertEquals(VpnHostPolicy.Command.Attach, d.command)
        assertEquals("invite-code", d.invite)
        assertTrue(d.wanted)
    }

    @Test
    fun joinWhileAlreadyRunningStillAttachesWithInvite() {
        val d = VpnHostPolicy.decide(
            VpnHostPolicy.ACTION_CONNECT,
            "invite-code",
            wanted = true,
        )
        assertEquals(VpnHostPolicy.Command.Attach, d.command)
        assertEquals("invite-code", d.invite)
    }

    @Test
    fun startStopStartRestoresWanted() {
        var wanted = false
        wanted = decide(VpnHostPolicy.ACTION_CONNECT, wanted = wanted).wanted
        assertTrue(wanted)
        wanted = decide(VpnHostPolicy.ACTION_DISCONNECT, wanted = wanted).wanted
        assertFalse(wanted)
        wanted = decide(VpnHostPolicy.ACTION_CONNECT, wanted = wanted).wanted
        assertTrue(wanted)
    }

    @Test
    fun revokeIsTheSameCommandAsDisconnect() {
        val d = decide(VpnHostPolicy.ACTION_DISCONNECT, wanted = true)
        assertEquals(VpnHostPolicy.Command.Stop, d.command)
        assertFalse(d.wanted)
        assertFalse(d.sticky)
    }

    @Test
    fun emptyInviteIsDropped() {
        val d = VpnHostPolicy.decide(VpnHostPolicy.ACTION_CONNECT, "   ", wanted = false)
        assertNull(d.invite)
    }

    private fun decide(action: String, wanted: Boolean) =
        VpnHostPolicy.decide(action, invite = null, wanted = wanted)
}

class DesiredConnectionTest {
    @Test
    fun defaultsToDisconnected() {
        assertFalse(DesiredConnection(MemoryFlagStore()).wanted)
    }

    @Test
    fun remembersExplicitDisconnect() {
        val store = MemoryFlagStore(true)
        val desired = DesiredConnection(store)
        desired.wanted = false
        assertFalse(DesiredConnection(store).wanted)
    }
}
