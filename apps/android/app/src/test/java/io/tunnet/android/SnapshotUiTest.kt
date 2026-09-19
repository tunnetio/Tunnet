package io.tunnet.android

import io.tunnet.android.wire.DataPlane
import io.tunnet.android.wire.Lifecycle
import io.tunnet.android.wire.Peer
import io.tunnet.android.wire.PeerConn
import io.tunnet.android.wire.PeerPath
import io.tunnet.android.wire.Snapshot
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SnapshotUiTest {
    @Test
    fun idleSnapshotIsNotJoined() {
        val snap = Snapshot.newBuilder()
            .setLifecycle(Lifecycle.LIFECYCLE_IDLE)
            .setHostname("phone")
            .build()
        assertFalse(snap.isJoined())
        assertEquals("Not joined", snap.headline(null))
        assertEquals("Not joined to a network", snap.notificationText())
    }

    @Test
    fun pendingApprovalIsBusy() {
        val snap = Snapshot.newBuilder()
            .setLifecycle(Lifecycle.LIFECYCLE_PENDING_APPROVAL)
            .build()
        assertTrue(snap.busy())
        assertEquals("Waiting for approval", snap.headline(null))
        assertEquals("Waiting for approval…", snap.notificationText())
    }

    @Test
    fun joiningIsBusyAndHeadlineJoining() {
        val snap = Snapshot.newBuilder()
            .setLifecycle(Lifecycle.LIFECYCLE_JOINING)
            .build()
        assertTrue(snap.busy())
        assertEquals("Joining", snap.headline(null))
    }

    @Test
    fun runningWithDataplaneIsConnected() {
        val snap = Snapshot.newBuilder()
            .setLifecycle(Lifecycle.LIFECYCLE_RUNNING)
            .setDataPlane(DataPlane.DATA_PLANE_UP)
            .addNetworks(
                io.tunnet.android.wire.Network.newBuilder()
                    .setNetworkId("n")
                    .setNetworkName("lab")
                    .setIp("10.9.0.2"),
            )
            .build()
        assertTrue(snap.isJoined())
        assertTrue(snap.dataPlaneUp())
        assertEquals("Connected", snap.headline(null))
        assertEquals("Connected - 10.9.0.2", snap.notificationText())
    }

    @Test
    fun vpnConsentDeniedIsHostStateNotLifecycle() {
        val snap = Snapshot.newBuilder()
            .setLifecycle(Lifecycle.LIFECYCLE_IDLE)
            .build()
        assertEquals("Disconnected", snap.headline("VPN permission is required to connect"))
    }

    @Test
    fun failedIdleAgentIsAttachedSoHostCanDisconnect() {
        val idle = Snapshot.newBuilder()
            .setLifecycle(Lifecycle.LIFECYCLE_IDLE)
            .setHostname("phone")
            .build()
        assertTrue(idle.agentAttached())
        val failed = Snapshot.newBuilder()
            .setLifecycle(Lifecycle.LIFECYCLE_FAILED)
            .build()
        assertTrue(failed.agentAttached())
        val stopped = Snapshot.newBuilder()
            .setLifecycle(Lifecycle.LIFECYCLE_STOPPED)
            .build()
        assertFalse(stopped.agentAttached())
    }

    @Test
    fun failedNotificationUsesDiagnosticMessage() {
        val snap = Snapshot.newBuilder()
            .setLifecycle(Lifecycle.LIFECYCLE_FAILED)
            .setError(
                io.tunnet.android.wire.SnapshotError.newBuilder()
                    .setMessage("mesh supervisor stopped"),
            )
            .build()
        assertEquals("Failed", snap.headline(null))
        assertEquals("mesh supervisor stopped", snap.notificationText())
    }

    @Test
    fun peerStatusPrefersPresenceThenConn() {
        val online = Peer.newBuilder()
            .setHostname("peer")
            .setIp("10.9.0.3")
            .setOnline(true)
            .setConnState(PeerConn.PEER_CONN_CONNECTED)
            .setPath(PeerPath.PEER_PATH_DIRECT)
            .build()
        assertEquals("connected", online.statusLabel())
        assertEquals("direct", online.pathLabel())
    }

    @Test
    fun unknownLifecycleIsNotMappedOntoAnExistingState() {
        val snap = Snapshot.newBuilder()
            .setLifecycleValue(99)
            .build()
        assertEquals(Lifecycle.UNRECOGNIZED, snap.lifecycle)
        assertEquals("Disconnected", snap.headline(null))
        assertFalse(snap.busy())
    }
}
