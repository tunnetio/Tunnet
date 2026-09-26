package io.tunnet.android

import io.tunnet.android.wire.DataPlane
import io.tunnet.android.wire.Lifecycle
import io.tunnet.android.wire.Network
import io.tunnet.android.wire.Snapshot
import io.tunnet.android.wire.SnapshotError
import org.junit.Assert.assertEquals
import org.junit.Test

class SnapshotNotificationTest {
    @Test
    fun idleSnapshotReportsNoNetwork() {
        val snapshot = Snapshot.newBuilder()
            .setLifecycle(Lifecycle.LIFECYCLE_IDLE)
            .setHostname("phone")
            .build()

        assertEquals("Not joined to a network", snapshot.notificationText())
    }

    @Test
    fun runningSnapshotReportsConnectedNetwork() {
        val snapshot = Snapshot.newBuilder()
            .setLifecycle(Lifecycle.LIFECYCLE_RUNNING)
            .setDataPlane(DataPlane.DATA_PLANE_UP)
            .addNetworks(
                Network.newBuilder()
                    .setNetworkId("network")
                    .setNetworkName("lab")
                    .setIp("10.9.0.2"),
            )
            .build()

        assertEquals("Connected - 10.9.0.2", snapshot.notificationText())
    }

    @Test
    fun failedSnapshotUsesNativeDiagnostic() {
        val snapshot = Snapshot.newBuilder()
            .setLifecycle(Lifecycle.LIFECYCLE_FAILED)
            .setError(SnapshotError.newBuilder().setMessage("mesh supervisor stopped"))
            .build()

        assertEquals("mesh supervisor stopped", snapshot.notificationText())
    }
}
