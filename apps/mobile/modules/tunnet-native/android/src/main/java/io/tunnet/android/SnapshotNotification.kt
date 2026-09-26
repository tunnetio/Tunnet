package io.tunnet.android

import io.tunnet.android.wire.DataPlane
import io.tunnet.android.wire.Lifecycle
import io.tunnet.android.wire.Snapshot

private fun Snapshot.isJoined(): Boolean = networksCount > 0

private fun Snapshot.dataPlaneUp(): Boolean = dataPlane == DataPlane.DATA_PLANE_UP

fun Snapshot.notificationText(): String = when {
    lifecycle == Lifecycle.LIFECYCLE_FAILED ->
        if (hasError() && error.message.isNotEmpty()) error.message else "Agent failed"
    lifecycle == Lifecycle.LIFECYCLE_PENDING_APPROVAL -> "Waiting for approval…"
    lifecycle == Lifecycle.LIFECYCLE_JOINING -> "Joining…"
    lifecycle == Lifecycle.LIFECYCLE_ACTIVATING -> "Starting…"
    !isJoined() -> "Not joined to a network"
    dataPlaneUp() -> "Connected - ${networksList.joinToString { it.ip }}"
    else -> "Connecting…"
}
