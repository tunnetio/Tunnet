package io.tunnet.android

import io.tunnet.android.wire.DataPlane
import io.tunnet.android.wire.Lifecycle
import io.tunnet.android.wire.Peer
import io.tunnet.android.wire.Snapshot

fun Snapshot.isJoined(): Boolean = networksCount > 0

fun Snapshot.agentAttached(): Boolean = when (lifecycle) {
    Lifecycle.LIFECYCLE_UNSPECIFIED,
    Lifecycle.LIFECYCLE_STOPPED,
    -> false
    else -> true
}

fun Snapshot.dataPlaneUp(): Boolean = dataPlane == DataPlane.DATA_PLANE_UP

fun Snapshot.headline(vpnConsentDenied: String?): String {
    if (vpnConsentDenied != null) return "Disconnected"
    return when (lifecycle) {
        Lifecycle.LIFECYCLE_JOINING -> "Joining"
        Lifecycle.LIFECYCLE_PENDING_APPROVAL -> "Waiting for approval"
        Lifecycle.LIFECYCLE_ACTIVATING -> "Starting"
        Lifecycle.LIFECYCLE_STOPPING -> "Stopping"
        Lifecycle.LIFECYCLE_FAILED -> "Failed"
        Lifecycle.LIFECYCLE_RUNNING -> when {
            dataPlaneUp() -> "Connected"
            isJoined() -> "Connecting"
            else -> "Not joined"
        }
        Lifecycle.LIFECYCLE_IDLE -> if (isJoined()) "Connecting" else "Not joined"
        else -> "Disconnected"
    }
}

fun Snapshot.busy(): Boolean = when (lifecycle) {
    Lifecycle.LIFECYCLE_JOINING,
    Lifecycle.LIFECYCLE_PENDING_APPROVAL,
    Lifecycle.LIFECYCLE_ACTIVATING,
    Lifecycle.LIFECYCLE_STOPPING,
    -> true
    else -> false
}

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

fun Peer.statusLabel(): String = when {
    hasOnline() && online -> {
        if (hasConnState()) connState.name.removePrefix("PEER_CONN_").lowercase() else "online"
    }
    hasConnState() -> connState.name.removePrefix("PEER_CONN_").lowercase()
    hasOnline() && !online -> "offline"
    else -> "unknown"
}

fun Peer.pathLabel(): String? =
    if (hasPath()) path.name.removePrefix("PEER_PATH_").lowercase() else null
