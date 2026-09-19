package io.tunnet.android

import io.tunnet.android.wire.ErrorKind
import io.tunnet.android.wire.NativeResult
import io.tunnet.android.wire.Snapshot

fun interface SnapshotListener {
    fun onSnapshot(bytes: ByteArray)
}

/**
 * Binding to `libtunnet_mobile.so`.
 *
 * Commands return protobuf [NativeResult]; branch on [ErrorKind], not [NativeResult.message].
 * Runtime state is pushed through [setSnapshotListener].
 *
 * Command calls BLOCK. Never call them from the main thread.
 */
object TunnetNative {
    init {
        System.loadLibrary("tunnet_mobile")
    }

    sealed interface Result {
        data object Ok : Result
        data class Err(val kind: ErrorKind, val message: String) : Result
    }

    fun start(stateDir: String, deviceName: String, vpnService: Any): Result =
        parse(nativeStart(stateDir, deviceName, vpnService))

    fun stop(): Result = parse(nativeStop())

    /**
     * Drop the TUN provider for a destroyed Service. Does not stop the agent.
     * A later [start] rebinds the new Service.
     */
    fun releaseHost() {
        nativeReleaseHost()
    }

    fun join(inviteCode: String, hostname: String): Result =
        parse(nativeJoin(inviteCode, hostname))

    fun setLanAvailable(available: Boolean) {
        nativeSetLanAvailable(available)
    }

    /**
     * Register the snapshot consumer. The current snapshot is delivered
     * immediately if the agent is running. Pass null to detach.
     *
     * Called from a native worker thread. Detach before the Service is
     * destroyed so callbacks cannot target a dead listener.
     */
    fun setSnapshotListener(listener: SnapshotListener?) {
        nativeSetSnapshotListener(listener)
    }

    fun parseSnapshot(bytes: ByteArray): Snapshot = Snapshot.parseFrom(bytes)

    private fun parse(raw: ByteArray?): Result {
        if (raw == null) {
            return Result.Err(ErrorKind.ERROR_KIND_INTERNAL, "native call returned nothing")
        }
        return try {
            val result = NativeResult.parseFrom(raw)
            if (result.ok) {
                Result.Ok
            } else {
                Result.Err(result.kind, result.message)
            }
        } catch (e: Exception) {
            Result.Err(
                ErrorKind.ERROR_KIND_INTERNAL,
                "could not parse agent response: ${e.message}",
            )
        }
    }

    private external fun nativeStart(stateDir: String, deviceName: String, vpnService: Any): ByteArray?
    private external fun nativeStop(): ByteArray?
    private external fun nativeReleaseHost()
    private external fun nativeJoin(inviteCode: String, hostname: String): ByteArray?
    private external fun nativeSetLanAvailable(available: Boolean)
    private external fun nativeSetSnapshotListener(listener: SnapshotListener?)
}
