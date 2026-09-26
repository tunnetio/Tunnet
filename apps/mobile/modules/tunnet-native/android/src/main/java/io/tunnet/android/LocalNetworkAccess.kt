package io.tunnet.android

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.content.ContextCompat

/**
 * Android 17 local-network permission as a host fact, not mesh policy.
 *
 * Below API 37 the platform does not gate LAN. On API 37+, denial means
 * discovery over LAN/mDNS is unavailable; relay/DHT still work.
 */
object LocalNetworkAccess {
    const val PERMISSION = "android.permission.ACCESS_LOCAL_NETWORK"
    const val RUNTIME_SDK = 37

    enum class State {
        NotRequired,
        Granted,
        Denied,
    }

    fun requiresRuntimePermission(sdkInt: Int): Boolean = sdkInt >= RUNTIME_SDK

    fun state(sdkInt: Int, granted: Boolean): State = when {
        !requiresRuntimePermission(sdkInt) -> State.NotRequired
        granted -> State.Granted
        else -> State.Denied
    }

    fun isAvailable(state: State): Boolean = state != State.Denied

    fun shouldRequest(state: State): Boolean = state == State.Denied

    fun state(context: Context): State = state(
        sdkInt = Build.VERSION.SDK_INT,
        granted = ContextCompat.checkSelfPermission(context, PERMISSION) ==
            PackageManager.PERMISSION_GRANTED,
    )

    fun isAvailable(context: Context): Boolean = isAvailable(state(context))

    fun shouldRequest(context: Context): Boolean = shouldRequest(state(context))
}
