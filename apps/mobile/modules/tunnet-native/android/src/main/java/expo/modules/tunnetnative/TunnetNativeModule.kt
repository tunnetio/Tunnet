package expo.modules.tunnetnative

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import androidx.core.content.ContextCompat
import expo.modules.kotlin.Promise
import expo.modules.kotlin.activityresult.AppContextActivityResultContract
import expo.modules.kotlin.activityresult.AppContextActivityResultLauncher
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import io.tunnet.android.LocalNetworkAccess
import io.tunnet.android.TunnetVpnService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

class TunnetNativeModule : Module() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var snapshotJob: Job? = null

    private lateinit var vpnConsentLauncher: AppContextActivityResultLauncher<String, Boolean>
    private lateinit var localNetworkLauncher: AppContextActivityResultLauncher<String, Boolean>
    private lateinit var notificationLauncher: AppContextActivityResultLauncher<String, Boolean>

    override fun definition() = ModuleDefinition {
        Name("TunnetNative")

        Events("onRuntimeSnapshot")

        RegisterActivityContracts {
            vpnConsentLauncher = registerForActivityResult(VpnConsentContract)
            localNetworkLauncher = registerForActivityResult(RequestPermissionContract())
            notificationLauncher = registerForActivityResult(RequestPermissionContract())
        }

        OnStartObserving("onRuntimeSnapshot") {
            snapshotJob?.cancel()
            snapshotJob = scope.launch {
                TunnetVpnService.snapshotBytes.collect { bytes ->
                    if (bytes != null) {
                        sendEvent("onRuntimeSnapshot", mapOf("snapshot" to bytes))
                    }
                }
            }
        }

        OnStopObserving("onRuntimeSnapshot") {
            snapshotJob?.cancel()
            snapshotJob = null
        }

        OnActivityEntersForeground {
            TunnetVpnService.pushLanAvailability()
        }

        AsyncFunction("start") { invite: String? ->
            val context = requireReactContext()
            check(VpnService.prepare(context) == null) {
                "VPN permission must be granted before starting Tunnet"
            }
            val intent = Intent(context, TunnetVpnService::class.java)
                .setAction(TunnetVpnService.ACTION_CONNECT)
            if (!invite.isNullOrBlank()) {
                intent.putExtra(TunnetVpnService.EXTRA_INVITE, invite.trim())
            }
            ContextCompat.startForegroundService(context, intent)
        }

        AsyncFunction("stop") {
            val context = requireReactContext()
            context.startService(
                Intent(context, TunnetVpnService::class.java)
                    .setAction(TunnetVpnService.ACTION_DISCONNECT),
            )
        }

        AsyncFunction("joinNetwork") { inviteCode: String ->
            check(inviteCode.isNotBlank()) { "inviteCode must not be blank" }
            check(TunnetVpnService.requestJoin(inviteCode.trim())) {
                "Tunnet runtime is not ready"
            }
        }

        AsyncFunction("getPlatformState") {
            val context = requireReactContext()
            mapOf(
                "supported" to true,
                "vpnPermissionGranted" to (VpnService.prepare(context) == null),
                "localNetworkAccess" to when (LocalNetworkAccess.state(context)) {
                    LocalNetworkAccess.State.NotRequired -> "not_required"
                    LocalNetworkAccess.State.Granted -> "granted"
                    LocalNetworkAccess.State.Denied -> "denied"
                },
                "notificationPermissionGranted" to notificationPermissionGranted(context),
                "serviceRunning" to TunnetVpnService.isRunning(),
            )
        }

        AsyncFunction("requestVpnPermission") { promise: Promise ->
            if (VpnService.prepare(requireReactContext()) == null) {
                promise.resolve(true)
                return@AsyncFunction
            }
            appContext.mainQueue.launch {
                runCatching { vpnConsentLauncher.launch(VPN_CONSENT_INPUT) }
                    .onSuccess { promise.resolve(it) }
                    .onFailure { promise.reject("ERR_VPN_PERMISSION", it.message, it) }
            }
        }

        AsyncFunction("requestLocalNetworkPermission") { promise: Promise ->
            val context = requireReactContext()
            if (!LocalNetworkAccess.requiresRuntimePermission(Build.VERSION.SDK_INT)) {
                promise.resolve(true)
                return@AsyncFunction
            }
            if (LocalNetworkAccess.isAvailable(context)) {
                promise.resolve(true)
                return@AsyncFunction
            }
            appContext.mainQueue.launch {
                runCatching { localNetworkLauncher.launch(LocalNetworkAccess.PERMISSION) }
                    .onSuccess {
                        TunnetVpnService.pushLanAvailability()
                        promise.resolve(it)
                    }
                    .onFailure {
                        promise.reject("ERR_LOCAL_NETWORK_PERMISSION", it.message, it)
                    }
            }
        }

        AsyncFunction("requestNotificationPermission") { promise: Promise ->
            val context = requireReactContext()
            if (notificationPermissionGranted(context)) {
                promise.resolve(true)
                return@AsyncFunction
            }
            appContext.mainQueue.launch {
                runCatching { notificationLauncher.launch(POST_NOTIFICATIONS_PERMISSION) }
                    .onSuccess { promise.resolve(it) }
                    .onFailure {
                        promise.reject("ERR_NOTIFICATION_PERMISSION", it.message, it)
                    }
            }
        }

        OnDestroy {
            snapshotJob?.cancel()
            scope.cancel()
        }
    }

    private fun requireReactContext(): Context =
        appContext.reactContext ?: error("React context is unavailable")

    private fun notificationPermissionGranted(context: Context): Boolean =
        Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
            ContextCompat.checkSelfPermission(
                context,
                POST_NOTIFICATIONS_PERMISSION,
            ) == PackageManager.PERMISSION_GRANTED

    private object VpnConsentContract : AppContextActivityResultContract<String, Boolean> {
        override fun createIntent(context: Context, input: String): Intent =
            checkNotNull(VpnService.prepare(context)) { "VPN permission is already granted" }

        override fun parseResult(input: String, resultCode: Int, intent: Intent?): Boolean =
            resultCode == Activity.RESULT_OK
    }

    // Expo's activity-result registry recognizes AndroidX's permission intent contract by these keys.
    private class RequestPermissionContract : AppContextActivityResultContract<String, Boolean> {
        override fun createIntent(context: Context, input: String): Intent =
            Intent(REQUEST_PERMISSIONS_ACTION).putExtra(
                REQUEST_PERMISSIONS_EXTRA,
                arrayOf(input),
            )

        override fun parseResult(input: String, resultCode: Int, intent: Intent?): Boolean {
            if (resultCode != Activity.RESULT_CANCELED) {
                return false
            }
            val permissions = intent?.getStringArrayExtra(PERMISSIONS_RESULT_EXTRA) ?: return false
            val results = intent.getIntArrayExtra(PERMISSION_GRANTS_RESULT_EXTRA) ?: return false
            val resultIndex = permissions.indexOf(input)
            return resultIndex >= 0 && results.getOrNull(resultIndex) == PackageManager.PERMISSION_GRANTED
        }
    }

    private companion object {
        const val VPN_CONSENT_INPUT = "vpn-consent"
        const val POST_NOTIFICATIONS_PERMISSION = "android.permission.POST_NOTIFICATIONS"
        const val REQUEST_PERMISSIONS_ACTION = "android.intent.action.REQUEST_PERMISSIONS"
        const val REQUEST_PERMISSIONS_EXTRA = "android.intent.extra.PERMISSIONS"
        const val PERMISSIONS_RESULT_EXTRA = "androidx.activity.result.contract.extra.PERMISSIONS"
        const val PERMISSION_GRANTS_RESULT_EXTRA =
            "androidx.activity.result.contract.extra.PERMISSION_GRANT_RESULTS"
    }
}
