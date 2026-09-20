package io.tunnet.android

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import io.tunnet.android.wire.Lifecycle
import io.tunnet.android.wire.Snapshot
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlin.coroutines.coroutineContext

/**
 * Android owner of the embedded agent.
 *
 * Start and stop take [ops]. Join runs off that mutex so Disconnect, revoke,
 * and destroy can cancel a pending join immediately.
 * Snapshot observation is independent: detaching the listener does not stop
 * the runtime.
 */
class TunnetVpnService : VpnService() {

    companion object {
        private const val TAG = "TunnetVpn"
        private const val CHANNEL_ID = "tunnet-vpn"
        private const val NOTIFICATION_ID = 1

        const val ACTION_CONNECT = VpnHostPolicy.ACTION_CONNECT
        const val ACTION_DISCONNECT = VpnHostPolicy.ACTION_DISCONNECT
        const val EXTRA_INVITE = "io.tunnet.android.INVITE"

        private val main = Handler(Looper.getMainLooper())
        private val _snapshots = MutableStateFlow(Snapshot.getDefaultInstance())
        val snapshots: StateFlow<Snapshot> = _snapshots.asStateFlow()

        @Volatile
        private var running: TunnetVpnService? = null

        fun stateDir(context: Context): String = context.filesDir.resolve("tunnet").absolutePath

        fun pushLanAvailability() {
            running?.let { service ->
                service.enqueue { service.syncLanLocked() }
            }
        }

        internal fun publishSnapshot(snapshot: Snapshot) {
            _snapshots.value = snapshot
        }
    }

    private val desired by lazy { DesiredConnection.of(this) }
    private val job = SupervisorJob()
    private val scope = CoroutineScope(job + Dispatchers.IO)
    private val ops = Mutex()

    @Volatile
    private var alive = true

    private var multicastLock: WifiManager.MulticastLock? = null
    @Volatile
    private var rustMulticastDemand = false
    @Volatile
    private var wifiPresent = false
    private val wifiNetworks = mutableSetOf<Network>()
    private var wifiCallback: ConnectivityManager.NetworkCallback? = null

    private val listener = SnapshotListener { bytes ->
        val snapshot = runCatching { TunnetNative.parseSnapshot(bytes) }.getOrElse { err ->
            Log.e(TAG, "snapshot decode failed", err)
            return@SnapshotListener
        }
        main.post {
            if (!alive) return@post
            publishSnapshot(snapshot)
            goForeground(snapshot.notificationText())
        }
    }

    override fun onCreate() {
        super.onCreate()
        alive = true
        running = this
        createNotificationChannel()
        registerWifiWatch()
        TunnetNative.setSnapshotListener(listener)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val decision = VpnHostPolicy.decide(
            action = intent?.action,
            invite = intent?.getStringExtra(EXTRA_INVITE),
            wanted = desired.wanted,
        )
        desired.wanted = decision.wanted
        when (decision.command) {
            VpnHostPolicy.Command.Stop -> {
                enqueue { stopLocked() }
                return START_NOT_STICKY
            }
            VpnHostPolicy.Command.Attach -> {
                goForeground("Starting…")
                val invite = decision.invite
                scope.launch {
                    val ready = ops.withLock { startAgentLocked() }
                    if (ready) {
                        joinNetwork(invite)
                    }
                }
                return START_STICKY
            }
        }
    }

    private fun enqueue(block: suspend () -> Unit) {
        scope.launch {
            ops.withLock { block() }
        }
    }

    private suspend fun startAgentLocked(): Boolean {
        if (!alive) return false
        syncLanLocked()
        val result = TunnetNative.start(
            stateDir(this),
            Build.MODEL ?: "android",
            this,
        )
        if (!alive || !coroutineContext.isActive) {
            return false
        }
        return when (result) {
            TunnetNative.Result.Ok -> {
                Log.i(TAG, "agent attached")
                true
            }
            is TunnetNative.Result.Err -> {
                Log.e(TAG, "agent failed to start: ${result.message}")
                desired.wanted = false
                publishFailed(result)
                applyMulticastLock()
                main.post {
                    ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
                }
                stopSelf()
                false
            }
        }
    }

    private suspend fun joinNetwork(invite: String?) {
        if (invite.isNullOrBlank()) return
        if (!alive || !desired.wanted || !coroutineContext.isActive) return
        when (val result = TunnetNative.join(invite, Build.MODEL ?: "android")) {
            TunnetNative.Result.Ok -> Log.i(TAG, "join issued")
            is TunnetNative.Result.Err -> Log.e(TAG, "join failed: ${result.message}")
        }
    }

    private fun syncLanLocked() {
        TunnetNative.setLanAvailable(LocalNetworkAccess.isAvailable(this))
        applyMulticastLock()
    }

    private suspend fun stopLocked() {
        desired.wanted = false
        TunnetNative.stop()
        applyMulticastLock()
        main.post {
            publishSnapshot(
                Snapshot.newBuilder().setLifecycle(Lifecycle.LIFECYCLE_STOPPED).build(),
            )
            ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        }
        stopSelf()
    }

    fun establishTun(
        addrs: Array<String>,
        routes: Array<String>,
        dns: Array<String>,
        mtu: Int,
        allowIpv6Passthrough: Boolean,
        inheritUnderlyingMetered: Boolean,
    ): Int {
        if (!alive) return -1
        val spec = when (
            val parsed = VpnTunnelSpec.parse(
                addrs,
                routes,
                dns,
                mtu,
                allowIpv6Passthrough,
                inheritUnderlyingMetered,
            )
        ) {
            is VpnTunnelSpec.Invalid -> {
                Log.e(TAG, parsed.reason)
                return -1
            }
            is VpnTunnelSpec.Ready -> parsed
        }
        return try {
            applyTunnel(spec)
        } catch (e: Exception) {
            Log.e(TAG, "establishTun failed", e)
            -1
        }
    }

    private fun applyTunnel(spec: VpnTunnelSpec.Ready): Int {
        val builder = Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(spec.mtu)
            .setBlocking(false)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            if (spec.allowIpv6Passthrough) {
                builder.allowFamily(android.system.OsConstants.AF_INET6)
            }
            builder.setMetered(!spec.inheritUnderlyingMetered)
        }

        for ((address, prefix) in spec.addresses) {
            builder.addAddress(address, prefix)
        }
        for ((network, prefix) in spec.routes) {
            builder.addRoute(network, prefix)
        }
        for (server in spec.dns) {
            builder.addDnsServer(server)
        }

        val pfd = builder.establish()
        if (pfd == null) {
            Log.e(TAG, "establish() returned null; VPN consent missing or revoked")
            return -1
        }
        Log.i(
            TAG,
            "tunnel established: addrs=${spec.addresses} routes=${spec.routes} " +
                "dns=${spec.dns} mtu=${spec.mtu}",
        )
        return TunnelFd.detachOrClose(pfd)
    }

    override fun onRevoke() {
        Log.i(TAG, "VPN permission revoked")
        desired.wanted = false
        enqueue { stopLocked() }
        super.onRevoke()
    }

    override fun onDestroy() {
        alive = false
        if (running === this) {
            running = null
        }
        unregisterWifiWatch()
        TunnetNative.setSnapshotListener(null)
        runBlocking {
            withContext(Dispatchers.IO) {
                ops.withLock {
                    TunnetNative.stop()
                }
            }
        }
        applyMulticastLock()
        job.cancel()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?) = super.onBind(intent)

    private fun publishFailed(result: TunnetNative.Result.Err) {
        main.post {
            publishSnapshot(
                Snapshot.newBuilder()
                    .setLifecycle(Lifecycle.LIFECYCLE_FAILED)
                    .setError(
                        io.tunnet.android.wire.SnapshotError.newBuilder()
                            .setKind(result.kind)
                            .setMessage(result.message),
                    )
                    .build(),
            )
        }
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.notification_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = getString(R.string.notification_channel_description)
            setShowBadge(false)
        }
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun goForeground(text: String) {
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(open)
            .setOngoing(true)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceCompat.startForeground(
                this,
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    /**
     * Called from the native multicast host. Do not take [ops]: this runs on
     * the agent thread while [startAgentLocked] may already hold that mutex.
     */
    @Synchronized
    fun setMulticastDemand(needed: Boolean) {
        rustMulticastDemand = needed
        applyMulticastLock()
    }

    @Synchronized
    private fun applyMulticastLock() {
        val hold = alive && MulticastHold.shouldHold(
            rustMulticastDemand,
            LocalNetworkAccess.isAvailable(this),
            wifiPresent,
        )
        if (hold) {
            acquireMulticastLock()
        } else {
            releaseMulticastLock()
        }
    }

    private fun registerWifiWatch() {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        val request = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .build()
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                synchronized(this@TunnetVpnService) {
                    wifiNetworks.add(network)
                    wifiPresent = wifiNetworks.isNotEmpty()
                }
                applyMulticastLock()
            }

            override fun onLost(network: Network) {
                synchronized(this@TunnetVpnService) {
                    wifiNetworks.remove(network)
                    wifiPresent = wifiNetworks.isNotEmpty()
                }
                applyMulticastLock()
            }
        }
        wifiCallback = callback
        cm.registerNetworkCallback(request, callback)
    }

    private fun unregisterWifiWatch() {
        wifiCallback?.let { callback ->
            runCatching {
                getSystemService(ConnectivityManager::class.java)
                    ?.unregisterNetworkCallback(callback)
            }
        }
        wifiCallback = null
        synchronized(this) {
            wifiNetworks.clear()
            wifiPresent = false
        }
    }

    private fun acquireMulticastLock() {
        if (multicastLock != null) return
        val wifi = applicationContext.getSystemService(WifiManager::class.java) ?: return
        multicastLock = wifi.createMulticastLock("tunnet-mdns").apply {
            setReferenceCounted(false)
            acquire()
        }
    }

    private fun releaseMulticastLock() {
        multicastLock?.let { if (it.isHeld) it.release() }
        multicastLock = null
    }
}
