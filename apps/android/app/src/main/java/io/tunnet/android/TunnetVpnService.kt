package io.tunnet.android

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.net.wifi.WifiManager
import android.os.Build
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

/**
 * Hosts the Tunnet agent and owns the tunnel.
 *
 * The agent runs in this process (it cannot be a daemon on Android) and asks
 * this service for a tunnel through [establishTun] whenever its data plane comes
 * up. That direction matters: the agent knows the mesh address, and only the
 * framework can open a TUN, so neither side can go first alone.
 */
class TunnetVpnService : VpnService() {

    companion object {
        private const val TAG = "TunnetVpn"
        private const val CHANNEL_ID = "tunnet-vpn"
        private const val NOTIFICATION_ID = 1

        const val ACTION_CONNECT = "io.tunnet.android.CONNECT"
        const val ACTION_DISCONNECT = "io.tunnet.android.DISCONNECT"

        /** How often the service refreshes status and the notification. */
        private const val POLL_SECONDS = 3L

        /** Where agent state (identity, sealed secrets, socket) lives. */
        fun stateDir(context: Context): String = context.filesDir.resolve("tunnet").absolutePath
    }

    /**
     * Agent calls block, so they never run on the main thread. Single-threaded
     * so start and stop cannot interleave.
     */
    private val worker = Executors.newSingleThreadExecutor()

    /**
     * Status polling lives in the SERVICE, not the UI.
     *
     * The service outlives the Activity, and the notification is what the user
     * sees when the app is closed. With polling only in the Activity, the
     * notification kept claiming "Not joined to a network" long after the join
     * succeeded, because nothing refreshed it once the screen was gone.
     */
    private var poller: ScheduledExecutorService? = null

    /**
     * Whether THIS service has begun starting the agent.
     *
     * Deliberately not derived from [TunnetState]: that is UI-facing status,
     * and the Activity sets `Starting` the instant the user taps so the tap
     * feels responsive. Guarding on it made the service mistake the UI's
     * optimism for its own progress and skip starting the agent entirely.
     */
    private var agentStarted = false

    /** Held while connected so mDNS peer discovery can receive multicast. */
    private var multicastLock: WifiManager.MulticastLock? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // A null intent is the system restarting us, and it is also how an
        // always-on VPN starts us, so it must mean connect rather than crash.
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                stopAgent()
                return START_NOT_STICKY
            }
            else -> startAgent()
        }
        // STICKY so the system brings the mesh back after killing us for memory.
        return START_STICKY
    }

    private fun startAgent() {
        if (agentStarted) {
            Log.i(TAG, "agent already starting or running")
            return
        }
        agentStarted = true
        TunnetState.setStage(Stage.Starting)
        TunnetState.setError(null)
        goForeground("Starting…")
        acquireMulticastLock()

        worker.execute {
            when (val result = TunnetNative.start(stateDir(this), Build.MODEL ?: "android", this)) {
                is TunnetNative.Result.Ok -> {
                    Log.i(TAG, "agent started")
                    TunnetState.setStage(Stage.Running)
                    redeemPendingInvite()
                    refreshStatus()
                    startPolling()
                }
                is TunnetNative.Result.Err -> {
                    Log.e(TAG, "agent failed to start: ${result.message}")
                    agentStarted = false
                    TunnetState.update { it.copy(stage = Stage.Stopped, error = result.message) }
                    releaseMulticastLock()
                    stopSelf()
                }
            }
        }
    }

    private fun stopAgent() {
        TunnetState.setStage(Stage.Stopping)
        stopPolling()
        worker.execute {
            TunnetNative.stop()
            agentStarted = false
            releaseMulticastLock()
            TunnetState.reset()
            ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    /**
     * Complete a join the user asked for before the agent was running.
     *
     * Joining requires a live agent, so a first-run "join" has to start one
     * first. Redeeming the intent here rather than making the user tap again
     * keeps that an implementation detail. After this the agent writes network
     * state, leaves its bootstrap mode and establishes the tunnel on its own.
     */
    private fun redeemPendingInvite() {
        val invite = TunnetState.takePendingInvite() ?: return
        Log.i(TAG, "redeeming pending invite")
        // The agent is already Running by this point, so `Stage` no longer
        // conveys progress; without this the screen reads "Not joined" while
        // the join is actually in flight.
        TunnetState.setJoining(true)
        try {
            when (val result = TunnetNative.join(invite, Build.MODEL ?: "android")) {
                is TunnetNative.Result.Ok -> {
                    Log.i(TAG, "joined network")
                    // Publish the joined status BEFORE the flag drops. The
                    // caller refreshes too, but that happens after this
                    // function returns, leaving a window where `joining` is
                    // false and membership has not landed: the screen reads
                    // "Not joined" for a second, which looks like failure.
                    refreshStatus()
                }
                is TunnetNative.Result.Err -> {
                    Log.e(TAG, "join failed: ${result.message}")
                    TunnetState.setError(result.message)
                }
            }
        } finally {
            TunnetState.setJoining(false)
        }
    }

    /** Keep status and the notification current while the agent runs. */
    private fun startPolling() {
        if (poller != null) return
        poller = Executors.newSingleThreadScheduledExecutor().also { executor ->
            executor.scheduleWithFixedDelay(
                {
                    // Fixed DELAY, not rate: a slow refresh must not queue more
                    // work up behind itself.
                    runCatching { refreshStatus() }
                        .onFailure { Log.w(TAG, "status poll failed", it) }
                },
                POLL_SECONDS,
                POLL_SECONDS,
                TimeUnit.SECONDS,
            )
        }
    }

    private fun stopPolling() {
        poller?.shutdownNow()
        poller = null
    }

    /**
     * Refresh node status and peers from the agent, and update the notification.
     *
     * Runs on [worker]; callers must not be on the main thread.
     */
    fun refreshStatus() {
        val status = TunnetNative.status()
        if (status !is TunnetNative.Result.Ok) {
            if (status is TunnetNative.Result.Err) {
                TunnetState.setError(status.message)
            }
            return
        }

        val data = status.data
        val networks = AgentJson.networks(data)
        val peers = networks.firstOrNull()?.let { loadPeers(it.id) } ?: emptyList()

        // Deliberately does NOT clear `error`: this is a periodic poll, and a
        // successful poll says nothing about the failed action the user is
        // waiting to hear about. Clearing it here swallowed join failures
        // entirely, because the join is always followed by a refresh.
        TunnetState.update {
            it.copy(
                dataPlaneUp = data.optBoolean("data_plane_up", false),
                endpointId = data.optString("endpoint_id"),
                hostname = data.optString("hostname"),
                networks = networks,
                peers = peers,
            )
        }

        val current = TunnetState.status.value
        goForeground(
            when {
                !current.joined -> "Not joined to a network"
                current.dataPlaneUp -> "Connected — ${current.networks.first().ip}"
                else -> "Connecting…"
            },
        )
    }

    private fun loadPeers(networkId: String): List<Peer> {
        val result = TunnetNative.peers(networkId)
        if (result !is TunnetNative.Result.Ok) return emptyList()
        return AgentJson.peers(result.data)
    }

    /**
     * Establish a tunnel for the agent. **Called from a native agent thread.**
     *
     * Returns an owned file descriptor via [android.os.ParcelFileDescriptor.detachFd],
     * transferring ownership to the agent, which closes it when the data plane
     * goes down. Returning the descriptor without detaching would double-close.
     *
     * Returns -1 when no tunnel could be established (typically because VPN
     * consent was never granted or was revoked); the agent surfaces that as a
     * start failure rather than retrying blindly.
     */
    fun establishTun(
        addrs: Array<String>,
        routes: Array<String>,
        dns: Array<String>,
        mtu: Int,
    ): Int {
        return try {
            if (addrs.isEmpty()) {
                Log.e(TAG, "no tunnel address supplied")
                return -1
            }
            if (routes.isEmpty()) {
                // Establishing anyway would produce a tunnel that captures no
                // traffic: connected in the UI, silently carrying nothing.
                Log.e(TAG, "no routes supplied; refusing to establish a tunnel that captures nothing")
                return -1
            }

            val builder = Builder()
                .setSession(getString(R.string.app_name))
                .setMtu(mtu)
                // tun-rs drives the descriptor with non-blocking async I/O.
                .setBlocking(false)

            // One /32 per joined network. The agent owns exactly these
            // addresses; anything wider would claim addresses belonging to
            // peers and blackhole them locally.
            for (addr in addrs) {
                builder.addAddress(addr, 32)
            }

            // Routes are supplied, never derived from the addresses. Each is a
            // network's peer range in CIDR form, which is the traffic that must
            // enter the tunnel. Deriving a route from a /32 address yields a
            // host route to ourselves, so no peer traffic would be captured.
            for (route in routes) {
                val (network, prefix) = parseCidr(route) ?: run {
                    Log.e(TAG, "ignoring unparseable route: $route")
                    null
                } ?: continue
                builder.addRoute(network, prefix)
            }

            for (server in dns) {
                builder.addDnsServer(server)
            }

            // Keep our OWN sockets out of the tunnel. They carry the encrypted
            // mesh traffic, so routing them into it would loop: encrypt, into
            // the TUN, read back, encrypt again. Excluding by UID is what makes
            // this work without per-socket protect() plumbing into iroh.
            //
            // Note this also means the app itself cannot reach mesh IPs. Nothing
            // in the UI needs to: the agent is reached over a unix socket, and
            // ping/file transfer run over iroh streams rather than through the
            // TUN.
            try {
                builder.addDisallowedApplication(packageName)
            } catch (e: android.content.pm.PackageManager.NameNotFoundException) {
                // Cannot happen for our own package; if it somehow does, a
                // routing loop is worse than no tunnel.
                Log.e(TAG, "could not exclude self from tunnel", e)
                return -1
            }

            val pfd = builder.establish()
            if (pfd == null) {
                Log.e(TAG, "establish() returned null; VPN consent missing or revoked")
                return -1
            }
            Log.i(
                TAG,
                "tunnel established: addrs=${addrs.joinToString()} " +
                    "routes=${routes.joinToString()} dns=${dns.joinToString()} mtu=$mtu",
            )
            pfd.detachFd()
        } catch (e: Exception) {
            Log.e(TAG, "establishTun failed", e)
            -1
        }
    }

    /**
     * Split `10.9.0.0/24` into its network address and prefix.
     *
     * `addRoute` rejects an address with host bits set, so the network address
     * is masked here rather than trusted: a range whose text form carries host
     * bits would otherwise throw at establish() time.
     */
    private fun parseCidr(cidr: String): Pair<String, Int>? {
        val parts = cidr.split("/")
        if (parts.size != 2) return null
        val prefix = parts[1].toIntOrNull() ?: return null
        if (prefix !in 0..32) return null
        val octets = parts[0].split(".").mapNotNull { it.toIntOrNull() }
        if (octets.size != 4 || octets.any { it !in 0..255 }) return null
        val value = (octets[0] shl 24) or (octets[1] shl 16) or (octets[2] shl 8) or octets[3]
        // `shl 32` is undefined on Int (it shifts by 0), so /0 is special-cased.
        val mask = if (prefix == 0) 0 else (-1 shl (32 - prefix))
        val network = value and mask
        val text = "${(network ushr 24) and 0xFF}.${(network ushr 16) and 0xFF}." +
            "${(network ushr 8) and 0xFF}.${network and 0xFF}"
        return text to prefix
    }

    /** The user revoked our VPN permission, or another VPN replaced us. */
    override fun onRevoke() {
        Log.i(TAG, "VPN permission revoked")
        stopAgent()
        super.onRevoke()
    }

    override fun onDestroy() {
        releaseMulticastLock()
        worker.shutdown()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?) = super.onBind(intent)

    // -- Foreground notification --------------------------------------------

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.notification_channel_name),
            // Low: an always-present status notification should be silent.
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

    // -- mDNS multicast ------------------------------------------------------

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
