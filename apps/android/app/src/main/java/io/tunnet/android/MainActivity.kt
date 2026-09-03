package io.tunnet.android

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The whole UI: join a network, connect, see peers.
 *
 * Holds no mesh logic. Every fact on screen comes from the agent via
 * [TunnetState]; the buttons only start/stop the service or forward a join.
 */
class MainActivity : ComponentActivity() {

    companion object {
        /** Guard so a configuration-driven `onCreate` does not re-trigger the
         * auto-connect. The flag is per process, like the agent itself. */
        private var autoConnected = false
    }

    /**
     * VPN consent. Android requires [VpnService.prepare] before a tunnel can be
     * established, and the result arrives asynchronously, so connecting is a
     * two-step flow: ask, then start the service once granted.
     */
    private val vpnConsent = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpnService()
        } else {
            TunnetState.setError("VPN permission is required to connect")
        }
    }

    /**
     * Notifications are how a foreground service stays visible. A denial is not
     * fatal (the VPN still runs), so the result is deliberately ignored.
     */
    private val notificationPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        requestNotificationPermissionIfNeeded()

        // The product promise is "connected until switched off", so opening the
        // app reconnects. A join without this would only appear after the user
        // tapped something, because a killed process loses the in-memory stage
        // and the poll refuses to run while Stopped. The daemon decides what
        // "connect" means: idle bootstrap when nothing is joined, the full
        // runtime (tunnel up) when state exists.
        if (!autoConnected) {
            autoConnected = true
            connect()
        }

        setContent {
            MaterialTheme {
                val status by TunnetState.status.collectAsStateWithLifecycle()
                // Poll rather than refresh-once: after a join the daemon
                // rebinds its API (idle bootstrap -> full runtime) and a single
                // refresh hits exactly that ~300ms window, reporting "not
                // joined" even though the join succeeded.
                LaunchedEffect(Unit) {
                    while (isActive) {
                        if (TunnetState.status.value.stage != Stage.Stopped) refresh()
                        delay(2000)
                    }
                }
                TunnetScreen(
                    status = status,
                    onConnect = ::connect,
                    onDisconnect = ::disconnect,
                    onJoin = ::join,
                )
            }
        }
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            notificationPermission.launch(android.Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    /** Ask for VPN consent if needed, then start the service. */
    private fun connect() {
        TunnetState.setError(null)
        // Show progress on THIS tap. Starting the agent takes a couple of
        // seconds, and the service only reports Starting once it is itself
        // running, so without this the screen sat unchanged long enough to look
        // broken.
        TunnetState.setStage(Stage.Starting)
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnConsent.launch(intent)
        } else {
            startVpnService()
        }
    }

    private fun startVpnService() {
        startForegroundService(
            Intent(this, TunnetVpnService::class.java).setAction(TunnetVpnService.ACTION_CONNECT),
        )
    }

    private fun disconnect() {
        startService(
            Intent(this, TunnetVpnService::class.java).setAction(TunnetVpnService.ACTION_DISCONNECT),
        )
    }

    /**
     * Join a Direct network by invite code.
     *
     * The agent must already be running, because the join goes through its Local
     * API: with no network joined the agent parks in its bootstrap mode serving
     * exactly that endpoint. Once state is written it proceeds to the full
     * runtime and establishes the tunnel on its own, so joining is also
     * connecting.
     */
    private fun join(inviteCode: String) {
        lifecycleScope.launch {
            TunnetState.setError(null)
            if (TunnetState.status.value.stage == Stage.Stopped) {
                // One tap, one intent: park the invite and let the service
                // redeem it once the agent is up, rather than asking the user
                // to tap again for a step that is our implementation detail.
                TunnetState.setPendingInvite(inviteCode)
                connect()
                return@launch
            }
            val result = withContext(Dispatchers.IO) {
                TunnetNative.join(inviteCode, Build.MODEL ?: "android")
            }
            when (result) {
                is TunnetNative.Result.Ok -> refresh()
                is TunnetNative.Result.Err -> TunnetState.setError(result.message)
            }
        }
    }

    /** Pull fresh status; the agent is the truth for everything shown. */
    private fun refresh() {
        lifecycleScope.launch {
            withContext(Dispatchers.IO) {
                when (val status = TunnetNative.status()) {
                    is TunnetNative.Result.Ok -> {
                        val data = status.data
                        val networks = AgentJson.networks(data)
                        // A poll must not clear an error the user has not seen
                        // yet (same rule as the service).
                        TunnetState.update {
                            it.copy(
                                dataPlaneUp = data.optBoolean("data_plane_up", false),
                                endpointId = data.optString("endpoint_id"),
                                hostname = data.optString("hostname"),
                                networks = networks,
                            )
                        }
                        // Peers come with the same poll, so the list is live.
                        networks.firstOrNull()?.let { loadPeersIntoState(it.id) }
                    }
                    is TunnetNative.Result.Err -> {
                        // "not running" is expected while stopped/stopping and
                        // would be noise on screen; anything else is real.
                        if (!status.message.contains("not running")) {
                            TunnetState.setError(status.message)
                        }
                    }
                }
            }
        }
    }

    /** Peers of the first joined network, driving the peer list. */
    private fun loadPeersIntoState(networkId: String) {
        when (val result = TunnetNative.peers(networkId)) {
            is TunnetNative.Result.Ok ->
                TunnetState.update { it.copy(peers = AgentJson.peers(result.data)) }
            is TunnetNative.Result.Err -> {}
        }
    }

    override fun onResume() {
        super.onResume()
        if (TunnetState.status.value.stage == Stage.Running) refresh()
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun TunnetScreen(
    status: TunnetStatus,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
    onJoin: (String) -> Unit,
) {
    Scaffold(topBar = { TopAppBar(title = { Text("Tunnet") }) }) { padding ->
        // One LazyColumn for the whole screen rather than a Column that grows:
        // an invite code is ~600 characters, and an unbounded field pushed the
        // Join button off the bottom with no way to scroll to it. This also
        // avoids nesting the peer list's scroller inside another scroller,
        // which Compose rejects at measure time.
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                // Keep the focused field and its button above the keyboard.
                .imePadding(),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            item { StatusCard(status) }

            status.error?.let { error ->
                item {
                    Card(Modifier.fillMaxWidth()) {
                        Text(
                            text = error,
                            color = MaterialTheme.colorScheme.error,
                            modifier = Modifier.padding(16.dp),
                        )
                    }
                }
            }

            if (status.joined) {
                item { ConnectionControls(status, onConnect, onDisconnect) }
                if (status.peers.isEmpty()) {
                    item { Text("No peers yet.", style = MaterialTheme.typography.bodyMedium) }
                } else {
                    item { Text("Peers", style = MaterialTheme.typography.titleMedium) }
                    items(status.peers) { peer -> PeerCard(peer) }
                }
            } else {
                item { JoinCard(status, onJoin) }
            }
        }
    }
}

@Composable
private fun StatusCard(status: TunnetStatus) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = when {
                        status.connected -> "Connected"
                        status.stage == Stage.Starting -> "Starting"
                        status.stage == Stage.Stopping -> "Stopping"
                        // Running but not joined is not "connecting": there is
                        // nothing to connect to until a network is joined, and
                        // claiming progress that will never arrive is a lie.
                        status.stage == Stage.Running && !status.joined -> "Not joined"
                        status.stage == Stage.Running -> "Connecting"
                        else -> "Disconnected"
                    },
                    style = MaterialTheme.typography.headlineSmall,
                )
                if (status.stage == Stage.Starting || status.stage == Stage.Stopping) {
                    Spacer(Modifier.fillMaxWidth(0.05f))
                    CircularProgressIndicator(Modifier.height(20.dp))
                }
            }
            status.networks.firstOrNull()?.let { network ->
                Text("Network: ${network.name}", style = MaterialTheme.typography.bodyMedium)
                Text("Mesh IP: ${network.ip}", style = MaterialTheme.typography.bodyMedium)
            }
            if (status.hostname.isNotEmpty()) {
                Text("This device: ${status.hostname}", style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
private fun ConnectionControls(
    status: TunnetStatus,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
) {
    val busy = status.stage == Stage.Starting || status.stage == Stage.Stopping
    if (status.stage == Stage.Stopped) {
        Button(onClick = onConnect, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
            Text("Connect")
        }
    } else {
        Button(onClick = onDisconnect, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
            Text("Disconnect")
        }
    }
}

@Composable
private fun JoinCard(status: TunnetStatus, onJoin: (String) -> Unit) {
    var invite by remember { mutableStateOf("") }
    val clipboard = LocalClipboardManager.current
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("Join a network", style = MaterialTheme.typography.titleMedium)
            Text(
                "Run `tunnet invite <network>` on a machine already in the mesh, " +
                    "then paste the code here.",
                style = MaterialTheme.typography.bodySmall,
            )
            OutlinedTextField(
                value = invite,
                onValueChange = { invite = it },
                label = { Text("Invite code") },
                // Capped so a long code scrolls inside the field instead of
                // growing it without limit.
                maxLines = 4,
                modifier = Modifier.fillMaxWidth(),
            )
            // An invite code is far too long to type, so pasting is the only
            // realistic path and deserves to be one tap.
            OutlinedButton(
                onClick = { clipboard.getText()?.text?.let { invite = it.trim() } },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Paste from clipboard")
            }
            Button(
                onClick = { onJoin(invite.trim()) },
                enabled = invite.isNotBlank() && status.stage != Stage.Starting,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(if (status.stage == Stage.Stopped) "Start and join" else "Join")
            }
        }
    }
}

@Composable
private fun PeerCard(peer: Peer) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp)) {
            Text(peer.hostname, style = MaterialTheme.typography.bodyLarge)
            Text(
                buildString {
                    append(peer.ip)
                    append(" · ")
                    append(peer.status)
                    peer.path?.let { append(" · ").append(it) }
                    peer.latencyMs?.let { append(" · ").append("%.0f ms".format(it)) }
                },
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}
