package io.tunnet.android

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.tunnet.android.wire.Lifecycle
import io.tunnet.android.wire.Peer
import io.tunnet.android.wire.Snapshot
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {

    private val vpnConsentDenied = MutableStateFlow<String?>(null)
    private val vpnConsentInProgress = MutableStateFlow(false)
    private val lanDenied = MutableStateFlow(false)
    private var pendingConnectInvite: String? = null

    private val vpnConsent = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        vpnConsentInProgress.value = false
        if (result.resultCode == Activity.RESULT_OK) {
            vpnConsentDenied.value = null
            startVpnService(pendingConnectInvite)
        } else {
            pendingConnectInvite = null
            vpnConsentDenied.value = "VPN permission is required to connect"
        }
    }

    private val notificationPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { }

    private val localNetworkPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) {
        refreshLanState()
        continueVpn(pendingConnectInvite)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        requestNotificationPermissionIfNeeded()
        refreshLanState()
        handleLaunchInvite(intent)

        setContent {
            MaterialTheme {
                val snapshot by TunnetVpnService.snapshots.collectAsStateWithLifecycle()
                val denied by vpnConsentDenied.collectAsStateWithLifecycle()
                val askingVpn by vpnConsentInProgress.collectAsStateWithLifecycle()
                val noLan by lanDenied.collectAsStateWithLifecycle()
                TunnetScreen(
                    snapshot = snapshot,
                    vpnConsentDenied = denied,
                    vpnConsentInProgress = askingVpn,
                    lanDenied = noLan,
                    onConnect = { connect(invite = null) },
                    onDisconnect = ::disconnect,
                    onJoin = { connect(invite = it) },
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleLaunchInvite(intent)
    }

    override fun onResume() {
        super.onResume()
        refreshLanState()
        TunnetVpnService.pushLanAvailability()
    }

    private fun handleLaunchInvite(intent: Intent?) {
        val invite = intent?.getStringExtra(TunnetVpnService.EXTRA_INVITE)?.trim().orEmpty()
        if (invite.isEmpty()) return
        intent?.removeExtra(TunnetVpnService.EXTRA_INVITE)
        connect(invite)
    }

    private fun refreshLanState() {
        lanDenied.value = LocalNetworkAccess.state(this) == LocalNetworkAccess.State.Denied
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            notificationPermission.launch(android.Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    private fun connect(invite: String?) {
        vpnConsentDenied.value = null
        pendingConnectInvite = invite
        if (LocalNetworkAccess.shouldRequest(this)) {
            localNetworkPermission.launch(LocalNetworkAccess.PERMISSION)
            return
        }
        continueVpn(invite)
    }

    private fun continueVpn(invite: String?) {
        val prepare = VpnService.prepare(this)
        if (prepare != null) {
            vpnConsentInProgress.value = true
            vpnConsent.launch(prepare)
        } else {
            startVpnService(invite)
        }
    }

    private fun startVpnService(invite: String?) {
        pendingConnectInvite = null
        val intent = Intent(this, TunnetVpnService::class.java)
            .setAction(TunnetVpnService.ACTION_CONNECT)
        if (!invite.isNullOrBlank()) {
            intent.putExtra(TunnetVpnService.EXTRA_INVITE, invite)
        }
        startForegroundService(intent)
    }

    private fun disconnect() {
        startService(
            Intent(this, TunnetVpnService::class.java).setAction(TunnetVpnService.ACTION_DISCONNECT),
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun TunnetScreen(
    snapshot: Snapshot,
    vpnConsentDenied: String?,
    vpnConsentInProgress: Boolean,
    lanDenied: Boolean,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
    onJoin: (String) -> Unit,
) {
    Scaffold(topBar = { TopAppBar(title = { Text("Tunnet") }) }) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .imePadding(),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            item { StatusCard(snapshot, vpnConsentDenied, vpnConsentInProgress, lanDenied) }

            val errorText = vpnConsentDenied ?: snapshot.error.message.takeIf {
                snapshot.hasError() && snapshot.lifecycle == Lifecycle.LIFECYCLE_FAILED && it.isNotEmpty()
            }
            errorText?.let { error ->
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

            item {
                ConnectionControls(
                    snapshot,
                    vpnConsentInProgress,
                    onConnect,
                    onDisconnect,
                )
            }

            if (snapshot.isJoined()) {
                if (snapshot.peersList.isEmpty()) {
                    item { Text("No peers yet.", style = MaterialTheme.typography.bodyMedium) }
                } else {
                    item { Text("Peers", style = MaterialTheme.typography.titleMedium) }
                    items(snapshot.peersList, key = { it.endpointId.ifEmpty { it.ip } }) { peer ->
                        PeerCard(peer, snapshot.endpointId)
                    }
                }
            } else {
                item { JoinCard(snapshot, vpnConsentInProgress, onJoin) }
            }
        }
    }
}

@Composable
private fun StatusCard(
    snapshot: Snapshot,
    vpnConsentDenied: String?,
    vpnConsentInProgress: Boolean,
    lanDenied: Boolean,
) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = if (vpnConsentInProgress) "Starting" else snapshot.headline(vpnConsentDenied),
                    style = MaterialTheme.typography.headlineSmall,
                )
                if (vpnConsentInProgress || snapshot.busy()) {
                    Spacer(Modifier.fillMaxWidth(0.05f))
                    CircularProgressIndicator(Modifier.height(20.dp))
                }
            }
            snapshot.networksList.firstOrNull()?.let { network ->
                Text("Network: ${network.networkName}", style = MaterialTheme.typography.bodyMedium)
                Text("Mesh IP: ${network.ip}", style = MaterialTheme.typography.bodyMedium)
            }
            if (snapshot.hostname.isNotEmpty()) {
                Text("This device: ${snapshot.hostname}", style = MaterialTheme.typography.bodySmall)
            }
            if (lanDenied) {
                Text(
                    "Local network access is off. Nearby discovery is disabled; " +
                        "peers can still connect through relay.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun ConnectionControls(
    snapshot: Snapshot,
    vpnConsentInProgress: Boolean,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
) {
    val stopped = snapshot.lifecycle == Lifecycle.LIFECYCLE_STOPPED ||
        snapshot.lifecycle == Lifecycle.LIFECYCLE_UNSPECIFIED
    val busy = snapshot.busy() || vpnConsentInProgress
    if (stopped) {
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
private fun JoinCard(
    snapshot: Snapshot,
    vpnConsentInProgress: Boolean,
    onJoin: (String) -> Unit,
) {
    var invite by remember { mutableStateOf("") }
    val context = LocalContext.current
    val stopped = snapshot.lifecycle == Lifecycle.LIFECYCLE_STOPPED ||
        snapshot.lifecycle == Lifecycle.LIFECYCLE_UNSPECIFIED
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
                maxLines = 4,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedButton(
                onClick = {
                    val pasted = context.getSystemService(android.content.ClipboardManager::class.java)
                        ?.primaryClip
                        ?.takeIf { it.itemCount > 0 }
                        ?.getItemAt(0)
                        ?.coerceToText(context)
                        ?.toString()
                        ?.trim()
                    if (!pasted.isNullOrEmpty()) {
                        invite = pasted
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Paste from clipboard")
            }
            Button(
                onClick = { onJoin(invite.trim()) },
                enabled = invite.isNotBlank() && !snapshot.busy() && !vpnConsentInProgress,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    when {
                        snapshot.lifecycle == Lifecycle.LIFECYCLE_JOINING -> "Joining…"
                        snapshot.lifecycle == Lifecycle.LIFECYCLE_PENDING_APPROVAL ->
                            "Waiting for approval…"
                        stopped -> "Start and join"
                        else -> "Join"
                    },
                )
            }
        }
    }
}

@Composable
private fun PeerCard(peer: Peer, selfEndpointId: String) {
    val scope = rememberCoroutineScope()
    var pinging by remember { mutableStateOf(false) }
    var pingText by remember { mutableStateOf<String?>(null) }
    val canPing = peer.ip.isNotBlank() &&
        (peer.endpointId.isEmpty() || peer.endpointId != selfEndpointId)
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(peer.hostname, style = MaterialTheme.typography.bodyLarge)
            Text(
                buildString {
                    append(peer.ip)
                    append(" · ")
                    append(peer.statusLabel())
                    peer.pathLabel()?.let { append(" · ").append(it) }
                    if (peer.hasLatencyMs()) {
                        append(" · ").append("%.0f ms".format(peer.latencyMs))
                    }
                },
                style = MaterialTheme.typography.bodySmall,
            )
            if (canPing) {
                Button(
                    onClick = {
                        pinging = true
                        pingText = null
                        scope.launch {
                            val result = withContext(Dispatchers.IO) { IcmpPing.ping(peer.ip) }
                            pingText = when (result) {
                                is IcmpPing.Result.Reply ->
                                    "%.1f ms".format(result.latencyMs)
                                is IcmpPing.Result.Failure -> result.message
                            }
                            pinging = false
                        }
                    },
                    enabled = !pinging,
                ) {
                    Text(if (pinging) "Pinging…" else "Ping")
                }
                pingText?.let { text ->
                    Text(text, style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}
