package io.tunnet.android

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONObject

/** A peer on the mesh, as the agent reports it. */
data class Peer(
    val hostname: String,
    val ip: String,
    /**
     * Human-readable liveness.
     *
     * Deliberately a string, not a boolean: the agent distinguishes presence
     * (`online`) from connection state (`connected`/`suspended`/`reconnecting`),
     * and both are optional. Collapsing that to "offline" made every peer look
     * dead, including ones actively exchanging traffic.
     */
    val status: String,
    /** Round-trip time when the agent has measured one. */
    val latencyMs: Double? = null,
    /** `direct` or `relay`, when known. */
    val path: String? = null,
)

/** A Direct network this node has joined. */
data class Network(
    val id: String,
    val name: String,
    val ip: String,
)

/** Where the agent is in its lifecycle, as far as the UI is concerned. */
enum class Stage { Stopped, Starting, Running, Stopping }

data class TunnetStatus(
    val stage: Stage = Stage.Stopped,
    /** True once the agent reports a live data plane, i.e. traffic is flowing. */
    val dataPlaneUp: Boolean = false,
    val endpointId: String = "",
    val hostname: String = "",
    val networks: List<Network> = emptyList(),
    val peers: List<Peer> = emptyList(),
    /** Last failure, shown until the next successful action clears it. */
    val error: String? = null,
) {
    val joined: Boolean get() = networks.isNotEmpty()
    val connected: Boolean get() = stage == Stage.Running && dataPlaneUp
}

/**
 * Process-wide status, published by [TunnetVpnService] and observed by the UI.
 *
 * A singleton rather than a bound service: the agent is already a process-wide
 * singleton (one VPN session per app), so binding would add a lifecycle to
 * marshal across without modelling anything the agent does not already enforce.
 */
object TunnetState {
    private val _status = MutableStateFlow(TunnetStatus())
    val status: StateFlow<TunnetStatus> = _status.asStateFlow()

    /**
     * An invite entered before the agent was running.
     *
     * Joining needs a running agent (the join goes through its Local API), but
     * the user's single intent is "join this network". Rather than make them
     * tap twice, the intent is parked here and [TunnetVpnService] redeems it as
     * soon as the agent is up. Single-use: cleared by whoever takes it.
     */
    @Volatile
    private var pendingInvite: String? = null

    fun setPendingInvite(code: String) {
        pendingInvite = code
    }

    fun takePendingInvite(): String? {
        val invite = pendingInvite
        pendingInvite = null
        return invite
    }

    fun update(transform: (TunnetStatus) -> TunnetStatus) {
        _status.value = transform(_status.value)
    }

    fun setStage(stage: Stage) = update { it.copy(stage = stage) }

    fun setError(message: String?) = update { it.copy(error = message) }

    /** Reset to stopped, keeping nothing stale from the previous session. */
    fun reset() {
        pendingInvite = null
        _status.value = TunnetStatus()
    }
}

/**
 * Parsers for the agent's JSON, in ONE place.
 *
 * The service and the UI both read node status, and when each had its own copy
 * the two drifted: a wrong field name (`assigned_ipv4` instead of `ip`) showed
 * a blank mesh address, and reading the optional `online` flag as a plain
 * boolean marked every peer offline. Optional fields are omitted entirely by
 * the agent, so defaults silently lie.
 */
object AgentJson {

    fun networks(node: JSONObject): List<Network> {
        val array = node.optJSONArray("networks") ?: return emptyList()
        return buildList {
            for (i in 0 until array.length()) {
                val n = array.getJSONObject(i)
                add(
                    Network(
                        id = n.optString("network_id"),
                        name = n.optString("network_name"),
                        ip = n.optString("ip"),
                    ),
                )
            }
        }
    }

    fun peers(response: JSONObject): List<Peer> {
        val array = response.optJSONArray("peers") ?: return emptyList()
        return buildList {
            for (i in 0 until array.length()) {
                val p = array.getJSONObject(i)
                add(
                    Peer(
                        hostname = p.optString("hostname"),
                        ip = p.optString("ip"),
                        status = peerStatus(p),
                        latencyMs = if (p.has("latency_ms")) p.optDouble("latency_ms") else null,
                        path = p.optString("path").takeIf { it.isNotEmpty() && it != "unknown" },
                    ),
                )
            }
        }
    }

    /**
     * Presence first, then connection state.
     *
     * `online` reflects whether the peer is announcing itself; `conn_state`
     * reflects this node's transport to it. A peer can be present but with no
     * active connection (`suspended`), which is normal when idle and must not
     * read as "offline".
     */
    private fun peerStatus(peer: JSONObject): String {
        val online = if (peer.has("online")) peer.optBoolean("online") else null
        val connState = peer.optString("conn_state").takeIf { it.isNotEmpty() }
        return when {
            online == true -> connState ?: "online"
            connState != null -> connState
            online == false -> "offline"
            else -> "unknown"
        }
    }
}
