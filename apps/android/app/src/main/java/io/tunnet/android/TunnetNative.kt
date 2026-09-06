package io.tunnet.android

import org.json.JSONObject

/**
 * Binding to the Tunnet agent (`libtunnet_mobile.so`, from `crates/tunnet-mobile`).
 *
 * Holds no mesh logic: the agent is the truth for everything (identity, peers,
 * whether the data plane is up), and it is driven through the same Local
 * Management API the CLI and desktop app use.
 *
 * Every native call returns a JSON envelope rather than throwing across JNI:
 *
 * ```json
 * {"ok": true,  "data": { ... }}
 * {"ok": false, "error": "reason"}
 * ```
 *
 * All calls BLOCK (some, like [start], for seconds). Never call them from the
 * main thread.
 */
object TunnetNative {
    init {
        System.loadLibrary("tunnet_mobile")
    }

    /** A native call's outcome: parsed data, or the agent's reason for failing. */
    sealed interface Result {
        data class Ok(val data: JSONObject) : Result
        data class Err(val message: String) : Result
    }

    /**
     * Start the agent against [stateDir], reporting itself as [deviceName].
     *
     * [vpnService] must expose `int establishTun(String ipv4, int prefix, int mtu)`:
     * the agent calls back into it whenever the data plane needs a tunnel, since
     * only the framework can open one. Registered before startup because the
     * agent establishes during startup when a network is already joined.
     */
    fun start(stateDir: String, deviceName: String, vpnService: Any): Result =
        parse(nativeStart(stateDir, deviceName, vpnService))

    /** Stop the agent and tear down the tunnel. Idempotent. */
    fun stop(): Result = parse(nativeStop())

    /** Node status: mode, endpoint id, joined networks, data-plane state. */
    fun status(): Result = parse(nativeStatus())

    /** Join a Direct network with an invite code. */
    fun join(inviteCode: String, hostname: String): Result =
        parse(nativeJoin(inviteCode, hostname))

    /** Peers of [networkId]. */
    fun peers(networkId: String): Result = parse(nativePeers(networkId))

    /** Bring the data plane up; establishes a tunnel via the callback above. */
    fun up(): Result = parse(nativeUp())

    /** Take the data plane down without stopping the agent. */
    fun down(): Result = parse(nativeDown())

    /**
     * Parse an envelope. A malformed one is reported as an error rather than
     * thrown: the agent is the only writer, so this can only mean a version
     * mismatch between the app and the packaged library, and surfacing that on
     * screen beats a crash.
     */
    private fun parse(raw: String?): Result {
        if (raw == null) {
            return Result.Err("native call returned nothing (out of memory?)")
        }
        return try {
            val json = JSONObject(raw)
            if (json.optBoolean("ok", false)) {
                Result.Ok(json.optJSONObject("data") ?: JSONObject())
            } else {
                Result.Err(json.optString("error", "unknown error"))
            }
        } catch (e: Exception) {
            Result.Err("could not parse agent response: ${e.message}")
        }
    }

    private external fun nativeStart(stateDir: String, deviceName: String, vpnService: Any): String?
    private external fun nativeStop(): String?
    private external fun nativeStatus(): String?
    private external fun nativeJoin(inviteCode: String, hostname: String): String?
    private external fun nativePeers(networkId: String): String?
    private external fun nativeUp(): String?
    private external fun nativeDown(): String?
}
