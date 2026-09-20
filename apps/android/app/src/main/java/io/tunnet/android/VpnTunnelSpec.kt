package io.tunnet.android

/**
 * Validated `VpnService.Builder` inputs. The host applies this mechanically;
 * it does not invent mesh addresses or routes.
 */
sealed class VpnTunnelSpec {
    data class Ready(
        val addresses: List<Pair<String, Int>>,
        val routes: List<Pair<String, Int>>,
        val dns: List<String>,
        val mtu: Int,
        val allowIpv6Passthrough: Boolean,
        val inheritUnderlyingMetered: Boolean,
    ) : VpnTunnelSpec()

    data class Invalid(val reason: String) : VpnTunnelSpec()

    companion object {
        fun parse(
            addrs: Array<String>,
            routes: Array<String>,
            dns: Array<String>,
            mtu: Int,
            allowIpv6Passthrough: Boolean,
            inheritUnderlyingMetered: Boolean,
        ): VpnTunnelSpec {
            if (addrs.isEmpty()) {
                return Invalid("no tunnel address supplied")
            }
            if (routes.isEmpty()) {
                return Invalid("no routes supplied; refusing a tunnel that captures nothing")
            }
            if (mtu !in 576..9000) {
                return Invalid("mtu $mtu is outside 576..9000")
            }

            val addresses = ArrayList<Pair<String, Int>>(addrs.size)
            for (addr in addrs) {
                val ip = parseIpv4(addr) ?: return Invalid("invalid tunnel address: $addr")
                addresses.add(ip to 32)
            }

            val parsedRoutes = ArrayList<Pair<String, Int>>(routes.size)
            for (route in routes) {
                parsedRoutes.add(parseCidr(route) ?: return Invalid("invalid route: $route"))
            }

            val servers = ArrayList<String>(dns.size)
            for (server in dns) {
                servers.add(parseIpv4(server) ?: return Invalid("invalid dns server: $server"))
            }

            return Ready(
                addresses = addresses,
                routes = parsedRoutes,
                dns = servers,
                mtu = mtu,
                allowIpv6Passthrough = allowIpv6Passthrough,
                inheritUnderlyingMetered = inheritUnderlyingMetered,
            )
        }

        internal fun parseIpv4(text: String): String? {
            val octets = text.split(".").mapNotNull { it.toIntOrNull() }
            if (octets.size != 4 || octets.any { it !in 0..255 }) return null
            return octets.joinToString(".")
        }

        internal fun parseCidr(cidr: String): Pair<String, Int>? {
            val parts = cidr.split("/")
            if (parts.size != 2) return null
            val prefix = parts[1].toIntOrNull() ?: return null
            if (prefix !in 1..32) return null
            val ip = parseIpv4(parts[0]) ?: return null
            val octets = ip.split(".").map { it.toInt() }
            val value = (octets[0] shl 24) or (octets[1] shl 16) or (octets[2] shl 8) or octets[3]
            val mask = if (prefix == 0) 0 else (-1 shl (32 - prefix))
            val network = value and mask
            val text = "${(network ushr 24) and 0xFF}.${(network ushr 16) and 0xFF}." +
                "${(network ushr 8) and 0xFF}.${network and 0xFF}"
            return text to prefix
        }
    }
}
