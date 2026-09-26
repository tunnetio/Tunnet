package io.tunnet.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VpnTunnelSpecTest {
    private fun parse(
        addrs: Array<String>,
        routes: Array<String>,
        dns: Array<String> = emptyArray(),
        mtu: Int = 1280,
        allowIpv6Passthrough: Boolean = true,
        inheritUnderlyingMetered: Boolean = true,
    ) = VpnTunnelSpec.parse(
        addrs,
        routes,
        dns,
        mtu,
        allowIpv6Passthrough,
        inheritUnderlyingMetered,
    )

    @Test
    fun validRequestIsAppliedMechanically() {
        val spec = parse(
            addrs = arrayOf("10.1.2.3"),
            routes = arrayOf("10.1.0.0/16"),
        )
        assertTrue(spec is VpnTunnelSpec.Ready)
        val ready = spec as VpnTunnelSpec.Ready
        assertEquals(listOf("10.1.2.3" to 32), ready.addresses)
        assertEquals(listOf("10.1.0.0" to 16), ready.routes)
        assertTrue(ready.dns.isEmpty())
        assertEquals(1280, ready.mtu)
        assertTrue(ready.allowIpv6Passthrough)
        assertTrue(ready.inheritUnderlyingMetered)
    }

    @Test
    fun hostAppliesFrameworkFlagsMechanically() {
        val spec = parse(
            addrs = arrayOf("10.1.2.3"),
            routes = arrayOf("10.1.0.0/16"),
            allowIpv6Passthrough = false,
            inheritUnderlyingMetered = false,
        ) as VpnTunnelSpec.Ready
        assertFalse(spec.allowIpv6Passthrough)
        assertFalse(spec.inheritUnderlyingMetered)
    }

    @Test
    fun hostBitsInARouteAreNormalizedNotInvented() {
        val spec = parse(
            addrs = arrayOf("10.9.0.1"),
            routes = arrayOf("10.9.4.5/16"),
        ) as VpnTunnelSpec.Ready
        assertEquals(listOf("10.9.0.0" to 16), spec.routes)
    }

    @Test
    fun emptyAddressesAreRejected() {
        val spec = parse(
            addrs = emptyArray(),
            routes = arrayOf("10.1.0.0/16"),
        )
        assertTrue(spec is VpnTunnelSpec.Invalid)
    }

    @Test
    fun emptyRoutesAreRejected() {
        val spec = parse(
            addrs = arrayOf("10.1.2.3"),
            routes = emptyArray(),
        )
        assertTrue(spec is VpnTunnelSpec.Invalid)
    }

    @Test
    fun unparseableRouteFailsTheWholeRequest() {
        val spec = parse(
            addrs = arrayOf("10.1.2.3"),
            routes = arrayOf("10.1.0.0/16", "not-a-cidr"),
        )
        assertTrue(spec is VpnTunnelSpec.Invalid)
    }

    @Test
    fun invalidAddressFails() {
        val spec = parse(
            addrs = arrayOf("fe80::1"),
            routes = arrayOf("10.1.0.0/16"),
        )
        assertTrue(spec is VpnTunnelSpec.Invalid)
    }

    @Test
    fun invalidMtuFails() {
        val spec = parse(
            addrs = arrayOf("10.1.2.3"),
            routes = arrayOf("10.1.0.0/16"),
            mtu = 0,
        )
        assertTrue(spec is VpnTunnelSpec.Invalid)
    }

    @Test
    fun defaultRouteIsRejected() {
        val spec = parse(
            addrs = arrayOf("10.1.2.3"),
            routes = arrayOf("0.0.0.0/0"),
        )
        assertTrue(spec is VpnTunnelSpec.Invalid)
    }

    @Test
    fun publicUnderlayIsNotCapturedByMeshRoutes() {
        val spec = parse(
            addrs = arrayOf("10.38.150.60"),
            routes = arrayOf("10.38.0.0/16", "192.0.2.53/32"),
            dns = arrayOf("192.0.2.53"),
        ) as VpnTunnelSpec.Ready
        assertFalse(spec.routes.any { it.second == 0 })
        val captured = spec.routes.map { (ip, prefix) -> "$ip/$prefix" }
        assertTrue(captured.contains("10.38.0.0/16"))
        assertTrue(captured.contains("192.0.2.53/32"))
        assertFalse(spec.routes.any { (ip, prefix) ->
            containsIpv4(ip, prefix, "1.1.1.1") || containsIpv4(ip, prefix, "192.168.1.20")
        })
    }

    @Test
    fun meshDnsServerIsAppliedMechanically() {
        val spec = parse(
            addrs = arrayOf("10.1.2.3"),
            routes = arrayOf("10.1.0.0/16", "192.0.2.53/32"),
            dns = arrayOf("192.0.2.53"),
        )
        assertTrue(spec is VpnTunnelSpec.Ready)
        val ready = spec as VpnTunnelSpec.Ready
        assertEquals(listOf("192.0.2.53"), ready.dns)
        assertTrue(ready.routes.contains("192.0.2.53" to 32))
    }

    @Test
    fun invalidDnsServerFailsTheWholeRequest() {
        val spec = parse(
            addrs = arrayOf("10.1.2.3"),
            routes = arrayOf("10.1.0.0/16"),
            dns = arrayOf("not-an-ip"),
        )
        assertTrue(spec is VpnTunnelSpec.Invalid)
    }

    @Test
    fun hostDoesNotInventADnsServer() {
        val spec = parse(
            addrs = arrayOf("10.1.2.3"),
            routes = arrayOf("10.1.0.0/16"),
        ) as VpnTunnelSpec.Ready
        assertTrue(spec.dns.isEmpty())
    }

    private fun containsIpv4(network: String, prefix: Int, ip: String): Boolean {
        val parsed = VpnTunnelSpec.parseCidr("$network/$prefix") ?: return false
        val route = parsed.first.split(".").map { it.toInt() }
        val addr = ip.split(".").map { it.toInt() }
        val routeVal = (route[0] shl 24) or (route[1] shl 16) or (route[2] shl 8) or route[3]
        val ipVal = (addr[0] shl 24) or (addr[1] shl 16) or (addr[2] shl 8) or addr[3]
        val mask = if (prefix == 0) 0 else (-1 shl (32 - prefix))
        return (routeVal and mask) == (ipVal and mask)
    }
}
