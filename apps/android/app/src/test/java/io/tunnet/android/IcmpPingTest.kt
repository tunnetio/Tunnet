package io.tunnet.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class IcmpPingTest {
    @Test
    fun onlyDottedIpv4IsAccepted() {
        assertTrue(IcmpPing.isIpv4("10.38.150.60"))
        assertFalse(IcmpPing.isIpv4("10.38.150.256"))
        assertFalse(IcmpPing.isIpv4("example.com"))
        assertFalse(IcmpPing.isIpv4("10.38.150.60; echo pwned"))
    }

    @Test
    fun androidPingLineYieldsLatency() {
        val out = "64 bytes from 10.38.150.60: icmp_seq=1 ttl=64 time=12.4 ms"
        val result = IcmpPing.parseOutput(out, "", 0)
        assertEquals(IcmpPing.Result.Reply(12.4), result)
    }

    @Test
    fun timeoutIsAFailure() {
        val result = IcmpPing.parseOutput("1 packets transmitted, 0 received", "", 1)
        assertTrue(result is IcmpPing.Result.Failure)
    }
}
