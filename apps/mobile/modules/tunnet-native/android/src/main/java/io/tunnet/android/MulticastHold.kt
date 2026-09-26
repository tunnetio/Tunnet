package io.tunnet.android

/**
 * Whether the host should hold Wi-Fi multicast capability.
 *
 * [demand] is a Rust discovery fact. LAN permission and Wi-Fi presence are
 * platform facts. This does not interpret mDNS/LAN policy flags.
 */
object MulticastHold {
    fun shouldHold(demand: Boolean, lanPermitted: Boolean, wifiPresent: Boolean): Boolean =
        demand && lanPermitted && wifiPresent
}
