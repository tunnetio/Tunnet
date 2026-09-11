//! Tunnet QUIC transport profile for the mesh DATAGRAM dataplane.
//!
//! Built from [`iroh::endpoint::QuicTransportConfig::builder`] so Iroh keeps
//! its NAT traversal, multipath, and path defaults. Only DATAGRAM buffer sizes
//! are overridden: noq's 1 MiB send default is about 100 ms of serialized data
//! on an ~80 Mbps path, which is far too much standing queue for a VPN.

use iroh::endpoint::QuicTransportConfig;

/// Outgoing DATAGRAM staging. 64 KiB is tens of 1280-byte packets, not a
/// second of bufferbloat.
pub const DATAGRAM_SEND_BUFFER: usize = 64 * 1024;

/// Incoming DATAGRAM staging. Larger than send so a burst from a peer is not
/// dropped before the peer worker can drain it.
pub const DATAGRAM_RECEIVE_BUFFER: usize = 256 * 1024;

/// QUIC transport used by every Tunnet agent endpoint.
pub fn tunnet_quic_transport() -> QuicTransportConfig {
    QuicTransportConfig::builder()
        .datagram_send_buffer_size(DATAGRAM_SEND_BUFFER)
        .datagram_receive_buffer_size(Some(DATAGRAM_RECEIVE_BUFFER))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_buffer_is_64kib() {
        assert_eq!(DATAGRAM_SEND_BUFFER, 64 * 1024);
    }

    #[test]
    fn receive_buffer_is_256kib() {
        assert_eq!(DATAGRAM_RECEIVE_BUFFER, 256 * 1024);
    }

    #[test]
    fn builder_succeeds() {
        let _ = tunnet_quic_transport();
    }
}
