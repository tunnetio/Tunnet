//! Re-exported common types useful to SDK consumers.

pub use tunnet_common::policy::{self, PolicyBundle};
pub use tunnet_common::{EndpointSnapshot, NetworkMembershipSnapshot, PeerEntry};

/// Header carried on every mesh application stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamHeader {
    pub network: uuid::Uuid,
    /// Destination port requested by the dialer.
    pub dst_port: u16,
    /// Host string sent by the dialer (overlay IP, hostname, or endpoint id).
    pub host: String,
}

impl From<tunnet_core::stream::StreamHeader> for StreamHeader {
    fn from(h: tunnet_core::stream::StreamHeader) -> Self {
        Self {
            network: h.network,
            dst_port: h.dst_port,
            host: h.host,
        }
    }
}
