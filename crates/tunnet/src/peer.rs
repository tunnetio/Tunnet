//! Peer information from the mesh routing table.

/// A peer currently known to the local overlay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    /// Overlay IPv4 address.
    pub ip: String,
    /// Peer hostname.
    pub hostname: String,
    /// Hex-encoded endpoint id.
    pub endpoint_id: String,
    /// Tags assigned to this peer.
    pub tags: Vec<String>,
}

impl Peer {
    pub(crate) fn from_peer_info(p: &tunnet_core::PeerInfo) -> Self {
        Self {
            ip: p.ip.to_string(),
            hostname: p.hostname.clone(),
            endpoint_id: p.endpoint_hex.clone(),
            tags: p.tags.clone(),
        }
    }

    pub(crate) fn from_peer_lite(p: tunnet_core::coordinator::PeerLite) -> Self {
        Self {
            ip: p.ip,
            hostname: p.hostname,
            endpoint_id: p.endpoint_id,
            tags: p.tags,
        }
    }
}
