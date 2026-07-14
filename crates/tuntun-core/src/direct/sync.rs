//! Direct-mode sync helpers (join signalling over AUTH; membership via iroh-docs).

use serde::{Deserialize, Serialize};

/// Lightweight messages still used for join handshake / upgrade notices.
/// Membership itself is synchronized by iroh-docs, not these gossip payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DirectSignalMsg {
    JoinRequest {
        endpoint_id: String,
        hostname: String,
        ipv4: String,
        collision_index: u8,
        invite_id: Option<String>,
    },
    JoinResponse {
        accepted: bool,
        reason: Option<String>,
        ipv4: Option<String>,
        collision_index: Option<u8>,
        /// Write-capable DocTicket (string) for iroh-docs membership.
        doc_ticket: Option<String>,
    },
    UpgradeToManaged {
        control_url: String,
        enrollment_token: String,
        network_id: String,
    },
}
