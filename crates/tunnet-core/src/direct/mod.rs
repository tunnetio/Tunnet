//! Direct mode: P2P mesh without a control plane.
//!
//! Membership is an [iroh-docs](https://github.com/n0-computer/iroh-docs) document
//! (one doc per network). Discovery uses Mainline DHT + invite coordinator dial.
//! Transport auth proves knowledge of the network PSK before app ALPNs are accepted.

pub mod contact;
pub mod firewall;

#[cfg(feature = "direct")]
pub mod admin;
#[cfg(feature = "direct")]
pub mod antispoof;
#[cfg(feature = "direct")]
pub mod auth;
#[cfg(all(feature = "direct", feature = "ipc"))]
pub mod connect;
#[cfg(feature = "direct")]
pub mod discovery;
#[cfg(feature = "direct")]
pub mod invite;
#[cfg(feature = "direct")]
pub mod ip;
#[cfg(feature = "direct")]
pub mod mdns;
#[cfg(feature = "direct")]
pub mod membership;
#[cfg(feature = "direct")]
pub mod policy_docs;
#[cfg(feature = "direct")]
pub mod sync;

#[cfg(feature = "direct")]
pub use admin::{PendingJoin, load_pending, push_pending, save_pending};
#[cfg(feature = "direct")]
pub use antispoof::{SpoofTracker, source_matches_peer};
#[cfg(feature = "direct")]
pub use auth::{
    AUTH_ALPN, AuthCache, DirectAuthHook, SecretResolver, run_psk_handshake_client,
    run_psk_handshake_server,
};
pub use contact::{contact_id_from_endpoint, contact_id_from_hex, is_contact_id, parse_contact_id};
#[cfg(feature = "direct")]
pub use discovery::{DiscoveryHandle, spawn_discovery, spawn_seed_auth, topic_from_name_secret};
pub use firewall::{
    EvalResult, FirewallConfig, FirewallEngine, FirewallRule, FirewallStats, PacketDirection,
    default_firewall, firewall_to_policy,
};
#[cfg(feature = "direct")]
pub use invite::{InviteCode, decode_invite, encode_invite};
#[cfg(feature = "direct")]
pub use ip::{derive_ipv4, direct_cgnat, network_id_from_topic};
#[cfg(feature = "direct")]
pub use mdns::apply_mdns;
#[cfg(feature = "direct")]
pub use membership::{
    DocsBootstrap, DocsMembership, MembershipEntry, load_approved, save_approved,
};
#[cfg(feature = "direct")]
pub use policy_docs::{PendingSuggestion, SuggestedPolicy};

/// ALPNs used by Direct membership (iroh-docs + its gossip transport).
#[cfg(feature = "direct")]
pub const DOCS_ALPN: &[u8] = iroh_docs::ALPN;
#[cfg(feature = "direct")]
pub const GOSSIP_ALPN: &[u8] = iroh_gossip::ALPN;
