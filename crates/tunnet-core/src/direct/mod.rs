//! Direct mode: P2P mesh without a control plane.
//!
//! Membership is an [iroh-docs](https://github.com/n0-computer/iroh-docs) document
//! (one doc per network). Discovery uses invite coordinator dial + membership gossip.
//! Transport auth uses signed grants or invite bootstrap before app ALPNs are accepted.

pub mod contact;
pub mod firewall;

#[cfg(feature = "direct")]
pub mod admin;
#[cfg(feature = "direct")]
pub mod antispoof;
#[cfg(feature = "direct")]
pub mod auth;
#[cfg(all(feature = "direct", feature = "local_api"))]
pub mod connect;
#[cfg(any(feature = "direct", feature = "managed"))]
pub mod connectivity;
#[cfg(feature = "direct")]
pub mod discovery;
#[cfg(feature = "direct")]
pub mod grants;
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
pub mod presence;
#[cfg(feature = "direct")]
pub mod sync;

#[cfg(feature = "direct")]
pub use admin::{PendingJoin, load_pending, push_pending, save_pending};
#[cfg(feature = "direct")]
pub use antispoof::{SpoofTracker, source_matches_peer};
#[cfg(feature = "direct")]
pub use auth::{
    AUTH_ALPN, AuthCache, AuthClientMode, AuthServerContext, DirectAuthHook,
    SharedAuthServerContext, build_auth_server_context, run_auth_client, run_auth_server,
};
#[cfg(any(feature = "direct", feature = "managed"))]
pub use connectivity::{
    ConnectivityOptions, ConnectivityProfile, apply_connectivity, endpoint_builder,
    relay_map_from_configs,
};
pub use contact::{contact_id_from_endpoint, contact_id_from_hex, is_contact_id, parse_contact_id};
#[cfg(feature = "direct")]
pub use discovery::{DiscoveryHandle, spawn_discovery, spawn_seed_auth, topic_from_name_secret};
pub use firewall::{
    FirewallConfig, FirewallEngine, FirewallRule, FirewallStats, default_firewall,
    firewall_to_policy,
};
#[cfg(feature = "direct")]
pub use grants::{
    EpochRecord, Genesis, MemberRole, NetworkGrant, Revocation, SignedMemberRecord,
    decrypt_content, encrypt_content, generate_coordinator_keypair, grant_expiry, sign_epoch,
    sign_genesis, sign_grant, sign_member_record, sign_revocation, signing_key_from_hex,
    verify_epoch, verify_genesis, verify_grant, verify_member_record, verify_revocation,
    verifying_key_from_hex,
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
pub use policy_docs::{
    POLICY_BUNDLE_KEY, PendingSuggestion, PolicyBundleDoc, SuggestedPolicy, effective_suggested,
    sign_policy_bundle, verify_policy_bundle,
};
#[cfg(feature = "direct")]
pub use presence::{
    PRESENCE_PUBLISH_INTERVAL, PRESENCE_TTL, PresenceBeacon, PresenceConfig, PresenceHandle,
    PresenceTable, build_beacon, sign_beacon, spawn_presence, verify_beacon,
};

/// ALPNs used by Direct membership (iroh-docs + its gossip transport).
#[cfg(feature = "direct")]
pub const DOCS_ALPN: &[u8] = iroh_docs::ALPN;
#[cfg(feature = "direct")]
pub const GOSSIP_ALPN: &[u8] = iroh_gossip::ALPN;
