//! Direct mode: P2P mesh without a control plane.

pub mod contact;
pub mod firewall;

pub mod addrplan;
pub mod grants;

#[cfg(feature = "direct")]
pub mod admin;
#[cfg(feature = "direct")]
pub mod antispoof;
#[cfg(feature = "direct")]
pub mod auth;
#[cfg(feature = "direct")]
pub mod authority;
#[cfg(all(feature = "direct", feature = "local_api"))]
pub mod connect;
#[cfg(any(feature = "direct", feature = "managed"))]
pub mod connectivity;
#[cfg(feature = "direct")]
pub mod discovery;
#[cfg(feature = "direct")]
pub mod invite;
#[cfg(feature = "direct")]
pub mod ip;
#[cfg(feature = "direct")]
pub mod join;
#[cfg(feature = "direct")]
pub mod mdns;
#[cfg(feature = "direct")]
pub mod membership;
#[cfg(feature = "direct")]
pub mod policy_docs;
#[cfg(feature = "direct")]
pub mod presence;
pub mod relay_policy;

pub use addrplan::{
    AddressPlan, AddressPlanError, ConflictCategory, NetworkConflict, allocate_peer_ip,
    detect_conflicts, is_usable_host, select_peer_cidr, usable_host_count, validate_member_ip,
    validate_peer_cidr,
};
#[cfg(feature = "direct")]
pub use admin::queue_kick;
#[cfg(feature = "direct")]
pub use antispoof::{SpoofTracker, source_matches_peer};
#[cfg(feature = "direct")]
pub use auth::{
    AUTH_ALPN, AuthCache, AuthServerContext, DirectAuthHook, SharedAuthServerContext,
    build_auth_server_context, run_auth_client, run_auth_server,
};
#[cfg(feature = "direct")]
pub use authority::{DirectAuthority, JoinDecision, JoinSnapshot, PendingJoin};
#[cfg(any(feature = "direct", feature = "managed"))]
pub use connectivity::{
    ConnectivityOptions, apply_connectivity, endpoint_builder, relay_auth_denied_detail,
    relay_map_from_configs, relay_uses_n0_preset,
};
pub use contact::{contact_id_from_endpoint, contact_id_from_hex, is_contact_id, parse_contact_id};
#[cfg(feature = "direct")]
pub use discovery::{DiscoveryHandle, spawn_discovery, spawn_seed_auth, topic_from_name_secret};
pub use firewall::{
    EvalResult, FirewallConfig, FirewallEngine, FirewallRule, FirewallStats, PacketDirection,
    default_firewall, firewall_to_policy,
};
pub use grants::{
    EpochRecord, GENESIS_SCHEMA_VERSION, Genesis, MEMBER_SCHEMA_VERSION, MemberRole, NetworkGrant,
    Revocation, SignedMemberRecord, decrypt_content, encrypt_content, generate_coordinator_keypair,
    grant_expiry, sign_epoch, sign_genesis, sign_grant, sign_member_record, sign_revocation,
    signing_key_from_hex, validate_member_against_genesis, validate_membership_set, verify_epoch,
    verify_genesis, verify_grant, verify_member_record, verify_revocation, verifying_key_from_hex,
};
#[cfg(feature = "direct")]
pub use invite::{InviteCode, decode_invite, encode_invite};
#[cfg(feature = "direct")]
pub use ip::network_id_from_topic;
#[cfg(feature = "direct")]
pub use join::{
    JOIN_ALPN, JoinAdmission, JoinPublisher, JoinRequest, JoinResponse, JoinStatus,
    decode_and_preflight, preflight_invite, run_join_client, run_join_server,
    run_join_server_dispatch, verify_admission,
};
#[cfg(feature = "direct")]
pub use mdns::apply_mdns;
#[cfg(feature = "direct")]
pub use membership::{DocsBootstrap, DocsMembership, MembershipEntry};
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
pub use relay_policy::{
    DirectRelayInput, DirectRelayMode, EffectiveRelayPolicy, RelayResolveError,
    resolve_direct_relay_policy, resolve_managed_relay_policy,
};

/// ALPNs used by Direct membership (iroh-docs + its gossip transport).
#[cfg(feature = "direct")]
pub const DOCS_ALPN: &[u8] = iroh_docs::ALPN;
#[cfg(feature = "direct")]
pub const GOSSIP_ALPN: &[u8] = iroh_gossip::ALPN;
/// Dedicated Direct connect protocol (not AUTH).
#[cfg(feature = "direct")]
pub const CONNECT_ALPN: &[u8] = b"tunnet/direct-connect/1";
