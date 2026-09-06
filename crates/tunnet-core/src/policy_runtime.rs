//! Unified compiled packet policy: one flow key, one conntrack, one verdict.
//!
//! Consolidates the overlapping ACL + Direct-firewall packet work into a
//! single hot path:
//!
//! ```text
//! not fragmented → L4 from PacketMeta (no fragment lock)
//! fragmented    → fragment slow path (fail-closed without first-fragment state)
//! established   → single canonical conntrack lookup → Allow
//! new flow      → compiled ACL phases + compiled firewall rules → verdict
//! ```
//!
//! Policy is compiled at configuration time (pre-sorted phases, merged port
//! intervals, lowercased selector keys, integer endpoint ids where possible).
//! The hot path allocates nothing, sorts nothing, and formats no strings
//! (notably no `format!("user:{id}")` per packet).

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use parking_lot::Mutex;
use tunnet_common::packet::{
    CachedTransport, FragKey, FragmentTable, PacketMeta, ResolvedL4, TcpFlags, Transport,
};
use tunnet_common::policy::{
    Action, DefaultAction, Direction, IcmpPolicy, PolicyBundle, Protocol, RuleScope, Selector,
};
use uuid::Uuid;

use crate::direct::firewall::FirewallRule;

// Reuse TTLs from the established engines.
const TCP_ACTIVE_TTL: Duration = Duration::from_secs(300);
const TCP_TIME_WAIT_TTL: Duration = Duration::from_secs(10);
const UDP_TTL: Duration = Duration::from_secs(30);
const ICMP_TTL: Duration = Duration::from_secs(10);

/// Canonical bidirectional conntrack key: one lookup in the common case.
/// Network-scoped (§2.2-1): the same 5-tuple in two networks is two flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct CanonKey {
    net: Uuid,
    proto: u8,
    a: Ipv4Addr,
    aport: u16,
    b: Ipv4Addr,
    bport: u16,
}

fn proto_num(p: Protocol) -> Option<u8> {
    match p {
        Protocol::Tcp => Some(6),
        Protocol::Udp => Some(17),
        Protocol::Icmp => Some(1),
        Protocol::Icmpv6 => Some(58),
        Protocol::Other(n) => Some(n),
        Protocol::Any => None,
    }
}

fn canon_key(
    net: Uuid,
    proto: Protocol,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: Option<u16>,
    dport: Option<u16>,
) -> Option<CanonKey> {
    let num = proto_num(proto)?;
    if num == 1 {
        // ICMP: direction-independent, keyed by sorted endpoints + echo id.
        let id = sport.or(dport).unwrap_or(0);
        let (a, b) = if src <= dst { (src, dst) } else { (dst, src) };
        return Some(CanonKey {
            net,
            proto: num,
            a,
            aport: id,
            b,
            bport: 0,
        });
    }
    let (a, aport, b, bport) = if (src, sport.unwrap_or(0)) <= (dst, dport.unwrap_or(0)) {
        (src, sport.unwrap_or(0), dst, dport.unwrap_or(0))
    } else {
        (dst, dport.unwrap_or(0), src, sport.unwrap_or(0))
    };
    Some(CanonKey {
        net,
        proto: num,
        a,
        aport,
        b,
        bport,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpPhase {
    SynSent,
    Established,
    TimeWait,
}

#[derive(Debug, Clone, Copy)]
enum Phase {
    Tcp(TcpPhase),
    Udp,
    Icmp,
}

#[derive(Debug, Clone, Copy)]
struct FlowState {
    phase: Phase,
    last_seen: Instant,
    /// Generations that admitted this flow (§0.4, §2.2-2): the ACL snapshot
    /// generation AND the firewall snapshot generation that decided. ANY
    /// mismatch revalidates — an old firewall can never be trusted under a
    /// new generation.
    admitted_acl_gen: u64,
    admitted_fw_gen: u64,
    /// Expiry-wheel token: bumped whenever a new heap node is pushed.
    seq: u64,
    /// Millis timestamp of the last heap node push (throttles refresh churn).
    heap_ms: u64,
}

fn ttl_of(s: &FlowState) -> Duration {
    match s.phase {
        Phase::Tcp(TcpPhase::TimeWait) => TCP_TIME_WAIT_TTL,
        Phase::Tcp(_) => TCP_ACTIVE_TTL,
        Phase::Udp => UDP_TTL,
        Phase::Icmp => ICMP_TTL,
    }
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Amortized expiry wheel (§14): 16 independent shards, no global lock.
/// Each packet-path call pops at most [`REAP_BUDGET`] expired nodes from the
/// single shard selected by its flow key — O(1) amortized, never a full-map
/// retain on the hot path. Stale nodes (superseded `seq`) are skipped; a
/// background task performs the rare heap rebuilds.
const EXPIRY_SHARDS: usize = 16;
const REAP_BUDGET: usize = 4;

#[derive(Debug, Default)]
struct ExpiryWheel {
    shards: [Mutex<std::collections::BinaryHeap<ExpiryNode>>; EXPIRY_SHARDS],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExpiryNode {
    expires_ms: u64,
    seq: u64,
    key: CanonKey,
}

impl PartialOrd for ExpiryNode {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ExpiryNode {
    // Reversed: BinaryHeap is a max-heap; earliest expiry pops first.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other
            .expires_ms
            .cmp(&self.expires_ms)
            .then_with(|| other.seq.cmp(&self.seq))
    }
}

impl ExpiryWheel {
    fn shard(key: &CanonKey) -> usize {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut h);
        (h.finish() as usize) % EXPIRY_SHARDS
    }

    fn push(&self, key: CanonKey, expires_ms: u64, seq: u64) {
        self.shards[Self::shard(&key)].lock().push(ExpiryNode {
            expires_ms,
            seq,
            key,
        });
    }

    /// Pop up to `REAP_BUDGET` expired nodes for one shard; the caller
    /// validates each against live state (missing / seq-mismatch / refreshed
    /// entries are simply skipped).
    fn reap_shard(&self, shard: usize, now_ms: u64, mut consume: impl FnMut(CanonKey, u64)) {
        let mut heap = self.shards[shard].lock();
        for _ in 0..REAP_BUDGET {
            let Some(top) = heap.peek() else { break };
            if top.expires_ms > now_ms {
                break;
            }
            let node = *top;
            heap.pop();
            consume(node.key, node.seq);
        }
    }

    fn clear(&self) {
        for s in &self.shards {
            s.lock().clear();
        }
    }
}

/// Precompiled selector: no per-packet allocation or case folding.
#[derive(Debug, Clone)]
enum Sel {
    Any,
    Endpoint(Box<str>),
    Tag(Box<str>),
    Network(Box<str>),
    Cidr(ipnet::IpNet),
    User { id: Box<str>, marker: Box<str> },
}

impl Sel {
    fn compile(s: &Selector) -> Self {
        match s {
            Selector::Any => Self::Any,
            Selector::Endpoint(id) => Self::Endpoint(id.to_ascii_lowercase().into()),
            Selector::Tag(t) => Self::Tag(t.clone().into()),
            Selector::Network(n) => Self::Network(n.clone().into()),
            Selector::Cidr(net) => Self::Cidr(*net),
            Selector::User(id) => {
                let lower = id.to_ascii_lowercase();
                Self::User {
                    marker: format!("user:{id}").into(),
                    id: lower.into(),
                }
            }
        }
    }

    fn matches(
        &self,
        endpoint_hex: &str,
        tags: &[String],
        network: &str,
        ip: Option<Ipv4Addr>,
    ) -> bool {
        match self {
            Self::Any => true,
            Self::Endpoint(id) => id.as_ref().eq_ignore_ascii_case(endpoint_hex),
            Self::Tag(t) => tags.iter().any(|x| x.as_str() == t.as_ref()),
            Self::Network(n) => n.as_ref() == network,
            Self::Cidr(net) => ip.is_some_and(|ip| net.contains(&std::net::IpAddr::V4(ip))),
            Self::User { id, marker } => tags
                .iter()
                .any(|x| x.as_str() == marker.as_ref() || x.eq_ignore_ascii_case(id)),
        }
    }
}

#[derive(Debug, Clone)]
struct CompiledRule {
    src: Sel,
    dst: Sel,
    action: Action,
    order_index: i32,
    priority: i32,
    protocol: Option<Protocol>,
    /// Merged, sorted, non-overlapping port intervals. Empty = any.
    ports: Vec<(u16, u16)>,
    has_posture: bool,
}

impl CompiledRule {
    fn port_hit(&self, port: Option<u16>) -> bool {
        if self.ports.is_empty() {
            return true;
        }
        let Some(p) = port else { return false };
        self.ports.iter().any(|(a, b)| p >= *a && p <= *b)
    }
}

fn compile_ports(r: &tunnet_common::policy::PolicyRule) -> Vec<(u16, u16)> {
    let mut v: Vec<(u16, u16)> = r.ports.iter().map(|p| (p.start, p.end)).collect();
    if v.is_empty() {
        return v;
    }
    v.sort();
    let mut out = Vec::with_capacity(v.len());
    let mut cur = v[0];
    for (a, b) in v.into_iter().skip(1) {
        if a <= cur.1.saturating_add(1) {
            cur.1 = cur.1.max(b);
        } else {
            out.push(cur);
            cur = (a, b);
        }
    }
    out.push(cur);
    out
}

/// Allocation-free compiled ACL snapshot.
#[derive(Debug)]
pub struct CompiledAcl {
    org_deny: Vec<CompiledRule>,
    net_deny: Vec<CompiledRule>,
    net_allow: Vec<CompiledRule>,
    default_action: DefaultAction,
    icmp_policy: IcmpPolicy,
}

impl CompiledAcl {
    pub fn compile(bundle: &PolicyBundle) -> Self {
        let mut org_deny = Vec::new();
        let mut net_deny = Vec::new();
        let mut net_allow = Vec::new();
        for r in &bundle.rules {
            if !r.enabled {
                continue;
            }
            let c = CompiledRule {
                src: Sel::compile(&r.src),
                dst: Sel::compile(&r.dst),
                action: r.action,
                order_index: r.order_index,
                priority: r.priority,
                protocol: r.protocol,
                ports: compile_ports(r),
                has_posture: !r.src_posture.is_empty(),
            };
            match (r.scope, r.action) {
                (RuleScope::Organization, Action::Deny) => org_deny.push(c),
                (RuleScope::Network, Action::Deny) => net_deny.push(c),
                (RuleScope::Network, Action::Allow) => net_allow.push(c),
                _ => {}
            }
        }
        for v in [&mut org_deny, &mut net_deny, &mut net_allow] {
            v.sort_by(|a, b| {
                a.order_index
                    .cmp(&b.order_index)
                    .then_with(|| a.priority.cmp(&b.priority))
            });
        }
        Self {
            org_deny,
            net_deny,
            net_allow,
            default_action: bundle.default_action,
            icmp_policy: bundle.icmp_policy,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn verdict(
        &self,
        protocol: Protocol,
        self_hex: &str,
        self_ip: Ipv4Addr,
        self_tags: &[String],
        self_net: &str,
        peer_hex: &str,
        peer_ip: Option<Ipv4Addr>,
        peer_tags: &[String],
        dst_port: Option<u16>,
        direction: Direction,
        src_posture_ok: bool,
    ) -> Action {
        if protocol == Protocol::Icmp {
            match self.icmp_policy {
                IcmpPolicy::Allow => return Action::Allow,
                IcmpPolicy::Deny => return Action::Deny,
                IcmpPolicy::Acl => {}
            }
        }
        // Three ordered phases: org deny, network deny, network allow.
        // First hit in a phase wins; deny phases precede the allow phase.
        let mut posture_skip = false;
        for phase_rules in [&self.org_deny, &self.net_deny, &self.net_allow] {
            for rule in phase_rules.iter() {
                if !rule_hit(
                    rule, protocol, self_hex, self_ip, self_tags, self_net, peer_hex, peer_ip,
                    peer_tags, dst_port, direction,
                ) {
                    continue;
                }
                if rule.has_posture && !src_posture_ok {
                    posture_skip = true;
                    continue;
                }
                return rule.action;
            }
        }
        let _ = posture_skip;
        self.default_action.into()
    }

    /// True when the bundle carries no rules (fail-open outage analysis).
    pub fn is_empty_open(&self) -> bool {
        self.org_deny.is_empty() && self.net_deny.is_empty() && self.net_allow.is_empty()
    }

    pub fn default_is_allow(&self) -> bool {
        matches!(self.default_action, DefaultAction::Allow)
    }
}

#[allow(clippy::too_many_arguments)]
fn rule_hit(
    r: &CompiledRule,
    protocol: Protocol,
    self_hex: &str,
    self_ip: Ipv4Addr,
    self_tags: &[String],
    self_net: &str,
    peer_hex: &str,
    peer_ip: Option<Ipv4Addr>,
    peer_tags: &[String],
    dst_port: Option<u16>,
    direction: Direction,
) -> bool {
    if !protocol.matches_rule(r.protocol) {
        return false;
    }
    if protocol.is_icmp() {
        // port-restricted rules still match ICMP (matches legacy semantics)
    } else if matches!(protocol, Protocol::Other(_)) {
        if !r.ports.is_empty() {
            return false;
        }
    } else if !r.port_hit(dst_port) {
        return false;
    }
    let (src_ok, dst_ok) = match direction {
        Direction::Inbound => (
            r.src.matches(peer_hex, peer_tags, self_net, peer_ip),
            r.dst.matches(self_hex, self_tags, self_net, Some(self_ip)),
        ),
        Direction::Outbound => (
            r.src.matches(self_hex, self_tags, self_net, Some(self_ip)),
            r.dst.matches(peer_hex, peer_tags, self_net, peer_ip),
        ),
    };
    // Note: peer_network uses self_net, matching legacy AclEngine behavior
    // (peer network context was the local network name).
    src_ok && dst_ok
}

/// Compiled local-firewall rule (direction + action + proto + ports + peer).
#[derive(Debug, Clone)]
pub struct CompiledFwRule {
    pub inbound: bool,
    pub allow: bool,
    pub reject: bool,
    pub protocol: Protocol,
    pub ports: Vec<(u16, u16)>,
    pub peer_endpoint: Option<Box<str>>,
    pub peer_hostname: Option<Box<str>>,
    pub peer_network: Option<Uuid>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyVerdict {
    Allow,
    Deny,
    Reject,
}

/// Compiled firewall rule set for exactly one network (§0.2).
/// Rules from network A can never affect network B: the fast path uses the
/// set resolved into the peer's fast state, never a per-packet UUID lookup.
#[derive(Debug, Clone, Default)]
pub struct FwSet {
    pub enabled: bool,
    pub rules: Vec<CompiledFwRule>,
}

/// Per-network firewall verdict counters, fed by the runtime and read by
/// control-plane stats (legacy engines no longer see packets).
#[derive(Debug, Default)]
pub struct FwCounters {
    pub allowed: AtomicU64,
    pub denied: AtomicU64,
    pub rejected: AtomicU64,
}

/// Immutable firewall publication: ruleset + the publication generation
/// that installed it (§2.2-2). Packets always read rules and generation
/// from the same snapshot — never a torn mix.
#[derive(Debug, Clone)]
pub struct FwSnapshot {
    pub generation: u64,
    pub set: FwSet,
}

/// Stable per-network policy slot (§2.1-3, §2.2-2):
///
/// ```text
/// network → stable Arc<FwSlot> → ArcSwap<FwSnapshot> → Arc<FwCounters>
/// ```
///
/// Fast states hold the stable slot forever. Firewall publication swaps the
/// slot's snapshot atomically — existing peers observe new rules
/// immediately with no per-packet network map lookup and no registry-wide
/// peer relink. The counters object is equally stable, so control-plane
/// stats survive republishes.
pub struct FwSlot {
    pub snapshot: ArcSwap<FwSnapshot>,
    pub counters: Arc<FwCounters>,
}

impl Default for FwSlot {
    fn default() -> Self {
        Self {
            snapshot: ArcSwap::from_pointee(FwSnapshot {
                generation: 0,
                set: FwSet::default(),
            }),
            counters: Arc::new(FwCounters::default()),
        }
    }
}

/// Deny-log capacity (control-plane diagnostics, not the hot path).
pub const DENY_LOG_CAP: usize = 64;

/// Deny record for control-plane diagnostics (not the hot path).
#[derive(Debug, Clone, serde::Serialize)]
pub struct AclDenyRecord {
    pub peer_endpoint: String,
    pub dst_port: Option<u16>,
    pub protocol: String,
    pub reason: String,
    pub rule_slug: Option<String>,
    pub scope: Option<String>,
    pub at_unix: i64,
}

/// One dataplane-generation-owned packet-policy runtime (§0.1).
///
/// A single `PolicyRuntime` is shared by outbound processing and every
/// inbound connection: one canonical conntrack, one fragment table, one
/// verdict. Snapshots compile off the packet path and publish with ONE
/// atomic store (§2.1-4): the generation lives INSIDE the immutable
/// snapshot, so a packet can never observe new policy with an old
/// generation (no torn publication). Conntrack entries carry the admitting
/// generations (taken from the same snapshots) and revalidate on mismatch.
///
/// Publication model (§2.2-2): one unified `publication` token is bumped
/// per publish; the ACL snapshot AND every touched firewall snapshot carry
/// the new token. Publish order is always firewall-slot-swap first, ACL
/// snapshot second; packets load ACL first, firewall second. By the SeqCst
/// total order, observing the new ACL generation implies observing the new
/// firewall snapshot — the (new ACL, old firewall) poison pair is
/// impossible. Conntrack admission stamps exactly the pair that decided.
#[derive(Clone)]
pub struct PolicyRuntime {
    inner: Arc<ArcSwap<RuntimeInner>>,
    /// Stable per-network firewall slots, shared across ALL generations:
    /// publication swaps slot contents, so every holder observes updates
    /// without relink (§2.1-3).
    slots: Arc<DashMap<Uuid, Arc<FwSlot>>>,
    /// Unified publication token (§2.2-2): bumped once per publish and
    /// stamped on the ACL snapshot and every touched firewall snapshot.
    publication: Arc<AtomicU64>,
    /// Serializes publishers (ACL, firewall, invalidate) into one atomic
    /// transaction each: load → allocate generation → compile → swap slots
    /// → store snapshot. Committed generations are strictly monotonic and
    /// no publish can clobber a concurrent one (§2.2 blocker). Control
    /// path only — the packet hot path never takes this lock.
    publish_lock: Arc<parking_lot::Mutex<()>>,
}

struct RuntimeInner {
    /// Policy generation, published atomically WITH this snapshot.
    generation: u64,
    acl: CompiledAcl,
    acl_source: PolicyBundle,
    fw_source: HashMap<Uuid, (Vec<FirewallRule>, Vec<FirewallRule>, bool)>,
    self_source: crate::acl::SelfIdentity,
    self_hex: String,
    self_ip: Ipv4Addr,
    self_tags: Vec<String>,
    self_net: String,
    src_posture_ok: bool,
    stale: bool,
    conntrack: DashMap<CanonKey, FlowState>,
    expiry: ExpiryWheel,
    fragments: Mutex<FragmentTable>,
    deny_log: Arc<Mutex<std::collections::VecDeque<AclDenyRecord>>>,
}

impl PolicyRuntime {
    /// Bootstrap a runtime from control-plane state (dataplane bring-up).
    /// `fw` maps network → (local rules, suggested rules, enabled).
    pub fn bootstrap(
        bundle: &PolicyBundle,
        fw: &HashMap<Uuid, (Vec<FirewallRule>, Vec<FirewallRule>, bool)>,
        self_id: &crate::acl::SelfIdentity,
        src_posture_ok: bool,
        stale: bool,
    ) -> Self {
        let this = Self {
            inner: Arc::new(ArcSwap::from_pointee(RuntimeInner::empty())),
            slots: Arc::new(DashMap::new()),
            publication: Arc::new(AtomicU64::new(1)),
            publish_lock: Arc::new(parking_lot::Mutex::new(())),
        };
        let inner = this.compile_new(bundle, fw, self_id, src_posture_ok, stale, None, 1);
        // No sweeper here: the dataplane actor starts exactly one per
        // generation via spawn_sweeper (tests stay task-free).
        this.inner.store(Arc::new(inner));
        this
    }

    /// Background expiry sweeper (§14): rate-limited, shard-local, never
    /// blocking packets. Each 250 ms tick reaps at most a few dozen expired
    /// nodes per shard and rebuilds a heap only when stale nodes dominate.
    /// Tied to the dataplane generation token: BringDown cancels it, so no
    /// sweeper task leaks across bring-up cycles.
    pub fn spawn_sweeper(&self, cancel: tokio_util::sync::CancellationToken) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let inner = self.inner.clone();
        handle.spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_millis(250));
            loop {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => break,
                    _ = tick.tick() => {}
                }
                // Reload every tick: republishes replace the table and the
                // sweeper must follow, never pinning a dead generation.
                let snapshot = inner.load();
                let now_ms = now_millis();
                let now = Instant::now();
                for shard in 0..EXPIRY_SHARDS {
                    let mut budget = 32;
                    while budget > 0 {
                        let node = snapshot.expiry.shards[shard].lock().pop();
                        let Some(node) = node else { break };
                        if node.expires_ms > now_ms {
                            snapshot.expiry.shards[shard].lock().push(node);
                            break;
                        }
                        budget -= 1;
                        let remove = match snapshot.conntrack.get(&node.key) {
                            Some(e) => {
                                e.seq == node.seq && now.duration_since(e.last_seen) > ttl_of(&e)
                            }
                            None => false,
                        };
                        if remove {
                            snapshot.conntrack.remove(&node.key);
                        }
                    }
                }
                // Heap hygiene: rebuild a shard when stale nodes dominate, so
                // refresh churn cannot grow memory without bound. Rare,
                // background-only, shard by shard.
                for shard in 0..EXPIRY_SHARDS {
                    let live = snapshot.conntrack.len() / EXPIRY_SHARDS + 8;
                    let mut heap = snapshot.expiry.shards[shard].lock();
                    if heap.len() > live.saturating_mul(4).max(256) {
                        let nodes: Vec<_> = heap.drain().collect();
                        drop(heap);
                        for node in nodes {
                            let keep = match snapshot.conntrack.get(&node.key) {
                                Some(e) => e.seq == node.seq,
                                None => false,
                            };
                            if keep {
                                snapshot.expiry.shards[shard].lock().push(node);
                            }
                        }
                        // One shard per tick is enough; remaining shards wait.
                        break;
                    }
                }
            }
        });
    }

    /// Current policy generation, read from the live snapshot (single
    /// atomic load — always consistent with the policy it describes).
    pub fn generation(&self) -> u64 {
        self.inner.load().generation
    }

    /// Stable firewall slot for a network (slow paths only: fast-state
    /// creation and install-time relink, never established packets).
    /// Creates a disabled default slot for unknown networks.
    pub fn slot_for_network(&self, network: Uuid) -> Arc<FwSlot> {
        self.slots
            .entry(network)
            .or_insert_with(|| Arc::new(FwSlot::default()))
            .clone()
    }

    /// Resolve the compiled firewall set for a network (slow paths only).
    pub fn fw_for_network(&self, network: Uuid) -> Arc<FwSet> {
        Arc::new(self.slot_for_network(network).snapshot.load().set.clone())
    }

    /// Counters for a network's firewall (control-plane stats surface).
    pub fn fw_counters_for(&self, network: Uuid) -> Arc<FwCounters> {
        self.slot_for_network(network).counters.clone()
    }

    pub fn recent_denies(&self) -> Vec<AclDenyRecord> {
        self.inner.load().deny_log.lock().iter().cloned().collect()
    }

    /// This node's mesh IP (for self-traffic drops and NAT).
    pub fn self_ip(&self) -> Ipv4Addr {
        self.inner.load().self_ip
    }

    pub fn conntrack_len(&self) -> usize {
        self.inner.load().conntrack.len()
    }

    pub fn publish_acl(
        &self,
        bundle: &PolicyBundle,
        self_id: &crate::acl::SelfIdentity,
        src_posture_ok: bool,
        stale: bool,
    ) -> u64 {
        let _guard = self.publish_lock.lock();
        let generation = self.publication.fetch_add(1, Ordering::SeqCst) + 1;
        let prev = self.inner.load();
        let inner = self.compile_new(
            bundle,
            &prev.fw_source,
            self_id,
            src_posture_ok,
            stale,
            Some(&prev),
            generation,
        );
        self.inner.store(Arc::new(inner));
        generation
    }

    pub fn publish_firewall(
        &self,
        network: Uuid,
        local: Vec<FirewallRule>,
        suggested: Vec<FirewallRule>,
        enabled: bool,
    ) -> u64 {
        let _guard = self.publish_lock.lock();
        let generation = self.publication.fetch_add(1, Ordering::SeqCst) + 1;
        let prev = self.inner.load();
        let mut fw_source = prev.fw_source.clone();
        fw_source.insert(network, (local, suggested, enabled));
        let inner = self.compile_new(
            &prev.acl_source,
            &fw_source,
            &prev.self_source,
            prev.src_posture_ok,
            prev.stale,
            Some(&prev),
            generation,
        );
        self.inner.store(Arc::new(inner));
        generation
    }

    pub fn invalidate(&self) -> u64 {
        let _guard = self.publish_lock.lock();
        let generation = self.publication.fetch_add(1, Ordering::SeqCst) + 1;
        let inner = self.inner.load();
        inner.conntrack.clear();
        inner.expiry.clear();
        let next = self.compile_new(
            &inner.acl_source,
            &inner.fw_source,
            &inner.self_source,
            inner.src_posture_ok,
            inner.stale,
            Some(&inner),
            generation,
        );
        self.inner.store(Arc::new(next));
        generation
    }
}

impl RuntimeInner {
    /// Placeholder before the first real compile (bootstrap only).
    fn empty() -> Self {
        Self {
            generation: 0,
            acl: CompiledAcl::compile(&PolicyBundle::default()),
            acl_source: PolicyBundle::default(),
            fw_source: HashMap::new(),
            self_source: crate::acl::SelfIdentity {
                endpoint_hex: String::new(),
                ip: Ipv4Addr::UNSPECIFIED,
                tags: vec![],
                network: String::new(),
            },
            self_hex: String::new(),
            self_ip: Ipv4Addr::UNSPECIFIED,
            self_tags: vec![],
            self_net: String::new(),
            src_posture_ok: false,
            stale: false,
            conntrack: DashMap::new(),
            expiry: ExpiryWheel::default(),
            fragments: Mutex::new(FragmentTable::default()),
            deny_log: Arc::new(Mutex::new(std::collections::VecDeque::with_capacity(
                DENY_LOG_CAP,
            ))),
        }
    }

    /// Carry the live conntrack table across a republish (entries revalidate
    /// by generation instead of being dropped).
    fn rebuild_conntrack(&self) -> DashMap<CanonKey, FlowState> {
        // Move entries without revalidating here: stale generations are
        // rechecked lazily on next hit, which spreads the cost.
        let next = DashMap::with_capacity(self.conntrack.len());
        for entry in self.conntrack.iter() {
            next.insert(*entry.key(), *entry.value());
        }
        next
    }
}

impl PolicyRuntime {
    #[allow(clippy::too_many_arguments)]
    fn compile_new(
        &self,
        bundle: &PolicyBundle,
        fw: &HashMap<Uuid, (Vec<FirewallRule>, Vec<FirewallRule>, bool)>,
        self_id: &crate::acl::SelfIdentity,
        src_posture_ok: bool,
        stale: bool,
        prev: Option<&RuntimeInner>,
        generation: u64,
    ) -> RuntimeInner {
        for (net, (local, suggested, enabled)) in fw {
            // Swap the stable slot's snapshot stamped with this publish's
            // token: every live fast state holding this slot observes the
            // new rules atomically, with no relink. Counters objects are
            // never replaced, so stats survive. This store precedes the
            // ACL snapshot store below — the packet path's load order
            // (ACL first, firewall second) depends on it (§2.2-2).
            let slot = self.slot_for_network(*net);
            slot.snapshot.store(Arc::new(FwSnapshot {
                generation,
                set: FwSet {
                    enabled: *enabled,
                    rules: compile_fw_rules(local, suggested),
                },
            }));
        }
        // Preserve shared state across republishes: conntrack entries carry
        // their admitting generation and revalidate (§0.4); the deny log
        // survives so diagnostics are not wiped by updates. Fragment state
        // is short-TTL (2 s) and starts fresh — at most a few fail-closed
        // drops of in-flight fragments.
        let (conntrack, deny_log) = match prev {
            Some(p) => (p.rebuild_conntrack(), p.deny_log.clone()),
            None => (
                DashMap::new(),
                Arc::new(Mutex::new(std::collections::VecDeque::with_capacity(
                    DENY_LOG_CAP,
                ))),
            ),
        };
        RuntimeInner {
            generation,
            acl: CompiledAcl::compile(bundle),
            acl_source: bundle.clone(),
            fw_source: fw.clone(),
            self_source: self_id.clone(),
            self_hex: self_id.endpoint_hex.clone(),
            self_ip: self_id.ip,
            self_tags: self_id.tags.clone(),
            self_net: self_id.network.clone(),
            src_posture_ok,
            stale,
            conntrack,
            expiry: ExpiryWheel::default(),
            fragments: Mutex::new(FragmentTable::default()),
            deny_log,
        }
    }
}

impl PolicyRuntime {
    /// Hot-path check. `fw_slot` is the peer's stable network slot — the
    /// snapshot is loaded INSIDE, after the ACL snapshot, matching publish
    /// order (§2.2-2). `peer_*` are cheap slices from the same fast state.
    /// No allocation, no sorting, no string formatting; unfragmented
    /// traffic never touches the fragment lock. Both generations used come
    /// from the snapshots actually evaluated — publication can never tear.
    #[allow(clippy::too_many_arguments)]
    pub fn check(
        &self,
        meta: &PacketMeta,
        direction: Direction,
        peer_hex: &str,
        peer_tags: &[String],
        peer_hostname: Option<&str>,
        peer_network: Option<Uuid>,
        fw_slot: &FwSlot,
        fw_counters: &FwCounters,
    ) -> PolicyVerdict {
        let inner = self.inner.load();
        self.check_inner(
            &inner,
            inner.generation,
            meta,
            direction,
            peer_hex,
            peer_tags,
            peer_hostname,
            peer_network,
            fw_slot,
            fw_counters,
        )
        .0
    }

    /// Check returning the snapshot generations actually used (concurrency
    /// tests pair verdicts with generations to prove atomic publication).
    #[allow(clippy::too_many_arguments)]
    pub fn check_with_generation(
        &self,
        meta: &PacketMeta,
        direction: Direction,
        peer_hex: &str,
        peer_tags: &[String],
        peer_hostname: Option<&str>,
        peer_network: Option<Uuid>,
        fw_slot: &FwSlot,
        fw_counters: &FwCounters,
    ) -> (PolicyVerdict, u64, u64) {
        let inner = self.inner.load();
        let policy_gen = inner.generation;
        let (verdict, _, fw_gen) = self.check_inner(
            &inner,
            policy_gen,
            meta,
            direction,
            peer_hex,
            peer_tags,
            peer_hostname,
            peer_network,
            fw_slot,
            fw_counters,
        );
        (verdict, policy_gen, fw_gen)
    }

    #[allow(clippy::too_many_arguments)]
    fn check_inner(
        &self,
        inner: &RuntimeInner,
        policy_gen: u64,
        meta: &PacketMeta,
        direction: Direction,
        peer_hex: &str,
        peer_tags: &[String],
        peer_hostname: Option<&str>,
        peer_network: Option<Uuid>,
        fw_slot: &FwSlot,
        fw_counters: &FwCounters,
    ) -> (PolicyVerdict, u64, u64) {
        // Load order is the protocol: ACL snapshot first, firewall snapshot
        // second — the reverse of publish order (slot swap, then ACL
        // store). Observing the new ACL generation therefore implies
        // observing the new firewall snapshot; the (new ACL, old firewall)
        // poison pair cannot occur (§2.2-2).
        let fw_snap = fw_slot.snapshot.load();
        let fw_gen = fw_snap.generation;
        let fw = &fw_snap.set;
        // Fast path: unfragmented traffic never touches the fragment lock.
        let l4: ResolvedL4 = if meta.is_later_fragment() {
            let Some(hit) = inner.fragments.lock().lookup_meta(meta) else {
                return (PolicyVerdict::Deny, policy_gen, fw_gen);
            };
            hit
        } else {
            if meta.is_fragment() {
                inner.fragments.lock().remember_meta(meta);
            }
            match ResolvedL4::from_transport(meta.transport) {
                Some(l4) => l4,
                None => return (PolicyVerdict::Deny, policy_gen, fw_gen),
            }
        };

        let (Some(src), Some(dst)) = (meta.src_v4, meta.dst_v4) else {
            return (PolicyVerdict::Deny, policy_gen, fw_gen);
        };
        let tcp_flags = l4.tcp_flags.map(|f| f.0).unwrap_or(0);
        // Conntrack is network-scoped: the membership network joins the key.
        let net = peer_network.unwrap_or(Uuid::nil());

        // Single canonical established lookup, shared both directions (§0.1).
        // Entries admitted under older generations revalidate once (§0.4,
        // §2.2-2: ANY generation mismatch — ACL or firewall — revalidates).
        if let Some(key) = canon_key(net, l4.protocol, src, dst, l4.src_port, l4.dst_port)
            && self.conntrack_allows(inner, policy_gen, fw_gen, key, direction, tcp_flags)
        {
            self.reap_for_key(inner, &key);
            return (PolicyVerdict::Allow, policy_gen, fw_gen);
        }

        let peer_ip = match direction {
            Direction::Outbound => Some(dst),
            Direction::Inbound => Some(src),
        };
        let action = inner.acl.verdict(
            l4.protocol,
            &inner.self_hex,
            inner.self_ip,
            &inner.self_tags,
            &inner.self_net,
            peer_hex,
            peer_ip,
            peer_tags,
            l4.dst_port,
            direction,
            inner.src_posture_ok,
        );
        if action == Action::Deny {
            // Fail-open only for open networks with no rules during control
            // outage (preserved legacy semantics); otherwise deny + log.
            let open_failover =
                inner.stale && inner.acl.is_empty_open() && inner.acl.default_is_allow();
            if !open_failover {
                self.record_deny(inner, peer_hex, l4.dst_port, l4.protocol);
                return (PolicyVerdict::Deny, policy_gen, fw_gen);
            }
        }

        // Network-scoped firewall second (pre-resolved set, then defaults).
        // The set already belongs to the peer's network; the NetworkId
        // filter inside rules keeps its legacy meaning against peer_network.
        if fw.enabled {
            match fw_verdict(
                &fw.rules,
                direction,
                l4,
                peer_hex,
                peer_hostname,
                peer_network,
            ) {
                Some(PolicyVerdict::Allow) => {
                    fw_counters.allowed.fetch_add(1, Ordering::Relaxed);
                }
                Some(v) => {
                    if v == PolicyVerdict::Reject {
                        fw_counters.rejected.fetch_add(1, Ordering::Relaxed);
                    } else {
                        fw_counters.denied.fetch_add(1, Ordering::Relaxed);
                    }
                    return (v, policy_gen, fw_gen);
                }
                None => {
                    // Built-in defaults: outbound allow; inbound from a known
                    // peer allow; inbound without peer identity: ICMP echo.
                    let allowed = match direction {
                        Direction::Outbound => true,
                        Direction::Inbound => {
                            if !peer_hex.is_empty() {
                                true
                            } else {
                                matches!(l4.protocol, Protocol::Icmp) && l4.icmp_type == Some(8)
                            }
                        }
                    };
                    if !allowed {
                        fw_counters.denied.fetch_add(1, Ordering::Relaxed);
                        return (PolicyVerdict::Deny, policy_gen, fw_gen);
                    }
                    fw_counters.allowed.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        if let Some(key) = canon_key(net, l4.protocol, src, dst, l4.src_port, l4.dst_port) {
            self.open_flow(inner, policy_gen, fw_gen, key, l4.protocol, tcp_flags);
        }
        (PolicyVerdict::Allow, policy_gen, fw_gen)
    }

    /// Established-flow fast path with generation revalidation (§0.4,
    /// §2.2-2). Entries admitted under older generations are re-evaluated
    /// once against current policy instead of being trusted blindly; a
    /// revocation therefore takes effect on the next packet of the flow,
    /// not after its TTL. ANY mismatch — ACL or firewall — revalidates, so
    /// an old firewall snapshot can never be trusted under a new ACL
    /// generation or vice versa.
    fn conntrack_allows(
        &self,
        inner: &RuntimeInner,
        policy_gen: u64,
        fw_gen: u64,
        key: CanonKey,
        direction: Direction,
        tcp_flags: u8,
    ) -> bool {
        let now = Instant::now();
        let now_ms = now_millis();
        let mut e = match inner.conntrack.get_mut(&key) {
            Some(e) => e,
            None => return false,
        };
        if now.duration_since(e.last_seen) > ttl_of(&e) {
            drop(e);
            inner.conntrack.remove(&key);
            return false;
        }
        if e.admitted_acl_gen != policy_gen || e.admitted_fw_gen != fw_gen {
            // Security-relevant publish happened since admission: revalidate
            // fully below (the caller falls through to policy evaluation).
            return false;
        }
        let allowed = match e.phase {
            Phase::Tcp(TcpPhase::SynSent) => {
                if matches!(direction, Direction::Inbound)
                    || (tcp_flags & TcpFlags::ACK) != 0
                    || (tcp_flags & TcpFlags::RST) != 0
                {
                    if (tcp_flags & TcpFlags::RST) != 0 || (tcp_flags & TcpFlags::FIN) != 0 {
                        e.phase = Phase::Tcp(TcpPhase::TimeWait);
                    } else {
                        e.phase = Phase::Tcp(TcpPhase::Established);
                    }
                    e.last_seen = now;
                    true
                } else if matches!(direction, Direction::Outbound) {
                    e.last_seen = now;
                    true
                } else {
                    false
                }
            }
            Phase::Tcp(TcpPhase::Established) => {
                if (tcp_flags & TcpFlags::RST) != 0 || (tcp_flags & TcpFlags::FIN) != 0 {
                    e.phase = Phase::Tcp(TcpPhase::TimeWait);
                }
                e.last_seen = now;
                true
            }
            Phase::Tcp(TcpPhase::TimeWait) => {
                e.last_seen = now;
                true
            }
            Phase::Udp | Phase::Icmp => {
                e.last_seen = now;
                true
            }
        };
        if allowed {
            // Throttled wheel maintenance: at most ~1 push per TTL/4 per flow.
            let ttl = ttl_of(&e);
            if now_ms.wrapping_sub(e.heap_ms) > (ttl.as_millis() as u64 / 4).max(1000) {
                e.seq = e.seq.wrapping_add(1);
                e.heap_ms = now_ms;
                let seq = e.seq;
                drop(e);
                inner
                    .expiry
                    .push(key, now_ms.saturating_add(ttl.as_millis() as u64), seq);
            }
        }
        allowed
    }

    /// Bounded amortized expiry for one flow's shard (§14): pop at most
    /// REAP_BUDGET expired nodes, removing only entries whose token still
    /// matches (missing / refreshed entries are skipped, never trusted).
    fn reap_for_key(&self, inner: &RuntimeInner, key: &CanonKey) {
        let now_ms = now_millis();
        let now = Instant::now();
        inner
            .expiry
            .reap_shard(ExpiryWheel::shard(key), now_ms, |k, seq| {
                let remove = match inner.conntrack.get(&k) {
                    Some(e) => e.seq == seq && now.duration_since(e.last_seen) > ttl_of(&e),
                    None => false,
                };
                if remove {
                    inner.conntrack.remove(&k);
                }
            });
    }

    fn open_flow(
        &self,
        inner: &RuntimeInner,
        policy_gen: u64,
        fw_gen: u64,
        key: CanonKey,
        proto: Protocol,
        tcp_flags: u8,
    ) {
        let now = Instant::now();
        let phase = match proto {
            Protocol::Tcp => {
                if (tcp_flags & TcpFlags::SYN) != 0 && (tcp_flags & TcpFlags::ACK) == 0 {
                    Phase::Tcp(TcpPhase::SynSent)
                } else if (tcp_flags & TcpFlags::FIN) != 0 || (tcp_flags & TcpFlags::RST) != 0 {
                    Phase::Tcp(TcpPhase::TimeWait)
                } else {
                    Phase::Tcp(TcpPhase::Established)
                }
            }
            Protocol::Udp => Phase::Udp,
            Protocol::Icmp | Protocol::Icmpv6 => Phase::Icmp,
            Protocol::Any | Protocol::Other(_) => return,
        };
        let now_ms = now_millis();
        let ttl = match phase {
            Phase::Tcp(TcpPhase::TimeWait) => TCP_TIME_WAIT_TTL,
            Phase::Tcp(_) => TCP_ACTIVE_TTL,
            Phase::Udp => UDP_TTL,
            Phase::Icmp => ICMP_TTL,
        };
        inner
            .conntrack
            .entry(key)
            .and_modify(|st| {
                st.last_seen = now;
                // Stamp exactly the pair that decided (load-ordered above).
                st.admitted_acl_gen = policy_gen;
                st.admitted_fw_gen = fw_gen;
                if matches!(st.phase, Phase::Tcp(TcpPhase::SynSent))
                    && matches!(phase, Phase::Tcp(TcpPhase::Established))
                {
                    st.phase = phase;
                }
                if matches!(phase, Phase::Tcp(TcpPhase::TimeWait)) {
                    st.phase = phase;
                }
            })
            .or_insert_with(|| {
                inner
                    .expiry
                    .push(key, now_ms.saturating_add(ttl.as_millis() as u64), 1);
                FlowState {
                    phase,
                    last_seen: now,
                    admitted_acl_gen: policy_gen,
                    admitted_fw_gen: fw_gen,
                    seq: 1,
                    heap_ms: now_ms,
                }
            });
    }

    fn record_deny(
        &self,
        inner: &RuntimeInner,
        peer_hex: &str,
        dst_port: Option<u16>,
        proto: Protocol,
    ) {
        let record = AclDenyRecord {
            peer_endpoint: peer_hex.to_string(),
            dst_port,
            protocol: format!("{proto:?}").to_lowercase(),
            reason: "policy_deny".to_string(),
            rule_slug: None,
            scope: None,
            at_unix: jiff::Timestamp::now().as_second(),
        };
        let mut log = inner.deny_log.lock();
        if log.len() >= DENY_LOG_CAP {
            log.pop_front();
        }
        log.push_back(record);
    }
}

fn fw_verdict(
    rules: &[CompiledFwRule],
    direction: Direction,
    l4: ResolvedL4,
    peer_hex: &str,
    peer_hostname: Option<&str>,
    peer_network: Option<Uuid>,
) -> Option<PolicyVerdict> {
    let inbound = matches!(direction, Direction::Inbound);
    for r in rules {
        if r.inbound != inbound {
            continue;
        }
        if !l4.protocol.matches_rule(Some(r.protocol)) {
            continue;
        }
        if !r.ports.is_empty() && !l4.protocol.is_icmp() {
            let Some(p) = l4.dst_port else { continue };
            if !r.ports.iter().any(|(a, b)| p >= *a && p <= *b) {
                continue;
            }
        }
        if let Some(ep) = r.peer_endpoint.as_ref()
            && !ep.as_ref().eq_ignore_ascii_case(peer_hex)
        {
            continue;
        }
        if let Some(h) = r.peer_hostname.as_ref()
            && peer_hostname.is_none_or(|ph| !ph.eq_ignore_ascii_case(h))
        {
            continue;
        }
        if let Some(n) = r.peer_network
            && peer_network != Some(n)
        {
            continue;
        }
        if r.allow {
            return Some(PolicyVerdict::Allow);
        }
        if r.reject {
            return Some(PolicyVerdict::Reject);
        }
        return Some(PolicyVerdict::Deny);
    }
    None
}

trait FragMetaExt {
    fn lookup_meta(&mut self, meta: &PacketMeta) -> Option<ResolvedL4>;
    fn remember_meta(&mut self, meta: &PacketMeta);
}

impl FragMetaExt for FragmentTable {
    fn lookup_meta(&mut self, meta: &PacketMeta) -> Option<ResolvedL4> {
        let key = FragKey {
            src: meta.src,
            dst: meta.dst,
            protocol: meta.proto,
            identification: meta.fragmentation.identification()?,
        };
        self.lookup_cached(&key)
    }

    fn remember_meta(&mut self, meta: &PacketMeta) {
        use tunnet_common::packet::Fragmentation;
        if !matches!(meta.fragmentation, Fragmentation::First { .. }) {
            return;
        }
        let Some(id) = meta.fragmentation.identification() else {
            return;
        };
        let key = FragKey {
            src: meta.src,
            dst: meta.dst,
            protocol: meta.proto,
            identification: id,
        };
        let cached = match meta.transport {
            Transport::Tcp {
                src_port,
                dst_port,
                flags,
                ..
            } => CachedTransport::Tcp {
                src_port,
                dst_port,
                flags,
            },
            Transport::Udp {
                src_port, dst_port, ..
            } => CachedTransport::Udp { src_port, dst_port },
            Transport::Icmpv4 {
                type_u8,
                code,
                echo_id,
                echo_seq,
                ..
            } => CachedTransport::Icmpv4 {
                type_u8,
                code,
                echo_id,
                echo_seq,
            },
            Transport::Icmpv6 { type_u8, code, .. } => CachedTransport::Icmpv6 { type_u8, code },
            Transport::Other { protocol, .. } => CachedTransport::Other { protocol },
            Transport::LaterFragment { .. } => return,
        };
        self.insert_cached(key, cached);
    }
}

/// Compile a firewall rule list once (local + suggested concatenated, local first).
pub fn compile_fw_rules(
    local: &[tunnet_core_firewall_types::FirewallRule],
    suggested: &[tunnet_core_firewall_types::FirewallRule],
) -> Vec<CompiledFwRule> {
    local
        .iter()
        .chain(suggested.iter())
        .map(|r| {
            let mut ports: Vec<(u16, u16)> = r.ports.iter().map(|p| (p.start, p.end)).collect();
            ports.sort();
            let mut merged: Vec<(u16, u16)> = Vec::with_capacity(ports.len());
            for (a, b) in ports {
                if let Some(last) = merged.last_mut()
                    && a <= last.1.saturating_add(1)
                {
                    last.1 = last.1.max(b);
                    continue;
                }
                merged.push((a, b));
            }
            let (peer_endpoint, peer_hostname, peer_network) = match &r.peer {
                tunnet_core_firewall_types::PeerFilter::Any => (None, None, None),
                tunnet_core_firewall_types::PeerFilter::Endpoint(e) => {
                    (Some(e.clone().into_boxed_str()), None, None)
                }
                tunnet_core_firewall_types::PeerFilter::Hostname(h) => {
                    (None, Some(h.clone().into_boxed_str()), None)
                }
                tunnet_core_firewall_types::PeerFilter::NetworkId(n) => {
                    (None, None, n.parse().ok())
                }
            };
            CompiledFwRule {
                inbound: matches!(
                    r.direction,
                    tunnet_core_firewall_types::FirewallDirection::In
                ),
                allow: matches!(r.action, tunnet_core_firewall_types::FirewallAction::Allow),
                reject: matches!(r.action, tunnet_core_firewall_types::FirewallAction::Reject),
                protocol: r.protocol,
                ports: merged,
                peer_endpoint,
                peer_hostname,
                peer_network,
            }
        })
        .collect()
}

// Re-export firewall types without a hard module dependency cycle.
pub mod tunnet_core_firewall_types {
    pub use crate::direct::firewall::{
        FirewallAction, FirewallDirection, FirewallRule, PeerFilter,
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::SelfIdentity;
    use std::sync::Arc;
    use tunnet_common::policy::{PolicyRule, RuleScope, Selector};
    use tunnet_core_firewall_types::FirewallRule;

    fn self_id() -> SelfIdentity {
        SelfIdentity {
            endpoint_hex: "aa".into(),
            ip: Ipv4Addr::new(10, 0, 0, 1),
            tags: vec![],
            network: "net".into(),
        }
    }

    /// Test runtime with an explicit firewall slot (no engine polling).
    /// Returns (runtime, stable slot). The slot is standalone (not the
    /// runtime's): tests that need publication use `slot_for_network`.
    fn harness(bundle: PolicyBundle, fw_enabled: bool) -> (PolicyRuntime, Arc<FwSlot>) {
        let rt = PolicyRuntime::bootstrap(&bundle, &HashMap::new(), &self_id(), true, false);
        let slot = Arc::new(FwSlot {
            snapshot: ArcSwap::from_pointee(FwSnapshot {
                generation: rt.generation(),
                set: FwSet {
                    enabled: fw_enabled,
                    rules: vec![],
                },
            }),
            counters: Arc::new(FwCounters::default()),
        });
        (rt, slot)
    }

    fn check_out(rt: &PolicyRuntime, m: &PacketMeta, slot: &FwSlot) -> PolicyVerdict {
        rt.check(
            m,
            Direction::Outbound,
            "bb",
            &[],
            None,
            None,
            slot,
            &slot.counters,
        )
    }

    fn check_in(rt: &PolicyRuntime, m: &PacketMeta, slot: &FwSlot) -> PolicyVerdict {
        rt.check(
            m,
            Direction::Inbound,
            "bb",
            &[],
            None,
            None,
            slot,
            &slot.counters,
        )
    }

    fn meta_tcp(dst_port: u16) -> PacketMeta {
        meta_tcp_ports(40000, dst_port)
    }

    fn meta_tcp_ports(sport: u16, dst_port: u16) -> PacketMeta {
        let b = etherparse::PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .tcp(sport, dst_port, 1, 1000);
        let mut o = Vec::new();
        b.write(&mut o, b"hello").unwrap();
        let pkt = tunnet_common::packet::parse(&o).unwrap();
        PacketMeta::from_packet(&pkt)
    }

    fn open_bundle() -> PolicyBundle {
        PolicyBundle::default()
    }

    #[test]
    fn open_bundle_allows_and_establishes() {
        let (p, slot) = harness(open_bundle(), false);
        let m = meta_tcp(80);
        assert_eq!(check_out(&p, &m, &slot), PolicyVerdict::Allow);
        // Second packet of the same flow: single conntrack hit.
        assert_eq!(check_out(&p, &m, &slot), PolicyVerdict::Allow);
        assert_eq!(p.conntrack_len(), 1);
    }

    #[test]
    fn deny_rule_matches_legacy_semantics() {
        let bundle = PolicyBundle {
            rules: vec![PolicyRule {
                src: Selector::Any,
                dst: Selector::Any,
                action: Action::Deny,
                ports: vec![tunnet_common::policy::PortRange { start: 22, end: 22 }],
                protocol: Some(Protocol::Tcp),
                priority: 0,
                order_index: 0,
                scope: RuleScope::Network,
                enabled: true,
                slug: None,
                src_posture: vec![],
            }],
            default_action: DefaultAction::Allow,
            ..PolicyBundle::default()
        };
        let (p, slot) = harness(bundle.clone(), false);
        let m22 = meta_tcp(22);
        let m80 = meta_tcp(80);
        assert_eq!(check_out(&p, &m22, &slot), PolicyVerdict::Deny);
        assert_eq!(check_out(&p, &m80, &slot), PolicyVerdict::Allow);
        // Legacy evaluator agrees (differential equivalence probe).
        let legacy = {
            use tunnet_common::policy::{EvalCtx, evaluate_detailed};
            let ctx = EvalCtx {
                self_endpoint_hex: "aa",
                self_ip: Ipv4Addr::new(10, 0, 0, 1),
                self_tags: &[],
                self_network: "net",
                peer_endpoint_hex: "bb",
                peer_ip: Some(Ipv4Addr::new(10, 0, 0, 2)),
                peer_tags: &[],
                peer_network: "net",
                dst_port: Some(22),
                protocol: Protocol::Tcp,
                src_posture_ok: true,
            };
            evaluate_detailed(&bundle, &ctx, Direction::Outbound).action
        };
        assert_eq!(legacy, Action::Deny);
    }

    #[test]
    fn later_fragment_without_state_denied() {
        let (p, slot) = harness(open_bundle(), false);
        // Craft a later fragment manually.
        let b = etherparse::PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64).udp(40000, 443);
        let mut o = Vec::new();
        b.write(&mut o, &[0; 100]).unwrap();
        o[6] = 0x20; // MF + offset bit pattern => fragment offset nonzero
        o[7] = 0x08;
        let pkt = tunnet_common::packet::parse(&o).unwrap();
        let meta = PacketMeta::from_packet(&pkt);
        assert!(meta.is_later_fragment());
        assert_eq!(check_out(&p, &meta, &slot), PolicyVerdict::Deny);
    }

    fn meta_udp(sport: u16, dport: u16) -> PacketMeta {
        let b = etherparse::PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64).udp(sport, dport);
        let mut o = Vec::new();
        b.write(&mut o, &[0; 40]).unwrap();
        let pkt = tunnet_common::packet::parse(&o).unwrap();
        PacketMeta::from_packet(&pkt)
    }

    fn legacy_action(bundle: &PolicyBundle, port: Option<u16>, proto: Protocol) -> Action {
        use tunnet_common::policy::{EvalCtx, evaluate_detailed};
        let ctx = EvalCtx {
            self_endpoint_hex: "aa",
            self_ip: Ipv4Addr::new(10, 0, 0, 1),
            self_tags: &[],
            self_network: "net",
            peer_endpoint_hex: "bb",
            peer_ip: Some(Ipv4Addr::new(10, 0, 0, 2)),
            peer_tags: &[],
            peer_network: "net",
            dst_port: port,
            protocol: proto,
            src_posture_ok: true,
        };
        evaluate_detailed(bundle, &ctx, Direction::Outbound).action
    }

    fn new_policy(bundle: PolicyBundle) -> (PolicyRuntime, Arc<FwSlot>) {
        harness(bundle, false)
    }

    #[test]
    fn differential_matrix_matches_legacy() {
        // order_index ascending first-match, port ranges, org-deny priority,
        // disabled rules, protocol scoping — new engine must equal legacy.
        let bundle = PolicyBundle {
            rules: vec![
                PolicyRule {
                    src: Selector::Tag("admin".into()),
                    dst: Selector::Any,
                    action: Action::Allow,
                    ports: vec![],
                    protocol: None,
                    priority: 0,
                    order_index: 5,
                    scope: RuleScope::Network,
                    enabled: false,
                    slug: Some("disabled".into()),
                    src_posture: vec![],
                },
                PolicyRule {
                    src: Selector::Any,
                    dst: Selector::Any,
                    action: Action::Deny,
                    ports: vec![
                        tunnet_common::policy::PortRange {
                            start: 8000,
                            end: 8010,
                        },
                        tunnet_common::policy::PortRange {
                            start: 8005,
                            end: 8020,
                        },
                    ],
                    protocol: Some(Protocol::Tcp),
                    priority: 0,
                    order_index: 1,
                    scope: RuleScope::Organization,
                    enabled: true,
                    slug: Some("org-deny-range".into()),
                    src_posture: vec![],
                },
                PolicyRule {
                    src: Selector::Any,
                    dst: Selector::Any,
                    action: Action::Allow,
                    ports: vec![tunnet_common::policy::PortRange {
                        start: 8000,
                        end: 9000,
                    }],
                    protocol: Some(Protocol::Tcp),
                    priority: 0,
                    order_index: 0,
                    scope: RuleScope::Network,
                    enabled: true,
                    slug: Some("net-allow-wide".into()),
                    src_posture: vec![],
                },
            ],
            default_action: DefaultAction::Deny,
            ..PolicyBundle::default()
        };
        let (p, slot) = new_policy(bundle.clone());
        // Org deny (merged 8000-8020) beats network allow despite higher order.
        for port in [8000, 8015, 8020] {
            let m = meta_tcp(port);
            let got = check_out(&p, &m, &slot);
            assert_eq!(got, PolicyVerdict::Deny, "port {port}");
            assert_eq!(
                legacy_action(&bundle, Some(port), Protocol::Tcp),
                Action::Deny
            );
        }
        // Outside the org-deny range but inside the network allow range,
        // the network allow wins.
        for port in [8021, 8500] {
            let m = meta_tcp(port);
            let got = check_out(&p, &m, &slot);
            assert_eq!(got, PolicyVerdict::Allow, "port {port}");
            assert_eq!(
                legacy_action(&bundle, Some(port), Protocol::Tcp),
                Action::Allow
            );
        }
        // Outside every range the restrictive default applies in both engines.
        let m = meta_tcp(7999);
        assert_eq!(check_out(&p, &m, &slot), PolicyVerdict::Deny);
        assert_eq!(
            legacy_action(&bundle, Some(7999), Protocol::Tcp),
            Action::Deny
        );
        // UDP to the same port is not matched by TCP-only rules → default deny.
        let u = meta_udp(40000, 8010);
        assert_eq!(check_out(&p, &u, &slot), PolicyVerdict::Deny);
        assert_eq!(
            legacy_action(&bundle, Some(8010), Protocol::Udp),
            Action::Deny
        );
    }

    #[test]
    fn first_fragment_allows_later_fragment() {
        let (p, slot) = new_policy(open_bundle());
        // First fragment (offset 0 + MF) is policy-evaluated and remembered.
        let b = etherparse::PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64).udp(40000, 443);
        let mut first = Vec::new();
        b.write(&mut first, &[0; 100]).unwrap();
        first[6] = 0x20; // MF set, offset 0
        first[7] = 0x00;
        let pkt = tunnet_common::packet::parse(&first).unwrap();
        let meta = PacketMeta::from_packet(&pkt);
        assert!(matches!(
            meta.fragmentation,
            tunnet_common::packet::Fragmentation::First { .. }
        ));
        assert_eq!(check_out(&p, &meta, &slot), PolicyVerdict::Allow);
        // Later fragment of the same datagram now resolves via cached state.
        let mut later = first.clone();
        later[6] = 0x20;
        later[7] = 0x08;
        let pkt = tunnet_common::packet::parse(&later).unwrap();
        let meta = PacketMeta::from_packet(&pkt);
        assert!(meta.is_later_fragment());
        assert_eq!(check_out(&p, &meta, &slot), PolicyVerdict::Allow);
    }

    #[test]
    fn malformed_packets_denied() {
        let (p, _slot) = new_policy(open_bundle());
        // Truncated garbage must never reach the transport.
        assert!(tunnet_common::packet::parse(&[0x45, 0x00]).is_err());
        assert!(tunnet_common::packet::parse(&[]).is_err());
        let _ = p;
    }

    #[test]
    fn conntrack_is_shared_bidirectionally() {
        // One canonical flow resolves to the same entry in either direction:
        // outbound SYN opens it, the inbound reply hits it (no second eval).
        let (p, slot) = harness(open_bundle(), true);
        let out = meta_tcp(443);
        assert_eq!(check_out(&p, &out, &slot), PolicyVerdict::Allow);
        assert_eq!(p.conntrack_len(), 1);
        // Reply direction: src/dst swapped, same 5-tuple.
        let b =
            etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [10, 0, 0, 1], 64).tcp(443, 40000, 1, 2);
        let mut o = Vec::new();
        b.write(&mut o, b"hi").unwrap();
        let pkt = tunnet_common::packet::parse(&o).unwrap();
        let reply = PacketMeta::from_packet(&pkt);
        assert_eq!(check_in(&p, &reply, &slot), PolicyVerdict::Allow);
        assert_eq!(p.conntrack_len(), 1, "same canonical entry both ways");
    }

    fn deny_80_bundle() -> PolicyBundle {
        PolicyBundle {
            rules: vec![PolicyRule {
                src: Selector::Any,
                dst: Selector::Any,
                action: Action::Deny,
                ports: vec![tunnet_common::policy::PortRange { start: 80, end: 80 }],
                protocol: Some(Protocol::Tcp),
                priority: 0,
                order_index: 0,
                scope: RuleScope::Network,
                enabled: true,
                slug: None,
                src_posture: vec![],
            }],
            default_action: DefaultAction::Allow,
            ..PolicyBundle::default()
        }
    }

    #[test]
    fn revocation_tcp_allow_to_deny() {
        // Established TCP must not survive an allow→deny publish.
        let (p, slot) = harness(PolicyBundle::default(), false);
        let m = meta_tcp(80);
        assert_eq!(check_out(&p, &m, &slot), PolicyVerdict::Allow);
        assert_eq!(p.conntrack_len(), 1);
        p.publish_acl(&deny_80_bundle(), &self_id(), true, false);
        // Next packet of the SAME flow revalidates and is denied.
        assert_eq!(check_out(&p, &m, &slot), PolicyVerdict::Deny);
        // And a fresh flow is denied too.
        let m2 = meta_tcp(80);
        assert_eq!(check_out(&p, &m2, &slot), PolicyVerdict::Deny);
    }

    #[test]
    fn revocation_udp_allow_to_deny() {
        let (p, slot) = harness(PolicyBundle::default(), false);
        let m = meta_udp(40000, 53);
        assert_eq!(check_out(&p, &m, &slot), PolicyVerdict::Allow);
        let deny_udp = PolicyBundle {
            rules: vec![PolicyRule {
                src: Selector::Any,
                dst: Selector::Any,
                action: Action::Deny,
                ports: vec![],
                protocol: Some(Protocol::Udp),
                priority: 0,
                order_index: 0,
                scope: RuleScope::Network,
                enabled: true,
                slug: None,
                src_posture: vec![],
            }],
            default_action: DefaultAction::Allow,
            ..PolicyBundle::default()
        };
        p.publish_acl(&deny_udp, &self_id(), true, false);
        assert_eq!(check_out(&p, &m, &slot), PolicyVerdict::Deny);
    }

    fn fw_deny_all_inbound() -> (Vec<FirewallRule>, Vec<FirewallRule>) {
        use tunnet_core_firewall_types::{FirewallAction, FirewallDirection, PeerFilter};
        (
            vec![FirewallRule {
                direction: FirewallDirection::In,
                action: FirewallAction::Deny,
                protocol: Protocol::Any,
                ports: vec![],
                peer: PeerFilter::Any,
            }],
            vec![],
        )
    }

    /// Check helper reading firewall state the way the hot path does: from
    /// the network's stable slot, with no post-publish re-resolution.
    fn check_in_slot(
        rt: &PolicyRuntime,
        m: &PacketMeta,
        net: Uuid,
        direction: tunnet_common::policy::Direction,
    ) -> PolicyVerdict {
        let slot = rt.slot_for_network(net);
        rt.check(
            m,
            direction,
            "bb",
            &[],
            None,
            Some(net),
            &slot,
            &slot.counters,
        )
    }

    #[test]
    fn revocation_suggested_rule_change() {
        // Suggested rules arrive via publish_firewall and must revoke too —
        // observed through the STABLE slot, with no manual re-resolution
        // after publication (§2.1-3).
        let net = Uuid::nil();
        let rt = PolicyRuntime::bootstrap(
            &PolicyBundle::default(),
            &HashMap::from([(net, (vec![], vec![], true))]),
            &self_id(),
            true,
            false,
        );
        // Pin the slot the way a fast state would (before any publish).
        let slot = rt.slot_for_network(net);
        let m = meta_tcp(443);
        assert_eq!(
            rt.check(
                &m,
                Direction::Outbound,
                "bb",
                &[],
                None,
                Some(net),
                &slot,
                &slot.counters
            ),
            PolicyVerdict::Allow
        );
        let (local, suggested) = fw_deny_all_inbound();
        rt.publish_firewall(net, local, suggested, true);
        // Same slot object, no re-fetch: the new rules are visible.
        assert_eq!(
            check_in_slot(&rt, &m, net, Direction::Inbound),
            PolicyVerdict::Deny
        );
    }

    #[test]
    fn revocation_firewall_disabled_then_deny() {
        // Disabled firewall admits; enabling with a deny rule revokes; all
        // observed through the stable slot with no re-resolution (§2.1-3).
        let net = Uuid::nil();
        let rt = PolicyRuntime::bootstrap(
            &PolicyBundle::default(),
            &HashMap::from([(net, (vec![], vec![], false))]),
            &self_id(),
            true,
            false,
        );
        let m = meta_tcp(443);
        assert_eq!(
            check_in_slot(&rt, &m, net, Direction::Inbound),
            PolicyVerdict::Allow
        );
        let (local, suggested) = fw_deny_all_inbound();
        rt.publish_firewall(net, local, suggested, true);
        assert_eq!(
            check_in_slot(&rt, &m, net, Direction::Inbound),
            PolicyVerdict::Deny
        );
        // And disabling again admits without clearing unrelated state.
        rt.publish_firewall(net, vec![], vec![], false);
        assert_eq!(
            check_in_slot(&rt, &m, net, Direction::Inbound),
            PolicyVerdict::Allow
        );
    }

    #[test]
    fn live_fast_state_observes_publication() {
        // §2.1-3: a fast state holding its network slot (like an active
        // peer) immediately observes local rule changes, suggested rule
        // changes, enable/disable flips, and allow→deny revocation of an
        // ESTABLISHED flow — with zero relink calls after install.
        use crate::peers::{PeerIdentity, PeerRegistry};
        use iroh::SecretKey;
        let net = Uuid::from_u128(0x21);
        let rt = PolicyRuntime::bootstrap(
            &PolicyBundle::default(),
            &HashMap::from([(net, (vec![], vec![], true))]),
            &self_id(),
            true,
            false,
        );
        let reg = PeerRegistry::new();
        let ep = SecretKey::generate().public();
        let fast = reg.ensure(Arc::new(PeerIdentity {
            endpoint: ep,
            endpoint_hex: format!("{ep}"),
            hostname: "peer".into(),
            ip: Ipv4Addr::new(10, 0, 0, 2),
            tags: vec![],
            network_id: net,
            network_name: "net".into(),
        }));
        // Install-time assignment only.
        reg.relink_policy(&rt);
        // The hot path, exactly as tun_io does it.
        let check_live = |rt: &PolicyRuntime, m: &PacketMeta| {
            let slot = fast.policy.load();
            rt.check(
                m,
                Direction::Inbound,
                "bb",
                &[],
                None,
                Some(net),
                &slot,
                &slot.counters,
            )
        };
        // Establish a flow through the live state.
        let m = meta_tcp(443);
        assert_eq!(check_live(&rt, &m), PolicyVerdict::Allow);
        // Local deny rule published: established flow revoked, no relink.
        let (local, _) = fw_deny_all_inbound();
        rt.publish_firewall(net, local, vec![], true);
        assert_eq!(check_live(&rt, &m), PolicyVerdict::Deny);
        // Back to allow via empty rules.
        rt.publish_firewall(net, vec![], vec![], true);
        let m2 = meta_tcp_ports(40001, 443);
        assert_eq!(check_live(&rt, &m2), PolicyVerdict::Allow);
        // Suggested deny published: revoked again (suggested rules flow
        // through the same slot swap as local ones).
        let (suggested_deny, _) = fw_deny_all_inbound();
        rt.publish_firewall(net, vec![], suggested_deny, true);
        assert_eq!(check_live(&rt, &m2), PolicyVerdict::Deny);
        // Counters object stayed stable across all publishes (stats intact).
        let slot = fast.policy.load();
        assert!(slot.counters.denied.load(Ordering::Relaxed) > 0);
        assert!(slot.counters.allowed.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn publication_is_atomic_under_concurrency() {
        // §2.1-4: publishers alternate allow-all/deny-all bundles while
        // readers evaluate one fixed flow. Every verdict is paired with the
        // generation the reader ACTUALLY used: a verdict at a deny
        // generation must be Deny (a torn snapshot+generation pair would
        // trust stale conntrack and wrongly Allow).
        use std::sync::Mutex;
        let rt = PolicyRuntime::bootstrap(
            &PolicyBundle::default(),
            &HashMap::new(),
            &self_id(),
            true,
            false,
        );
        let deny_gens = Arc::new(Mutex::new(Vec::<u64>::new()));
        let records = Arc::new(Mutex::new(Vec::<(PolicyVerdict, u64, u64)>::new()));
        let slot = Arc::new(FwSlot {
            snapshot: ArcSwap::from_pointee(FwSnapshot {
                generation: rt.generation(),
                set: FwSet {
                    enabled: false,
                    rules: vec![],
                },
            }),
            counters: Arc::new(FwCounters::default()),
        });
        // Establish the flow once (admitted under the bootstrap generation).
        let m = meta_tcp(80);
        assert_eq!(check_out(&rt, &m, &slot), PolicyVerdict::Allow);
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        std::thread::scope(|scope| {
            // Publisher: alternate deny/allow, recording deny generations.
            let rt_p = rt.clone();
            let deny_gens_p = deny_gens.clone();
            let stop_p = stop.clone();
            let publisher = scope.spawn(move || {
                let mut deny = true;
                while !stop_p.load(std::sync::atomic::Ordering::Relaxed) {
                    if deny {
                        rt_p.publish_acl(&deny_80_bundle(), &self_id(), true, false);
                        deny_gens_p.lock().unwrap().push(rt_p.generation());
                    } else {
                        rt_p.publish_acl(&PolicyBundle::default(), &self_id(), true, false);
                    }
                    deny = !deny;
                }
            });
            // Readers: hammer the SAME flow, pairing verdict + used gens.
            let mut readers = Vec::new();
            for _ in 0..4 {
                let rt_r = rt.clone();
                let records_r = records.clone();
                let stop_r = stop.clone();
                let slot_r = slot.clone();
                let m_r = meta_tcp(80);
                readers.push(scope.spawn(move || {
                    while !stop_r.load(std::sync::atomic::Ordering::Relaxed) {
                        let (v, g, fg) = rt_r.check_with_generation(
                            &m_r,
                            Direction::Outbound,
                            "bb",
                            &[],
                            None,
                            None,
                            &slot_r,
                            &slot_r.counters,
                        );
                        records_r.lock().unwrap().push((v, g, fg));
                    }
                }));
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            let _ = publisher.join();
            for r in readers {
                let _ = r.join();
            }
        });
        let deny_gens = deny_gens.lock().unwrap();
        let records = records.lock().unwrap();
        assert!(!deny_gens.is_empty(), "publisher must have run");
        assert!(!records.is_empty(), "readers must have run");
        // Verdicts at deny generations are Deny — no torn allow-through.
        // (Verdicts at allow generations may be Allow or Deny: a flow
        // denied under a deny gen stays denied until... conntrack only
        // opens on Allow, so re-allow re-admits; either is consistent.)
        for (v, g, _fg) in records.iter() {
            if deny_gens.contains(g) {
                assert_eq!(
                    *v,
                    PolicyVerdict::Deny,
                    "torn publication: Allow verdict at deny generation {g}"
                );
            }
        }
        // Generations observed are monotonic per snapshot (sanity: the
        // sequence of publishes is a total order).
        let mut gens: Vec<u64> = records.iter().map(|(_, g, _)| *g).collect();
        gens.sort();
        gens.dedup();
        for w in gens.windows(2) {
            assert!(w[1] > w[0], "generations must be distinct per publish");
        }
    }

    #[test]
    fn firewall_publication_is_atomic_under_concurrency() {
        // §2.2-2: publisher alternates firewall allow/deny (local rules,
        // then suggested, then enabled flips) while readers hammer one
        // ESTABLISHED flow. Every verdict pairs with the (acl, fw)
        // generations actually used. Invariants: a verdict stamped with a
        // deny fw_gen is Deny (the old-allow-firewall-under-new-generation
        // poison pair is impossible); a verdict at an allow fw_gen Allows
        // (re-allow re-admits, no stuck deny).
        use std::sync::Mutex;
        use tunnet_core_firewall_types::{FirewallAction, FirewallDirection, PeerFilter};
        let net = Uuid::from_u128(0x22);
        let rt = PolicyRuntime::bootstrap(
            &PolicyBundle::default(),
            &HashMap::from([(net, (vec![], vec![], true))]),
            &self_id(),
            true,
            false,
        );
        let deny_rule = FirewallRule {
            direction: FirewallDirection::Out,
            action: FirewallAction::Deny,
            protocol: Protocol::Tcp,
            ports: vec![],
            peer: PeerFilter::Any,
        };
        let deny_fw_gens = Arc::new(Mutex::new(Vec::<u64>::new()));
        let allow_fw_gens = Arc::new(Mutex::new(Vec::<u64>::new()));
        let records = Arc::new(Mutex::new(Vec::<(PolicyVerdict, u64, u64)>::new()));
        let m = meta_tcp(80);
        let slot0 = rt.slot_for_network(net);
        assert_eq!(
            rt.check(
                &m,
                Direction::Outbound,
                "bb",
                &[],
                None,
                Some(net),
                &slot0,
                &slot0.counters
            ),
            PolicyVerdict::Allow
        );
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        std::thread::scope(|scope| {
            let rt_p = rt.clone();
            let deny_p = deny_fw_gens.clone();
            let allow_p = allow_fw_gens.clone();
            let stop_p = stop.clone();
            let deny_rule_p = deny_rule.clone();
            let publisher = scope.spawn(move || {
                let mut deny = true;
                let mut use_suggested = false;
                while !stop_p.load(std::sync::atomic::Ordering::Relaxed) {
                    if deny {
                        // Alternate local / suggested / disable-flip denies
                        // so every mutation kind participates.
                        if use_suggested {
                            rt_p.publish_firewall(net, vec![], vec![deny_rule_p.clone()], true);
                        } else {
                            rt_p.publish_firewall(net, vec![deny_rule_p.clone()], vec![], true);
                        }
                        use_suggested = !use_suggested;
                        deny_p
                            .lock()
                            .unwrap()
                            .push(rt_p.slot_for_network(net).snapshot.load().generation);
                    } else {
                        rt_p.publish_firewall(net, vec![], vec![], true);
                        allow_p
                            .lock()
                            .unwrap()
                            .push(rt_p.slot_for_network(net).snapshot.load().generation);
                    }
                    deny = !deny;
                }
            });
            let mut readers = Vec::new();
            for _ in 0..4 {
                let rt_r = rt.clone();
                let records_r = records.clone();
                let stop_r = stop.clone();
                let m_r = meta_tcp(80);
                readers.push(scope.spawn(move || {
                    let slot_r = rt_r.slot_for_network(net);
                    while !stop_r.load(std::sync::atomic::Ordering::Relaxed) {
                        let (v, ag, fg) = rt_r.check_with_generation(
                            &m_r,
                            Direction::Outbound,
                            "bb",
                            &[],
                            None,
                            Some(net),
                            &slot_r,
                            &slot_r.counters,
                        );
                        records_r.lock().unwrap().push((v, ag, fg));
                    }
                }));
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            let _ = publisher.join();
            for r in readers {
                let _ = r.join();
            }
        });
        let deny_fw_gens = deny_fw_gens.lock().unwrap();
        let allow_fw_gens = allow_fw_gens.lock().unwrap();
        let records = records.lock().unwrap();
        assert!(!deny_fw_gens.is_empty() && !allow_fw_gens.is_empty());
        assert!(!records.is_empty());
        let mut saw_deny = 0u32;
        let mut saw_allow = 0u32;
        for (v, _ag, fg) in records.iter() {
            if deny_fw_gens.contains(fg) {
                saw_deny += 1;
                assert_eq!(
                    *v,
                    PolicyVerdict::Deny,
                    "old firewall admitted under new generation (fw_gen={fg})"
                );
            } else if allow_fw_gens.contains(fg) {
                saw_allow += 1;
                assert_eq!(
                    *v,
                    PolicyVerdict::Allow,
                    "re-allow failed to re-admit (fw_gen={fg})"
                );
            }
        }
        assert!(saw_deny > 0 && saw_allow > 0, "must observe both phases");
    }

    #[test]
    fn concurrent_publishers_lose_no_updates() {
        use std::sync::Mutex;
        use tunnet_common::policy::PortRange;
        use tunnet_core_firewall_types::{FirewallAction, FirewallDirection, PeerFilter};
        let net = Uuid::from_u128(0x23);
        let rt = PolicyRuntime::bootstrap(
            &PolicyBundle::default(),
            &HashMap::from([(net, (vec![], vec![], true))]),
            &self_id(),
            true,
            false,
        );
        let m = meta_tcp(80);
        let slot0 = rt.slot_for_network(net);
        assert_eq!(
            rt.check(
                &m,
                Direction::Outbound,
                "bb",
                &[],
                None,
                Some(net),
                &slot0,
                &slot0.counters
            ),
            PolicyVerdict::Allow
        );
        const PUBLISHERS_PER_KIND: u64 = 4;
        const ITERS: u64 = 200;
        const PUBLISHERS: u64 = 2 * PUBLISHERS_PER_KIND;
        let total = PUBLISHERS * ITERS;
        let seq = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let log = Arc::new(Mutex::new(Vec::<(u64, u8, u16)>::new()));
        let gen_samples = Arc::new(Mutex::new(Vec::<u64>::new()));
        let acl_bundle = |port: u16| PolicyBundle {
            rules: vec![PolicyRule {
                src: Selector::Any,
                dst: Selector::Any,
                action: Action::Deny,
                ports: vec![PortRange {
                    start: port,
                    end: port,
                }],
                protocol: Some(Protocol::Tcp),
                priority: 0,
                order_index: 0,
                scope: RuleScope::Network,
                enabled: true,
                slug: None,
                src_posture: vec![],
            }],
            default_action: DefaultAction::Allow,
            ..PolicyBundle::default()
        };
        let fw_rule = |port: u16| FirewallRule {
            direction: FirewallDirection::Out,
            action: FirewallAction::Deny,
            protocol: Protocol::Tcp,
            ports: vec![PortRange {
                start: port,
                end: port,
            }],
            peer: PeerFilter::Any,
        };
        std::thread::scope(|scope| {
            for kind in [0u8, 0, 0, 0, 1, 1, 1, 1] {
                let rt_p = rt.clone();
                let seq_p = seq.clone();
                let log_p = log.clone();
                scope.spawn(move || {
                    for _ in 0..ITERS {
                        let s = seq_p.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let port = 9000 + (s % 500) as u16;
                        let committed = if kind == 0 {
                            rt_p.publish_acl(&acl_bundle(port), &self_id(), true, false)
                        } else {
                            rt_p.publish_firewall(net, vec![fw_rule(port)], vec![], true)
                        };
                        log_p.lock().unwrap().push((committed, kind, port));
                    }
                });
            }
            for _ in 0..2 {
                let rt_r = rt.clone();
                let samples_r = gen_samples.clone();
                scope.spawn(move || {
                    let mut last = 0u64;
                    for _ in 0..ITERS * 4 {
                        let g = rt_r.generation();
                        assert!(g >= last, "generation regressed {last} -> {g}");
                        last = g;
                        samples_r.lock().unwrap().push(g);
                    }
                });
            }
        });
        assert_eq!(rt.generation(), 1 + total);
        let log = log.lock().unwrap();
        assert_eq!(log.len() as u64, total);
        let mut gens: Vec<u64> = log.iter().map(|(g, _, _)| *g).collect();
        gens.sort();
        gens.dedup();
        assert_eq!(
            gens.len() as u64,
            total,
            "every publish committed distinctly"
        );
        assert_eq!(gens[0], 2);
        assert_eq!(gens[gens.len() - 1], 1 + total);
        let (last_gen, last_kind, last_port) = *log.iter().max_by_key(|(g, _, _)| g).unwrap();
        assert_eq!(last_gen, 1 + total);
        let inner = rt.inner.load();
        if last_kind == 0 {
            assert!(
                inner.acl_source.rules.iter().any(|r| r
                    .ports
                    .iter()
                    .any(|p| p.start == last_port && p.end == last_port)),
                "final ACL must be the last-committed bundle (port {last_port})"
            );
        } else {
            let snap = rt.slot_for_network(net).snapshot.load();
            assert_eq!(snap.generation, last_gen);
            assert!(
                snap.set
                    .rules
                    .iter()
                    .any(|r| r.ports.contains(&(last_port, last_port))),
                "final firewall must be the last-committed set (port {last_port})"
            );
        }
        assert!(!gen_samples.lock().unwrap().is_empty());
        rt.publish_acl(&PolicyBundle::default(), &self_id(), true, false);
        rt.publish_firewall(net, vec![], vec![], true);
        let slot = rt.slot_for_network(net);
        assert_eq!(
            rt.check(
                &m,
                Direction::Outbound,
                "bb",
                &[],
                None,
                Some(net),
                &slot,
                &slot.counters
            ),
            PolicyVerdict::Allow
        );
    }

    #[test]
    fn conntrack_is_network_scoped() {
        // §2.2-1 (test 7): identical 5-tuples in A and B create independent
        // conntrack entries; a flow admitted in A never satisfies B, and a
        // deny published in B revokes B while A keeps working.
        use tunnet_core_firewall_types::{FirewallAction, FirewallDirection, PeerFilter};
        let net_a = Uuid::from_u128(0x0a);
        let net_b = Uuid::from_u128(0x0b);
        let rt = PolicyRuntime::bootstrap(
            &PolicyBundle::default(),
            &HashMap::from([
                (net_a, (vec![], vec![], true)),
                (net_b, (vec![], vec![], true)),
            ]),
            &self_id(),
            true,
            false,
        );
        let slot_a = rt.slot_for_network(net_a);
        let slot_b = rt.slot_for_network(net_b);
        let m = meta_tcp_ports(40000, 443);
        let check_net = |rt: &PolicyRuntime, net: Uuid, slot: &FwSlot| {
            rt.check(
                &m,
                Direction::Outbound,
                "bb",
                &[],
                None,
                Some(net),
                slot,
                &slot.counters,
            )
        };
        assert_eq!(check_net(&rt, net_a, &slot_a), PolicyVerdict::Allow);
        assert_eq!(rt.conntrack_len(), 1);
        // Same 5-tuple under B: full evaluation, second entry.
        assert_eq!(check_net(&rt, net_b, &slot_b), PolicyVerdict::Allow);
        assert_eq!(rt.conntrack_len(), 2, "one entry per network");
        // Deny in B only: B revokes, A keeps working.
        let deny_out = FirewallRule {
            direction: FirewallDirection::Out,
            action: FirewallAction::Deny,
            protocol: Protocol::Tcp,
            ports: vec![],
            peer: PeerFilter::Any,
        };
        rt.publish_firewall(net_b, vec![deny_out], vec![], true);
        assert_eq!(check_net(&rt, net_b, &slot_b), PolicyVerdict::Deny);
        assert_eq!(check_net(&rt, net_a, &slot_a), PolicyVerdict::Allow);
    }

    #[test]
    fn cross_network_firewall_isolation() {
        // Rules from network A must never affect network B, including
        // endpoint/hostname-scoped rules and disabled-network handling.
        // Uses the SAME endpoint and 5-tuple in both networks: only the
        // network-scoped conntrack key + per-network slot keeps them apart.
        use tunnet_core_firewall_types::{
            FirewallAction, FirewallDirection, FirewallRule, PeerFilter,
        };
        let net_a = Uuid::from_u128(0x0a);
        let net_b = Uuid::from_u128(0x0b);
        let a_rule = FirewallRule {
            direction: FirewallDirection::In,
            action: FirewallAction::Deny,
            protocol: Protocol::Tcp,
            ports: vec![],
            peer: PeerFilter::Any,
        };
        let a_ep_rule = FirewallRule {
            direction: FirewallDirection::Out,
            action: FirewallAction::Deny,
            protocol: Protocol::Tcp,
            ports: vec![],
            peer: PeerFilter::Endpoint("cc".into()),
        };
        let rt = PolicyRuntime::bootstrap(
            &PolicyBundle::default(),
            &HashMap::from([
                (net_a, (vec![a_rule, a_ep_rule], vec![], true)),
                (net_b, (vec![], vec![], true)),
            ]),
            &self_id(),
            true,
            false,
        );
        let slot_a = rt.slot_for_network(net_a);
        let slot_b = rt.slot_for_network(net_b);
        // Identical 5-tuple + endpoint in both networks: conntrack MUST NOT
        // leak across (network is in the key), and firewall verdicts come
        // from each network's own slot.
        let m_in = meta_tcp_ports(40000, 443);
        let m_in_b = meta_tcp_ports(40000, 443);
        let m_out_cc = meta_tcp_ports(40002, 443);
        let m_out_cc_b = meta_tcp_ports(40002, 443);
        let m_out_bb = meta_tcp_ports(40004, 443);
        // A denies inbound; B allows the identical packet.
        assert_eq!(
            rt.check(
                &m_in,
                Direction::Inbound,
                "bb",
                &[],
                None,
                Some(net_a),
                &slot_a,
                &slot_a.counters
            ),
            PolicyVerdict::Deny
        );
        assert_eq!(
            rt.check(
                &m_in_b,
                Direction::Inbound,
                "bb",
                &[],
                None,
                Some(net_b),
                &slot_b,
                &slot_b.counters
            ),
            PolicyVerdict::Allow
        );
        // Endpoint-scoped rule in A denies peer "cc" outbound under A...
        assert_eq!(
            rt.check(
                &m_out_cc,
                Direction::Outbound,
                "cc",
                &[],
                None,
                Some(net_a),
                &slot_a,
                &slot_a.counters
            ),
            PolicyVerdict::Deny
        );
        // ...but not under B, and not for other peers under A.
        assert_eq!(
            rt.check(
                &m_out_cc_b,
                Direction::Outbound,
                "cc",
                &[],
                None,
                Some(net_b),
                &slot_b,
                &slot_b.counters
            ),
            PolicyVerdict::Allow
        );
        assert_eq!(
            rt.check(
                &m_out_bb,
                Direction::Outbound,
                "bb",
                &[],
                None,
                Some(net_a),
                &slot_a,
                &slot_a.counters
            ),
            PolicyVerdict::Allow
        );
    }

    #[test]
    fn disabled_network_does_not_disable_others() {
        // The old global `enabled &&` flattening bug, proven gone: one
        // disabled network firewall must not affect another network.
        let net_a = Uuid::from_u128(0x0a);
        let net_b = Uuid::from_u128(0x0b);
        let rt = PolicyRuntime::bootstrap(
            &PolicyBundle::default(),
            &HashMap::from([
                (net_a, (vec![], vec![], false)),
                (net_b, (vec![], vec![], true)),
            ]),
            &self_id(),
            true,
            false,
        );
        assert!(!rt.fw_for_network(net_a).enabled);
        assert!(rt.fw_for_network(net_b).enabled);
        let m = meta_tcp(443);
        let slot_b = rt.slot_for_network(net_b);
        assert_eq!(
            rt.check(
                &m,
                Direction::Inbound,
                "bb",
                &[],
                None,
                Some(net_b),
                &slot_b,
                &slot_b.counters
            ),
            PolicyVerdict::Allow
        );
    }
}
