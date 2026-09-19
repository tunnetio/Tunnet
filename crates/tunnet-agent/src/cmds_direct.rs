use std::collections::HashSet;

use anyhow::Context;
#[cfg(feature = "local-api")]
use tunnet_core::direct::MembershipEntry;
use tunnet_core::direct::{
    AddressPlan, ConnectivityOptions, GENESIS_SCHEMA_VERSION, Genesis, JOIN_ALPN, JoinStatus,
    MEMBER_SCHEMA_VERSION, MemberRole, NetworkGrant, allocate_peer_ip, apply_connectivity,
    decode_and_preflight, endpoint_builder, generate_coordinator_keypair, grant_expiry,
    network_id_from_topic, relay_auth_denied_detail, run_join_client_notified, sign_genesis,
    sign_grant, sign_member_record, topic_from_name_secret, validate_peer_cidr, verify_admission,
};
use tunnet_core::{
    DirectState, PersistedState, SealPolicy, StatePaths, TunnetConfig, load_agent, persist_agent,
};

fn log_join_paths(conn: &iroh::endpoint::Connection) {
    let paths = conn.paths();
    let selected = paths
        .iter()
        .find(|p| p.is_selected())
        .map(|p| p.remote_addr().to_string());
    let relays: Vec<_> = paths
        .iter()
        .filter(|p| p.is_relay())
        .map(|p| p.remote_addr().to_string())
        .collect();
    let ips: Vec<_> = paths
        .iter()
        .filter(|p| p.is_ip())
        .map(|p| p.remote_addr().to_string())
        .collect();
    tracing::info!(
        ?selected,
        ?relays,
        ?ips,
        open = paths.len(),
        "join connection paths"
    );
}

#[derive(Debug)]
pub struct CreateArgs {
    pub hostname: Option<String>,
    pub open: bool,
    pub network_name: Option<String>,
    pub secret: Option<String>,
    pub cidr: Option<String>,
    pub no_encrypt_state: bool,
}

pub struct JoinArgs {
    pub invite_code: String,
    pub hostname: Option<String>,
    pub auto_accept_firewall: bool,
    pub no_encrypt_state: bool,
    pub on_pending: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
    pub cancel: Option<tokio_util::sync::CancellationToken>,
}

#[cfg(feature = "local-api")]
#[derive(Debug)]
pub struct UpgradeArgs {
    pub control_url: String,
    pub token: Option<String>,
}

#[cfg(feature = "local-api")]
#[derive(Debug)]
pub struct LeaveArgs {
    pub network: Option<String>,
    pub name: Option<String>,
}

pub struct DirectCreateOutcome {
    pub network_name: String,
    pub network_id: uuid::Uuid,
    pub endpoint_id: String,
    pub ipv4: std::net::Ipv4Addr,
}

fn paths(state_dir: Option<&str>) -> StatePaths {
    StatePaths::resolve(state_dir)
}

fn hostname_arg(explicit: Option<String>) -> String {
    explicit
        .or_else(|| std::env::var("HOSTNAME").ok())
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| "tunnet-node".into())
}

pub fn collect_host_nets() -> Vec<ipnet::Ipv4Net> {
    let mut out = Vec::new();
    for iface in netdev::get_interfaces() {
        for n in iface.ipv4 {
            if let Ok(net) = ipnet::Ipv4Net::new(n.addr(), n.prefix_len()) {
                out.push(net.trunc());
            }
        }
    }
    out.sort_by_key(|n| (u32::from(n.network()), n.prefix_len()));
    out.dedup();
    out
}

fn existing_plans(networks: &[DirectState]) -> Vec<(uuid::Uuid, ipnet::Ipv4Net)> {
    networks
        .iter()
        .map(|d| (d.network_id, d.genesis.address_plan.peer_cidr))
        .collect()
}

pub async fn persist_direct_create(
    args: CreateArgs,
    state_dir: Option<&str>,
) -> anyhow::Result<DirectCreateOutcome> {
    let paths = paths(state_dir);
    paths.ensure()?;
    let existing = PersistedState::try_load(&paths)?;
    if let Some(PersistedState::Managed(m)) = &existing {
        anyhow::bail!(
            "already enrolled in Managed network '{}'; run `tunnet reset --yes` first",
            m.network_name
        );
    }

    let hostname = hostname_arg(args.hostname);
    let network_name = args
        .network_name
        .unwrap_or_else(|| "direct".into())
        .to_ascii_lowercase();
    if !tunnet_common::validate_network_name(&network_name) {
        anyhow::bail!("invalid network name (3-32 lowercase alphanumeric/hyphen)");
    }

    let join_secret = match args.secret {
        Some(s) => {
            if s.len() < 8 {
                anyhow::bail!("--secret must be at least 8 characters");
            }
            hex::encode(s.as_bytes())
        }
        None => hex::encode(rand::random::<[u8; 32]>()),
    };

    let (coord_sk, coord_vk) = generate_coordinator_keypair();
    let coord_vk_hex = hex::encode(coord_vk.to_bytes());
    let coord_sk_hex = hex::encode(coord_sk.to_bytes());
    let content_key = hex::encode(rand::random::<[u8; 32]>());

    let topic_hash = topic_from_name_secret(&network_name, &join_secret);
    let network_id = network_id_from_topic(&topic_hash);
    let policy = SealPolicy::from_env_and_flag(args.no_encrypt_state);

    let (identity, mut networks) = match existing {
        Some(PersistedState::Direct { networks }) => {
            let (identity, _, _) = load_agent(&paths, policy)?;
            if networks
                .iter()
                .any(|d| d.network_name.eq_ignore_ascii_case(&network_name))
            {
                anyhow::bail!("already joined Direct network '{network_name}'");
            }
            if networks.iter().any(|d| d.network_id == network_id) {
                anyhow::bail!("network id collision with an existing Direct network");
            }
            (identity, networks)
        }
        _ => {
            let (secrets, _) = tunnet_core::secret_store::load_or_create_secrets(&paths, policy)?;
            (secrets.identity(), Vec::new())
        }
    };
    let my_id = identity.endpoint_id_hex();

    let host_nets = collect_host_nets();
    let plans = existing_plans(&networks);
    let address_plan = if let Some(cidr_str) = args.cidr.as_deref() {
        let cidr: ipnet::Ipv4Net = cidr_str.parse().context("invalid --cidr")?;
        validate_peer_cidr(&cidr, &plans, &host_nets)
            .map_err(|e| anyhow::anyhow!("invalid --cidr {cidr_str}: {e}"))?;
        AddressPlan { peer_cidr: cidr }
    } else {
        tunnet_core::direct::select_peer_cidr(&plans, &host_nets)
            .map_err(|e| anyhow::anyhow!("no safe IPv4 peer range on this host: {e}"))?
    };
    for d in &networks {
        let other = d.genesis.address_plan.peer_cidr;
        let cidr = address_plan.peer_cidr;
        if cidr.contains(&other.network())
            || cidr.contains(&other.broadcast())
            || other.contains(&cidr.network())
            || other.contains(&cidr.broadcast())
        {
            anyhow::bail!(
                "new network CIDR {cidr} overlaps active Direct network '{}' ({other})",
                d.network_name
            );
        }
    }

    let created_at = jiff::Timestamp::now();
    let genesis = sign_genesis(
        &coord_sk,
        Genesis {
            schema_version: GENESIS_SCHEMA_VERSION,
            network_id,
            network_name: network_name.clone(),
            coordinator_endpoint_id: my_id.clone(),
            coordinator_verifying_key: coord_vk_hex.clone(),
            address_plan,
            created_at,
            sig: String::new(),
        },
    )?;

    let occupied = HashSet::new();
    let self_ip = allocate_peer_ip(&address_plan, &network_id, &my_id, &occupied)
        .map_err(|e| anyhow::anyhow!("address allocation failed: {e}"))?;

    let issued_at = jiff::Timestamp::now();
    let self_grant = sign_grant(
        &coord_sk,
        NetworkGrant {
            network_id,
            endpoint_id: my_id.clone(),
            role: MemberRole::Coordinator,
            network_epoch: 0,
            issued_at,
            expires_at: grant_expiry(issued_at)?,
            content_key: content_key.clone(),
            sig: String::new(),
        },
    )?;
    let self_record = sign_member_record(
        &coord_sk,
        tunnet_core::direct::SignedMemberRecord {
            schema_version: MEMBER_SCHEMA_VERSION,
            network_id,
            endpoint_id: my_id.clone(),
            hostname: hostname.clone(),
            ipv4: self_ip,
            tags: vec![],
            status: "active".into(),
            ssh_host_key: None,
            sequence: 1,
            joined_at: created_at,
            grant: self_grant.clone(),
            endpoint_sig: String::new(),
            coordinator: true,
        },
    )?;
    let grant_json = serde_json::to_string(&self_grant)?;

    networks.push(DirectState {
        network_name: network_name.clone(),
        join_secret: join_secret.clone(),
        topic_hash,
        network_id,
        coordinator: true,
        open: args.open,
        hostname: hostname.clone(),
        coordinator_endpoint_id: Some(my_id.clone()),
        coordinator_verifying_key: Some(coord_vk_hex),
        network_epoch: 0,
        genesis,
        self_record,
        doc_ticket: None,
        namespace_id: None,
        coordinator_signing_key: Some(coord_sk_hex),
        network_grant: Some(grant_json),
        content_key: Some(content_key),
        auto_accept_firewall: false,
        created_at,
    });
    let persisted = PersistedState::Direct { networks };
    let tier = persist_agent(&paths, &identity, persisted, policy)?;
    {
        use tunnet_core::TunnetConfig;
        let mut cfg = TunnetConfig::from_persisted(&paths)?;
        cfg.upsert_direct(&network_name, &hostname, args.open, false);
        cfg.save(&paths)?;
    }

    tracing::info!(
        network = %network_name,
        endpoint_id = %my_id,
        ip = %self_ip,
        cidr = %address_plan.peer_cidr,
        seal = %tier.as_str(),
        "created Direct network"
    );

    Ok(DirectCreateOutcome {
        network_name,
        network_id,
        endpoint_id: my_id,
        ipv4: self_ip,
    })
}

pub struct DirectJoinOutcome {
    pub network_name: String,
    pub network_id: uuid::Uuid,
    pub endpoint_id: String,
    pub ipv4: std::net::Ipv4Addr,
}

pub async fn persist_direct_join(
    args: JoinArgs,
    state_dir: Option<&str>,
) -> anyhow::Result<DirectJoinOutcome> {
    let paths = paths(state_dir);
    paths.ensure()?;

    let hostname = hostname_arg(args.hostname);
    let policy = SealPolicy::from_env_and_flag(args.no_encrypt_state);

    let loaded = PersistedState::try_load(&paths)?;
    let (identity, existing_networks) = match loaded {
        Some(PersistedState::Managed(m)) => anyhow::bail!(
            "already enrolled in Managed network '{}'; run `tunnet reset --yes` first",
            m.network_name
        ),
        Some(PersistedState::Direct { networks }) => {
            let (id, _, _) = load_agent(&paths, policy)?;
            (id, networks)
        }
        None => {
            let (secrets, _) = tunnet_core::secret_store::load_or_create_secrets(&paths, policy)?;
            (secrets.identity(), Vec::new())
        }
    };

    let invite = decode_and_preflight(
        &args.invite_code,
        &existing_plans(&existing_networks),
        &collect_host_nets(),
    )?;
    let network_id = invite.genesis.network_id;
    let network_name = invite.genesis.network_name.clone();
    if existing_networks
        .iter()
        .any(|d| d.network_name.eq_ignore_ascii_case(&network_name))
    {
        anyhow::bail!("already joined Direct network '{network_name}'");
    }
    if existing_networks.iter().any(|d| d.network_id == network_id) {
        anyhow::bail!("already joined this Direct network id");
    }

    let my_id = identity.endpoint_id_hex();
    let secret = iroh::SecretKey::from_bytes(&identity.secret_bytes);
    let agent_cfg = TunnetConfig::try_load(&paths)?.unwrap_or_default();
    if let Err(errs) = agent_cfg.validate() {
        anyhow::bail!("invalid tunnet.toml: {}", errs.join("; "));
    }
    let credentials = tunnet_core::secret_store::load_relay_auth(&paths).unwrap_or_default();
    let mut connectivity =
        ConnectivityOptions::from_direct_config(&agent_cfg, credentials, None, None)
            .context("resolve Direct relay policy")?;
    crate::host_constraints::constrain_lan(&mut connectivity);
    let dial = tunnet_core::direct::join_dial_addr(&invite).context("coordinator dial address")?;
    // iroh 1.2 `SendDatagram` uses only `selected_path` once an IP path exists.
    // Unreachable join-client IPs (emulator NAT, CGNAT) then starve a working
    // relay for the rest of the handshake. This ephemeral endpoint is relay-only;
    // the mesh endpoint created after admission still binds IP + discovery.
    let relay_bootstrap = dial.relay_urls().next().is_some();
    if relay_bootstrap {
        connectivity.enable_mdns = false;
        connectivity.enable_dht = false;
    }
    tracing::info!(
        relay = connectivity.relay.kind(),
        mdns = connectivity.enable_mdns,
        dht = connectivity.enable_dht,
        "join using Direct relay policy"
    );
    let mut builder = apply_connectivity(
        endpoint_builder(&connectivity)
            .secret_key(secret)
            .alpns(vec![JOIN_ALPN.to_vec()]),
        &connectivity,
    );
    if relay_bootstrap {
        builder = builder.clear_address_lookup().clear_ip_transports();
    }
    let endpoint = builder.bind().await.context("bind join endpoint")?;

    let saw_pending = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let join_result = async {
        match tokio::time::timeout(std::time::Duration::from_secs(10), endpoint.online()).await {
            Ok(()) => tracing::info!("join endpoint online"),
            Err(_) => match relay_auth_denied_detail(&endpoint) {
                Some((url, reason)) => tracing::error!(
                    %url,
                    %reason,
                    "relay denied authentication (check relay auth token); attempting join connect anyway"
                ),
                None => tracing::warn!("relay not ready yet; attempting join connect anyway"),
            },
        }
        let relay_urls: Vec<String> = dial.relay_urls().map(|u| u.to_string()).collect();
        let ip_v4: Vec<_> = dial.ip_addrs().filter(|a| a.is_ipv4()).copied().collect();
        let ip_v6: Vec<_> = dial.ip_addrs().filter(|a| a.is_ipv6()).copied().collect();
        tracing::info!(
            coordinator = %dial.id,
            ?relay_urls,
            ?ip_v4,
            ?ip_v6,
            "connecting to coordinator"
        );
        let mut delay = std::time::Duration::from_millis(400);
        loop {
            if args
                .cancel
                .as_ref()
                .is_some_and(|c| c.is_cancelled())
            {
                anyhow::bail!("join cancelled");
            }
            let connect = async {
                let conn = endpoint
                    .connect(dial.clone(), JOIN_ALPN)
                    .await
                    .map_err(|e| anyhow::anyhow!("connect to coordinator: {e:#}"))?;
                log_join_paths(&conn);
                let pending_flag = saw_pending.clone();
                let on_pending_hook = args.on_pending.clone();
                let resp = run_join_client_notified(
                    &conn,
                    &invite.invite_secret,
                    &hostname,
                    move || {
                        pending_flag.store(true, std::sync::atomic::Ordering::SeqCst);
                        if let Some(cb) = &on_pending_hook {
                            cb();
                        }
                    },
                )
                .await
                .context("direct join")?;
                conn.close(0u32.into(), b"join_done");
                Ok::<_, anyhow::Error>(resp)
            };
            let resp = if let Some(cancel) = &args.cancel {
                tokio::select! {
                    _ = cancel.cancelled() => anyhow::bail!("join cancelled"),
                    r = connect => r,
                }
            } else {
                connect.await
            };
            match resp {
                Ok(resp) => match resp.status {
                    JoinStatus::Admitted => {
                        let admission = resp.admission.context("missing admission")?;
                        verify_admission(&invite, &my_id, &hostname, &admission)?;
                        break Ok(admission);
                    }
                    JoinStatus::Denied => {
                        anyhow::bail!(
                            "join denied: {}",
                            resp.reason.as_deref().unwrap_or("denied")
                        )
                    }
                    JoinStatus::Expired => {
                        anyhow::bail!(
                            "join expired: {}",
                            resp.reason.as_deref().unwrap_or("expired")
                        )
                    }
                    JoinStatus::Pending => {
                        saw_pending.store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                },
                Err(e) if saw_pending.load(std::sync::atomic::Ordering::SeqCst) => {
                    tracing::warn!(?e, "join session dropped while pending; reconnecting");
                }
                Err(e) => return Err(e),
            }
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(std::time::Duration::from_secs(5));
        }
    }
    .await;

    endpoint.close().await;
    let admission = join_result?;
    let ipv4 = admission.ipv4;
    let network_grant = Some(serde_json::to_string(&admission.network_grant)?);

    let mut networks = existing_networks;
    networks.push(DirectState {
        network_name: network_name.clone(),
        join_secret: String::new(),
        topic_hash: admission.topic_hash.clone(),
        network_id,
        coordinator: false,
        open: false,
        hostname: hostname.clone(),
        coordinator_endpoint_id: Some(invite.genesis.coordinator_endpoint_id.clone()),
        coordinator_verifying_key: Some(invite.genesis.coordinator_verifying_key.clone()),
        network_epoch: admission.network_grant.network_epoch,
        genesis: admission.genesis,
        self_record: admission.member_record,
        doc_ticket: Some(admission.doc_ticket),
        namespace_id: None,
        coordinator_signing_key: None,
        network_grant,
        content_key: Some(admission.content_key),
        auto_accept_firewall: args.auto_accept_firewall,
        created_at: jiff::Timestamp::now(),
    });
    let persisted = PersistedState::Direct { networks };
    let tier = persist_agent(&paths, &identity, persisted, policy)?;
    {
        use tunnet_core::TunnetConfig;
        let mut cfg = TunnetConfig::from_persisted(&paths)?;
        cfg.upsert_direct(&network_name, &hostname, false, false);
        cfg.save(&paths)?;
    }
    tracing::info!(
        network = %network_name,
        endpoint_id = %my_id,
        %ipv4,
        seal = %tier.as_str(),
        "joined Direct network"
    );

    Ok(DirectJoinOutcome {
        network_name,
        network_id,
        endpoint_id: my_id,
        ipv4,
    })
}

#[cfg(feature = "local-api")]
pub async fn run_upgrade(args: UpgradeArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let paths = paths(state_dir);
    let policy = SealPolicy::from_env_and_flag(false);
    let (identity, persisted, _) = load_agent(&paths, policy)?;
    let direct = persisted.require_direct_network(None)?.clone();
    if !direct.coordinator {
        anyhow::bail!("only the coordinator should run upgrade-to-managed first");
    }

    let members_path = paths.members_cache_file();
    let members: Vec<MembershipEntry> = if members_path.exists() {
        serde_json::from_slice(&std::fs::read(&members_path)?).unwrap_or_default()
    } else {
        vec![]
    };

    let token = args
        .token
        .context("provide --token <enrollment token> from the dashboard")?;

    let import = serde_json::json!({
        "direct_network_name": direct.network_name,
        "topic_hash": direct.topic_hash,
        "namespace_id": direct.namespace_id,
        "members": members,
        "coordinator_endpoint_id": identity.endpoint_id_hex(),
    });

    let client = tunnet_core::UnauthedClient::new(args.control_url.clone())?;
    let meta =
        crate::system_info::collect_system_metadata(&direct.hostname, env!("CARGO_PKG_VERSION"));
    let resp = client
        .enroll(tunnet_common::EnrollRequest {
            enrollment_token: Some(token.clone()),
            organization_slug: None,
            network_id: None,
            network_name: Some(direct.network_name.clone()),
            endpoint_id: identity.endpoint_id_hex(),
            hostname: direct.hostname.clone(),
            os: std::env::consts::OS.to_string(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            metadata: Some(serde_json::json!({
                "direct_upgrade": import,
                "system": meta,
            })),
            labels: None,
            expires_in: None,
        })
        .await
        .context("enroll into Managed during upgrade")?;

    if resp.status == "pending" {
        anyhow::bail!("upgrade enroll is pending approval; approve in the dashboard then re-run");
    }

    let managed = PersistedState::Managed(tunnet_core::ManagedState {
        control_url: args.control_url.clone(),
        network_name: resp.network_name.clone(),
        network_id: resp.network_id,
        organization_id: resp.organization_id,
        enrolled_at: jiff::Timestamp::now(),
        management_url: None,
        dashboard_url: None,
        local_ui: tunnet_common::local_api::LocalUiPolicy::default(),
    });
    persist_agent(&paths, &identity, managed, policy)?;
    tunnet_core::state::save_snapshot_cache(&paths, &resp.snapshot)?;

    let notice = serde_json::json!({
        "type": "upgrade_to_managed",
        "control_url": args.control_url,
        "enrollment_token": token,
        "network_id": resp.network_id,
        "network_name": resp.network_name,
    });
    std::fs::write(
        paths.upgrade_notice_file(),
        serde_json::to_vec_pretty(&notice)?,
    )?;

    println!(
        "Upgraded to Managed network '{}'. Restart with `tunnetd`. \
         Peers should pick up the upgrade notice or re-enroll with the same token.",
        resp.network_name
    );
    Ok(())
}

#[cfg(feature = "local-api")]
pub async fn run_leave(args: LeaveArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let paths = paths(state_dir);
    let policy = SealPolicy::from_env_and_flag(false);
    let name = args.network.or(args.name);
    let nname = tunnet_core::leave_direct_network(&paths, policy, name.as_deref())?;
    println!("Left Direct network '{nname}'. Restart the agent to apply.");
    #[cfg(feature = "local-api")]
    crate::cmds::finish_after_config(state_dir, true).await?;
    Ok(())
}

#[cfg(test)]
mod live_join {
    use super::*;

    #[tokio::test]
    #[ignore = "live coordinator"]
    async fn relay_only_connect_join_alpn() {
        let code = std::env::var("TUNNET_LIVE_INVITE").expect("TUNNET_LIVE_INVITE");
        let invite = tunnet_core::direct::decode_invite(&code).unwrap();
        let dial = tunnet_core::direct::join_dial_addr(&invite).unwrap();
        let opts = tunnet_core::direct::ConnectivityOptions::direct_default(false);
        let ep = apply_connectivity(endpoint_builder(&opts), &opts)
            .alpns(vec![JOIN_ALPN.to_vec()])
            .clear_address_lookup()
            .clear_ip_transports()
            .bind()
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(15), ep.online())
            .await
            .expect("join probe online");
        let conn = tokio::time::timeout(
            std::time::Duration::from_secs(35),
            ep.connect(dial, JOIN_ALPN),
        )
        .await
        .expect("connect wait")
        .unwrap_or_else(|e| panic!("connect JOIN_ALPN: {e:#}"));
        conn.close(0u32.into(), b"probe");
    }

    #[tokio::test]
    #[ignore = "live coordinator"]
    async fn lan_ip_only_connect_join_alpn() {
        let code = std::env::var("TUNNET_LIVE_INVITE").expect("TUNNET_LIVE_INVITE");
        let invite = tunnet_core::direct::decode_invite(&code).unwrap();
        let stamped = invite
            .coordinator_addr
            .clone()
            .expect("invite missing coordinator_addr");
        let lan: Vec<_> = stamped
            .ip_addrs()
            .filter(|a| match a.ip() {
                std::net::IpAddr::V4(v4) => v4.is_private() && !v4.is_loopback(),
                std::net::IpAddr::V6(_) => false,
            })
            .copied()
            .collect();
        assert!(!lan.is_empty(), "no private IPv4 on invite: {stamped:?}");
        let mut dial = iroh::EndpointAddr::new(stamped.id);
        for ip in lan {
            if ip.ip() == std::net::Ipv4Addr::new(192, 168, 1, 80) {
                dial.addrs.insert(iroh::TransportAddr::Ip(ip));
            }
        }
        if dial.ip_addrs().next().is_none() {
            dial.addrs.insert(iroh::TransportAddr::Ip(
                stamped.ip_addrs().next().copied().unwrap(),
            ));
        }
        let opts = tunnet_core::direct::ConnectivityOptions {
            relay: tunnet_core::direct::EffectiveRelayPolicy::Disabled,
            enable_dht: false,
            enable_mdns: false,
            enable_lan_discovery: false,
        };
        let ep = apply_connectivity(endpoint_builder(&opts), &opts)
            .alpns(vec![JOIN_ALPN.to_vec()])
            .clear_address_lookup()
            .bind()
            .await
            .unwrap();
        tracing::info!(?dial, "LAN-only JOIN dial");
        let conn = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            ep.connect(dial, JOIN_ALPN),
        )
        .await
        .expect("connect wait")
        .unwrap_or_else(|e| panic!("connect JOIN_ALPN via LAN IP: {e:#}"));
        conn.close(0u32.into(), b"probe");
    }

    #[tokio::test]
    #[ignore = "live coordinator"]
    async fn snapshot_ips_connect_join_alpn() {
        let code = std::env::var("TUNNET_LIVE_INVITE").expect("TUNNET_LIVE_INVITE");
        let invite = tunnet_core::direct::decode_invite(&code).unwrap();
        let dial = invite
            .coordinator_addr
            .clone()
            .expect("invite missing coordinator_addr");
        let opts = tunnet_core::direct::ConnectivityOptions::direct_default(false);
        let ep = apply_connectivity(endpoint_builder(&opts), &opts)
            .alpns(vec![JOIN_ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let conn = tokio::time::timeout(
            std::time::Duration::from_secs(35),
            ep.connect(dial, JOIN_ALPN),
        )
        .await
        .expect("connect wait")
        .unwrap_or_else(|e| panic!("connect JOIN_ALPN via snapshot IPs: {e:#}"));
        conn.close(0u32.into(), b"probe");
    }
}

#[cfg(test)]
mod join_identity {
    use super::*;

    #[test]
    fn pending_join_reuses_persisted_identity() {
        let dir = tempfile::tempdir().unwrap();
        let paths = StatePaths::resolve(Some(dir.path().to_str().unwrap()));
        paths.ensure().unwrap();
        let policy = SealPolicy::from_env_and_flag(true);
        let (a, _) = tunnet_core::secret_store::load_or_create_secrets(&paths, policy).unwrap();
        let (b, _) = tunnet_core::secret_store::load_or_create_secrets(&paths, policy).unwrap();
        assert_eq!(
            a.identity().endpoint_id_hex(),
            b.identity().endpoint_id_hex()
        );
        assert!(paths.secrets_file().is_file());
        assert!(PersistedState::try_load(&paths).unwrap().is_none());
    }
}
