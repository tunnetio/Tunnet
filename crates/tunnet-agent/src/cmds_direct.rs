use std::collections::HashSet;

use anyhow::Context;
use clap::Args;
use tunnet_core::direct::{
    AddressPlan, ConnectivityOptions, GENESIS_SCHEMA_VERSION, Genesis, JOIN_ALPN, JoinStatus,
    MEMBER_SCHEMA_VERSION, MemberRole, MembershipEntry, NetworkGrant, allocate_peer_ip,
    apply_connectivity, decode_and_preflight, endpoint_builder, generate_coordinator_keypair,
    grant_expiry, network_id_from_topic, run_join_client, sign_genesis, sign_grant,
    sign_member_record, topic_from_name_secret, validate_peer_cidr, verify_admission,
};
use tunnet_core::{
    AgentIdentity, DirectState, PersistedState, SealPolicy, StatePaths, TunnetConfig, load_agent,
    persist_agent,
};

#[derive(Args, Debug)]
pub struct CreateArgs {
    #[arg(long, env = "TUNNET_HOSTNAME")]
    pub hostname: Option<String>,
    #[arg(long)]
    pub open: bool,
    #[arg(long = "name")]
    pub network_name: Option<String>,
    #[arg(long)]
    pub secret: Option<String>,
    #[arg(long)]
    pub cidr: Option<String>,
    #[arg(long, env = "TUNNET_NO_ENCRYPT_STATE")]
    pub no_encrypt_state: bool,
}

#[derive(Args, Debug)]
pub struct JoinArgs {
    pub invite_code: String,
    #[arg(long, env = "TUNNET_HOSTNAME")]
    pub hostname: Option<String>,
    #[arg(long)]
    pub auto_accept_firewall: bool,
    #[arg(long, env = "TUNNET_NO_ENCRYPT_STATE")]
    pub no_encrypt_state: bool,
}

#[derive(Args, Debug)]
pub struct UpgradeArgs {
    #[arg(
        long,
        env = "CONTROL_PLANE_URL",
        default_value = "http://127.0.0.1:8080"
    )]
    pub control_url: String,
    #[arg(long, env = "TUNNET_ENROLL_TOKEN")]
    pub token: Option<String>,
}

#[derive(Args, Debug)]
pub struct LeaveArgs {
    #[arg(long)]
    pub network: Option<String>,
    pub name: Option<String>,
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

pub async fn run_create(args: CreateArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let paths = paths(state_dir);
    paths.ensure()?;
    let existing = PersistedState::try_load(&paths)?;
    if let Some(PersistedState::Managed(m)) = &existing {
        anyhow::bail!(
            "already enrolled in Managed network '{}'; run `tunnet reset --yes` first",
            m.network_name
        );
    }
    let had_networks =
        matches!(&existing, Some(PersistedState::Direct { networks }) if !networks.is_empty());

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
        _ => (AgentIdentity::generate(), Vec::new()),
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

    println!(
        "Created Direct network '{}'. endpoint_id={} ip={} cidr={} (secrets: {})",
        network_name,
        my_id,
        self_ip,
        address_plan.peer_cidr,
        tier.as_str()
    );
    println!("State directory: {}", paths.dir.display());
    crate::cmds::finish_after_config(state_dir, had_networks).await?;
    println!("Next: `tunnet invite` and share the code.");
    Ok(())
}

pub async fn run_join(args: JoinArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let paths = paths(state_dir);
    paths.ensure()?;

    let hostname = hostname_arg(args.hostname);
    let policy = SealPolicy::from_env_and_flag(args.no_encrypt_state);

    let loaded = PersistedState::try_load(&paths)?;
    let had_networks =
        matches!(&loaded, Some(PersistedState::Direct { networks }) if !networks.is_empty());
    let (identity, existing_networks) = match loaded {
        Some(PersistedState::Managed(m)) => anyhow::bail!(
            "already enrolled in Managed network '{}'; run `tunnet reset --yes` first",
            m.network_name
        ),
        Some(PersistedState::Direct { networks }) => {
            let (id, _, _) = load_agent(&paths, policy)?;
            (id, networks)
        }
        None => (AgentIdentity::generate(), Vec::new()),
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
    let connectivity = ConnectivityOptions::from_direct_config(&agent_cfg, credentials, None, None)
        .context("resolve Direct relay policy")?;
    tracing::info!(
        relay = connectivity.relay.kind(),
        "join using Direct relay policy"
    );
    let endpoint = apply_connectivity(
        endpoint_builder(&connectivity)
            .secret_key(secret)
            .alpns(vec![JOIN_ALPN.to_vec()]),
        &connectivity,
    )
    .bind()
    .await
    .context("bind join endpoint")?;

    let join_result = async {
        match tokio::time::timeout(std::time::Duration::from_secs(10), endpoint.online()).await {
            Ok(()) => tracing::info!("join endpoint online"),
            Err(_) => tracing::warn!("relay not ready yet; attempting join connect anyway"),
        }

        let coord: iroh::EndpointId = invite
            .genesis
            .coordinator_endpoint_id
            .parse()
            .context("invalid coordinator endpoint id in invite")?;
        let conn = endpoint
            .connect(coord, JOIN_ALPN)
            .await
            .context("connect to coordinator")?;
        let resp = run_join_client(&conn, &invite.invite_secret, &hostname)
            .await
            .context("direct join")?;
        conn.close(0u32.into(), b"join_done");
        match resp.status {
            JoinStatus::Pending => anyhow::bail!(
                "join pending approval; retry the same invite after the coordinator accepts this endpoint"
            ),
            JoinStatus::Denied => {
                anyhow::bail!(
                    "join denied: {}",
                    resp.reason.as_deref().unwrap_or("denied")
                )
            }
            JoinStatus::Admitted => {
                let admission = resp.admission.context("missing admission")?;
                verify_admission(&invite, &my_id, &hostname, &admission)?;
                Ok(admission)
            }
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

    println!(
        "Joined Direct network '{}'. endpoint_id={} ip={} (secrets: {})",
        network_name,
        my_id,
        ipv4,
        tier.as_str()
    );
    crate::cmds::finish_after_config(state_dir, had_networks).await?;
    Ok(())
}
pub async fn run_upgrade(args: UpgradeArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let paths = paths(state_dir);
    let policy = SealPolicy::from_env_and_flag(false);
    let (identity, persisted, _) = load_agent(&paths, policy)?;
    let direct = persisted.require_direct_network(None)?.clone();
    if !direct.coordinator {
        anyhow::bail!("only the coordinator should run upgrade-to-managed first");
    }

    let members_path = paths.dir.join("direct_members_cache.json");
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
        paths.dir.join("upgrade_notice.json"),
        serde_json::to_vec_pretty(&notice)?,
    )?;

    println!(
        "Upgraded to Managed network '{}'. Restart with `tunnetd`. \
         Peers should pick up the upgrade notice or re-enroll with the same token.",
        resp.network_name
    );
    Ok(())
}

pub async fn run_leave(args: LeaveArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let paths = paths(state_dir);
    let policy = SealPolicy::from_env_and_flag(false);
    let name = args.network.or(args.name);
    let nname = tunnet_core::leave_direct_network(&paths, policy, name.as_deref())?;
    println!("Left Direct network '{nname}'. Restart the agent to apply.");
    crate::cmds::finish_after_config(state_dir, true).await?;
    Ok(())
}
