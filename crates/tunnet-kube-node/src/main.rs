use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, bail};
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use clap::{Args, Parser, Subcommand};
use metrics::{describe_counter, describe_gauge, gauge};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tokio::net::TcpListener;
use tunnet_common::RedirectRule;
use tunnet_core::{
    AgentIdentity, CoreNode, CoreNodeConfig, PeerInfo, PersistedState, SealPolicy, SignedClient,
    StatePaths, StreamHandler, dial_stream, load_agent, stream_handler,
};

#[derive(Parser, Debug)]
#[command(
    name = "tunnet-kube-node",
    about = "Lightweight Tunnet CoreNode for Kubernetes",
    version = env!("CARGO_PKG_VERSION")
)]
struct Cli {
    #[arg(long, env = "TUNNET_STATE_DIR", default_value = "/var/lib/tunnet")]
    state_dir: String,

    /// Pod name (StatefulSet ordinal). Used to pick the projected identity secret.
    #[arg(long, env = "POD_NAME")]
    pod_name: Option<String>,

    #[arg(long, env = "HOSTNAME")]
    hostname: Option<String>,

    /// Maps to [`CoreNodeConfig::kind`] (e.g. k8s-connector, k8s-ingress).
    #[arg(long, env = "TUNNET_KIND")]
    kind: Option<String>,

    #[arg(long, env = "TUNNET_HEALTH_BIND", default_value = "0.0.0.0:8080")]
    health_bind: String,

    /// When no subcommand is passed, resolve mode from this env (operator sets it).
    #[arg(long, env = "TUNNET_MODE")]
    mode_env: Option<String>,

    #[command(subcommand)]
    mode: Option<Mode>,
}

#[derive(Subcommand, Debug, Clone)]
enum Mode {
    /// Advertise subnet routes and proxy inbound mesh streams to the cluster.
    Connector(ConnectorArgs),
    /// Reverse-proxy on the mesh interface to a cluster Service.
    IngressProxy(IngressArgs),
    /// Public relay tunnel to a cluster target.
    TunnelProxy(TunnelArgs),
    /// Local TCP listener that dials a mesh peer via stream protocol.
    EgressProxy(EgressArgs),
    /// Mesh sidecar: CoreNode only (no extra proxies).
    Sidecar,
}

#[derive(Args, Debug, Clone)]
struct ConnectorArgs {
    /// CIDRs to advertise via the control plane (`create_subnet_route`).
    #[arg(
        long = "routes",
        env = "TUNNET_ADVERTISED_ROUTES",
        value_delimiter = ','
    )]
    routes: Vec<String>,
}

#[derive(Args, Debug, Clone)]
struct IngressArgs {
    #[arg(long, env = "TUNNET_SERVE_PORT")]
    serve_port: u16,
    /// ClusterIP:port (or host:port) upstream.
    #[arg(long, env = "TUNNET_TARGET_ADDR")]
    target_addr: String,
    #[arg(long, env = "TUNNET_INTERNAL_HOSTNAME")]
    internal_hostname: String,
    #[arg(long, env = "TUNNET_PROTOCOL", default_value = "tcp")]
    protocol: String,
}

#[derive(Args, Debug, Clone)]
struct TunnelArgs {
    #[arg(long, env = "TUNNET_TUNNEL_ID")]
    tunnel_id: String,
    #[arg(long, env = "TUNNET_RELAY_ENDPOINT")]
    relay_endpoint: String,
    #[arg(long, env = "TUNNET_SUBDOMAIN")]
    subdomain: String,
    #[arg(long, env = "TUNNET_PUBLIC_HOSTNAME")]
    public_hostname: String,
    #[arg(long, env = "TUNNET_LOCAL_PORT")]
    local_port: u16,
    #[arg(long, env = "TUNNET_PROTOCOL", default_value = "https")]
    protocol: String,
    #[arg(long, env = "TUNNET_AUTH_TOKEN")]
    auth_token: String,
    /// ClusterIP:port upstream (defaults to 127.0.0.1:local_port).
    #[arg(long, env = "TUNNET_TARGET_ADDR")]
    target_addr: Option<String>,
    /// JSON array of redirect rules (`RedirectRule`).
    #[arg(long, env = "TUNNET_REDIRECT_RULES")]
    redirect_rules: Option<String>,
}

#[derive(Args, Debug, Clone)]
struct EgressArgs {
    /// Local bind address, e.g. 0.0.0.0:8080
    #[arg(long, env = "TUNNET_EGRESS_LISTEN", default_value = "0.0.0.0:0")]
    listen: String,
    #[arg(long, env = "TUNNET_MESH_HOST")]
    mesh_host: String,
    #[arg(long, env = "TUNNET_MESH_PORT")]
    mesh_port: u16,
}

#[derive(Clone)]
struct HealthState {
    ready: Arc<AtomicBool>,
    metrics: KubeMetrics,
}

#[derive(Clone)]
struct KubeMetrics {
    handle: PrometheusHandle,
}

impl KubeMetrics {
    fn new() -> anyhow::Result<Self> {
        let handle = PrometheusBuilder::new().install_recorder()?;
        describe_gauge!("tunnet_kube_ready", "1 when the node finished mode setup");
        describe_counter!(
            "tunnet_kube_egress_connections_total",
            "Egress proxy connections"
        );

        let upkeep = handle.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                upkeep.run_upkeep();
            }
        });

        Ok(Self { handle })
    }

    fn render(&self) -> String {
        self.handle.render()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logging();
    let cli = Cli::parse();
    let mode = resolve_mode(&cli)?;

    let state_root = resolve_state_dir(&cli.state_dir, cli.pod_name.as_deref());
    let paths = StatePaths::resolve(Some(state_root.to_str().unwrap_or("/var/lib/tunnet")));
    paths.ensure().context("ensure state dir")?;
    bootstrap_identity_from_env(&paths).context("bootstrap identity from secret")?;

    let (identity, persisted) = load_identity(&paths).context("load kube-node identity")?;

    let hostname = cli
        .hostname
        .unwrap_or_else(|| std::env::var("HOSTNAME").unwrap_or_else(|_| "tunnet-kube-node".into()));
    let kind = resolve_kind(cli.kind.as_deref(), &mode)?;

    let metrics = KubeMetrics::new().context("metrics")?;
    let ready = Arc::new(AtomicBool::new(false));
    let health = HealthState {
        ready: ready.clone(),
        metrics: metrics.clone(),
    };
    spawn_health_server(cli.health_bind.clone(), health);

    let node = Arc::new(
        CoreNode::bootstrap(
            identity,
            persisted,
            paths,
            CoreNodeConfig {
                hostname,
                poll_secs: 30,
                kind,
                agent_version: env!("CARGO_PKG_VERSION"),
                advertise_datagram_alpn: false,
                enable_mdns: false,
                ..Default::default()
            },
        )
        .await
        .context("bootstrap CoreNode")?,
    );

    let stream_handler = match &mode {
        Mode::Connector(_) => stream_handler(node.routes.clone()),
        _ => noop_stream_handler(),
    };
    let _router = spawn_unified_acceptor(node.clone(), stream_handler);

    match &mode {
        Mode::Connector(args) => setup_connector(node.as_ref(), args).await?,
        Mode::IngressProxy(args) => setup_ingress(node.as_ref(), args).await?,
        Mode::TunnelProxy(args) => setup_tunnel(node.as_ref(), args).await?,
        Mode::EgressProxy(args) => spawn_egress_proxy(node.clone(), args).await?,
        Mode::Sidecar => {
            tracing::info!("sidecar mode: CoreNode only");
        }
    }

    ready.store(true, Ordering::Relaxed);
    gauge!("tunnet_kube_ready").set(1.0);
    tracing::info!(%kind, endpoint_id = %node.endpoint_id_hex(), "tunnet-kube-node ready");

    tokio::signal::ctrl_c().await.context("ctrl_c")?;
    tracing::info!("shutting down");
    node.shutdown().await;
    Ok(())
}

fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new("info,tunnet_kube_node=debug,tunnet_core=debug")
    });
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn resolve_mode(cli: &Cli) -> anyhow::Result<Mode> {
    if let Some(mode) = &cli.mode {
        return Ok(mode.clone());
    }
    let Some(raw) = cli.mode_env.as_deref() else {
        bail!("pass a mode subcommand or set TUNNET_MODE");
    };
    Ok(match raw {
        "connector" => Mode::Connector(ConnectorArgs {
            routes: std::env::var("TUNNET_ADVERTISED_ROUTES")
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect(),
        }),
        "ingress" | "ingress-proxy" => Mode::IngressProxy(IngressArgs {
            serve_port: env_u16("TUNNET_SERVE_PORT")?,
            target_addr: require_env("TUNNET_TARGET_ADDR")?,
            internal_hostname: require_env("TUNNET_INTERNAL_HOSTNAME")?,
            protocol: std::env::var("TUNNET_PROTOCOL").unwrap_or_else(|_| "tcp".into()),
        }),
        "tunnel" | "tunnel-proxy" => Mode::TunnelProxy(TunnelArgs {
            tunnel_id: require_env("TUNNET_TUNNEL_ID")?,
            relay_endpoint: require_env("TUNNET_RELAY_ENDPOINT")?,
            subdomain: require_env("TUNNET_SUBDOMAIN")?,
            public_hostname: require_env("TUNNET_PUBLIC_HOSTNAME")?,
            local_port: env_u16("TUNNET_LOCAL_PORT")?,
            protocol: std::env::var("TUNNET_PROTOCOL").unwrap_or_else(|_| "https".into()),
            auth_token: require_env("TUNNET_AUTH_TOKEN")?,
            target_addr: std::env::var("TUNNET_TARGET_ADDR").ok(),
            redirect_rules: std::env::var("TUNNET_REDIRECT_RULES").ok(),
        }),
        "egress" | "egress-proxy" => Mode::EgressProxy(EgressArgs {
            listen: std::env::var("TUNNET_EGRESS_LISTEN").unwrap_or_else(|_| "0.0.0.0:0".into()),
            mesh_host: require_env("TUNNET_MESH_HOST")?,
            mesh_port: env_u16("TUNNET_MESH_PORT")?,
        }),
        "sidecar" => Mode::Sidecar,
        other => bail!("unsupported TUNNET_MODE {other:?}"),
    })
}

fn require_env(key: &str) -> anyhow::Result<String> {
    std::env::var(key).with_context(|| format!("missing required env {key}"))
}

fn env_u16(key: &str) -> anyhow::Result<u16> {
    require_env(key)?
        .parse()
        .with_context(|| format!("parse {key} as u16"))
}

/// Prefer per-pod projected secret dir when POD_NAME is set.
fn resolve_state_dir(base: &str, pod_name: Option<&str>) -> PathBuf {
    let base = PathBuf::from(base);
    let Some(pod) = pod_name else {
        return base;
    };
    // Operator mounts projected secrets under /var/lib/tunnet/nodes/<pod-name>/
    let projected = base.join("nodes").join(pod);
    if projected.join("identity.hex").is_file() || projected.join("state.json").is_file() {
        return projected;
    }
    // Fallbacks for single-replica mounts at the root.
    base
}

/// Copy identity.hex / state.json from the mounted Secret into the writable state dir.
fn bootstrap_identity_from_env(paths: &StatePaths) -> anyhow::Result<()> {
    let Ok(boot) = std::env::var("TUNNET_BOOTSTRAP_DIR") else {
        return Ok(());
    };
    let boot = PathBuf::from(boot);
    if !boot.is_dir() {
        return Ok(());
    }
    std::fs::create_dir_all(&paths.dir)
        .with_context(|| format!("create state dir {}", paths.dir.display()))?;
    for name in ["identity.hex", "state.json"] {
        let src = boot.join(name);
        let dst = paths.dir.join(name);
        if src.is_file() {
            std::fs::copy(&src, &dst)
                .with_context(|| format!("copy {} -> {}", src.display(), dst.display()))?;
        }
    }
    Ok(())
}

/// Load identity from operator Secret files (`identity.hex` + `state.json`),
/// falling back to sealed `load_agent` for local/dev.
fn load_identity(paths: &StatePaths) -> anyhow::Result<(AgentIdentity, PersistedState)> {
    let identity_path = paths.dir.join("identity.hex");
    let state_path = paths.dir.join("state.json");
    if identity_path.is_file() && state_path.is_file() {
        let hex = std::fs::read_to_string(&identity_path)
            .with_context(|| format!("read {}", identity_path.display()))?;
        let bytes = hex::decode(hex.trim()).context("decode identity.hex")?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("identity.hex must be 32 bytes"))?;
        let identity = AgentIdentity::from_bytes(seed);
        let state = PersistedState::load(paths)?;
        return Ok((identity, state));
    }

    let policy = SealPolicy::from_env_and_flag(false);
    let (identity, persisted, _) = load_agent(paths, policy)?;
    Ok((identity, persisted))
}

fn resolve_kind(override_kind: Option<&str>, mode: &Mode) -> anyhow::Result<&'static str> {
    if let Some(k) = override_kind {
        return parse_kind(k);
    }
    Ok(match mode {
        Mode::Connector(_) => "k8s-connector",
        Mode::IngressProxy(_) => "k8s-ingress",
        Mode::TunnelProxy(_) => "k8s-tunnel",
        Mode::EgressProxy(_) => "k8s-egress",
        Mode::Sidecar => "k8s-sidecar",
    })
}

fn parse_kind(s: &str) -> anyhow::Result<&'static str> {
    Ok(match s {
        "sdk" => "sdk",
        "agent" => "agent",
        "k8s-connector" => "k8s-connector",
        "k8s-ingress" => "k8s-ingress",
        "k8s-tunnel" => "k8s-tunnel",
        "k8s-egress" => "k8s-egress",
        "k8s-sidecar" => "k8s-sidecar",
        other => bail!("unsupported --kind {other:?}"),
    })
}

fn spawn_health_server(bind: String, health: HealthState) {
    tokio::spawn(async move {
        let app = Router::new()
            .route("/healthz", get(healthz))
            .route("/readyz", get(readyz))
            .route("/metrics", get(metrics_endpoint))
            .with_state(health);
        let listener = match tokio::net::TcpListener::bind(&bind).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(%bind, ?e, "failed to bind health server");
                return;
            }
        };
        tracing::info!(%bind, "health server listening");
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!(?e, "health server exited");
        }
    });
}

async fn healthz() -> &'static str {
    "ok"
}

async fn readyz(State(health): State<HealthState>) -> impl IntoResponse {
    if health.ready.load(Ordering::Relaxed) {
        (StatusCode::OK, "ok")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready")
    }
}

async fn metrics_endpoint(State(health): State<HealthState>) -> impl IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        health.metrics.render(),
    )
}

fn noop_stream_handler() -> StreamHandler {
    Arc::new(|accepted| {
        Box::pin(async move {
            tracing::debug!(
                peer = %accepted.peer_hex,
                host = %accepted.header.host,
                port = accepted.header.dst_port,
                "inbound stream (no handler)"
            );
            drop(accepted);
        })
    })
}

fn spawn_unified_acceptor(node: Arc<CoreNode>, handler: StreamHandler) -> iroh::protocol::Router {
    use iroh::protocol::{AcceptError, ProtocolHandler, Router};
    use tunnet_core::StreamProtocolHandler;

    #[derive(Clone)]
    struct SendOfferHandler {
        send: tunnet_core::SendManager,
    }
    impl std::fmt::Debug for SendOfferHandler {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SendOfferHandler").finish_non_exhaustive()
        }
    }
    impl ProtocolHandler for SendOfferHandler {
        async fn accept(&self, conn: iroh::endpoint::Connection) -> Result<(), AcceptError> {
            self.send.handle_offer_connection(conn).await;
            Ok(())
        }
    }

    let stream = StreamProtocolHandler::new(handler);
    let send = SendOfferHandler {
        send: node.send.clone(),
    };
    tracing::info!("unified ALPN acceptor started");
    Router::builder(node.endpoint.clone())
        .accept(tunnet_core::TUNNEL_STREAM_ALPN, stream)
        .accept(tunnet_common::SEND_ALPN, send)
        .spawn()
}

async fn setup_connector(node: &CoreNode, args: &ConnectorArgs) -> anyhow::Result<()> {
    if args.routes.is_empty() {
        bail!("connector mode requires at least one route (TUNNET_ADVERTISED_ROUTES / --routes)");
    }
    let signed = signed_client(node)?;
    for cidr in &args.routes {
        let advertised = signed
            .create_subnet_route(cidr, Some("k8s connector"))
            .await
            .with_context(|| format!("advertise subnet route {cidr}"))?;
        tracing::info!(%advertised, "subnet route advertised");
    }
    Ok(())
}

async fn setup_ingress(node: &CoreNode, args: &IngressArgs) -> anyhow::Result<()> {
    let target = SocketAddr::from_str(&args.target_addr)
        .with_context(|| format!("invalid target_addr {}", args.target_addr))?;
    let id = format!("k8s-ingress-{}", args.serve_port);
    let info = node
        .serves
        .start(
            id,
            args.serve_port,
            &args.protocol,
            &args.internal_hostname,
            None,
            None,
            tunnet_core::ServeAcl::default(),
            Some(target),
        )
        .await
        .context("start ingress serve")?;
    tracing::info!(url = %info.url, %target, "ingress proxy listening on mesh");
    Ok(())
}

async fn setup_tunnel(node: &CoreNode, args: &TunnelArgs) -> anyhow::Result<()> {
    let redirect_rules: Vec<RedirectRule> = match &args.redirect_rules {
        Some(json) => serde_json::from_str(json).context("parse redirect_rules JSON")?,
        None => Vec::new(),
    };
    let target_addr = match &args.target_addr {
        Some(s) => {
            Some(SocketAddr::from_str(s).with_context(|| format!("invalid target_addr {s}"))?)
        }
        None => None,
    };
    let info = node
        .tunnels
        .start(
            args.tunnel_id.clone(),
            &args.relay_endpoint,
            &args.subdomain,
            &args.public_hostname,
            args.local_port,
            &args.protocol,
            &args.auth_token,
            redirect_rules,
            target_addr,
        )
        .await
        .context("start tunnel")?;
    tracing::info!(url = %info.public_url, "tunnel proxy active");
    Ok(())
}

async fn spawn_egress_proxy(node: Arc<CoreNode>, args: &EgressArgs) -> anyhow::Result<()> {
    let listen = SocketAddr::from_str(&args.listen).context("parse egress listen as host:port")?;
    let mesh_host = args.mesh_host.clone();
    let mesh_port = args.mesh_port;

    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("bind egress listener {listen}"))?;
    tracing::info!(%listen, %mesh_host, mesh_port, "egress proxy listening");

    tokio::spawn(async move {
        loop {
            let Ok((tcp, peer_addr)) = listener.accept().await else {
                continue;
            };
            let node = node.clone();
            let mesh_host = mesh_host.clone();
            tokio::spawn(async move {
                metrics::counter!("tunnet_kube_egress_connections_total").increment(1);
                if let Err(e) = proxy_egress_connection(node, tcp, &mesh_host, mesh_port).await {
                    tracing::debug!(%peer_addr, ?e, "egress connection closed");
                }
            });
        }
    });
    Ok(())
}

async fn proxy_egress_connection(
    node: Arc<CoreNode>,
    tcp: tokio::net::TcpStream,
    mesh_host: &str,
    mesh_port: u16,
) -> anyhow::Result<()> {
    let peer = resolve_peer(&node, mesh_host)
        .with_context(|| format!("no mesh peer matches {mesh_host}"))?;
    let (send, recv) = dial_stream(&node.pool, peer.endpoint, mesh_port, mesh_host.to_string())
        .await
        .context("dial mesh stream")?;
    let (tcp_read, tcp_write) = tcp.into_split();
    tunnet_core::stream::splice_bidirectional(recv, send, tcp_read, tcp_write).await?;
    Ok(())
}

fn signed_client(node: &CoreNode) -> anyhow::Result<SignedClient> {
    let managed = node.persisted.require_managed()?;
    SignedClient::new(
        managed.control_url.clone(),
        node.endpoint_id_hex(),
        node.identity.signing_key.clone(),
    )
}

fn resolve_peer(node: &CoreNode, host: &str) -> Option<Arc<PeerInfo>> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return node.routes.lookup_ip(&ip);
    }
    node.routes
        .lookup_hostname(host)
        .or_else(|| node.routes.lookup_endpoint(host))
}

#[allow(dead_code)]
fn _touch_path(_: &Path) {}
