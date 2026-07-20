mod admin;
mod audit;
mod auth;
mod ca_crypto;
mod config;
mod db;
mod device_expiry;
mod device_expiry_sql;
mod device_handlers;
mod device_labels;
mod device_metadata;
mod entity_notify;
mod ha;
mod http;
mod ip_alloc;
mod metrics;
mod observability;
mod org_agent_policy;
mod pg_inet;
mod pg_notify;
mod policy_store;
mod posture;
mod presence;
mod reconnect;
mod register;
mod service_auth;
mod signing_key;
mod snapshot;
mod ssh;
mod ssh_auth;
mod state;
mod token_hash;
mod tunnels;
mod ws;
mod ws_hub;

use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};
use secrecy::ExposeSecret;
use tunnet_audit::{
    AuditConfig, AuditSink, AuditStream, PostgresPgSink, WebhookStream, start_worker,
};
use tunnet_common::license::resolve_entitlements_from_env;

use crate::admin::AdminState;
use crate::config::Args;
use crate::service_auth::ServiceAuth;
use crate::state::AppState;

#[derive(Parser, Debug)]
#[command(name = "tunnet-control", about = "Tunnet control plane")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[command(flatten)]
    serve: Args,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Audit log utilities
    Audit(AuditCli),
}

#[derive(Parser, Debug)]
struct AuditCli {
    #[command(subcommand)]
    command: AuditCommand,
}

#[derive(Subcommand, Debug)]
enum AuditCommand {
    /// Verify the HMAC hash chain for an organization
    Verify {
        #[arg(long)]
        org: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Audit(audit_cli)) => run_audit_cli(audit_cli).await,
        None => run_serve(cli.serve).await,
    }
}

async fn run_audit_cli(cli: AuditCli) -> anyhow::Result<()> {
    match cli.command {
        AuditCommand::Verify { org } => {
            let database_url = std::env::var("DATABASE_URL")
                .context("DATABASE_URL is required for audit verify")?;
            let hmac_key = std::env::var("TUNNET_AUDIT_HMAC_KEY")
                .context("TUNNET_AUDIT_HMAC_KEY is required for audit verify")?;
            if hmac_key.len() < 32 {
                anyhow::bail!("TUNNET_AUDIT_HMAC_KEY must be at least 32 characters");
            }

            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(2)
                .connect(&database_url)
                .await
                .context("connect to database")?;

            let report = tunnet_audit::verify_org_chain(&pool, hmac_key.as_bytes(), &org).await?;

            if let Some(err) = report.error {
                eprintln!(
                    "✗ Organization {org}: chain BROKEN at sequence {:?}",
                    report.broken_at
                );
                eprintln!("  {err}");
                eprintln!("  Verified before break: {} events", report.events_verified);
                std::process::exit(1);
            }

            println!(
                "✓ Organization {org}: {} events verified",
                report.events_verified
            );
            if let (Some(first), Some(last)) = (report.first_sequence, report.last_sequence) {
                println!("  Chain intact: sequence {first} → {last}");
            }
            if let (Some(ft), Some(lt)) = (report.first_time, report.last_time) {
                println!("  First event: {ft}");
                println!("  Last event:  {lt}");
            }
            println!("  HMAC schema versions: v1");
            Ok(())
        }
    }
}

async fn run_serve(args: Args) -> anyhow::Result<()> {
    observability::init(&args)?;

    tracing::info!(?args.bind, "starting tunnet control plane");

    let entitlements = resolve_entitlements_from_env().await;
    tracing::info!(
        tier = ?entitlements.tier,
        clickhouse_audit = entitlements.clickhouse_audit,
        "license entitlements loaded"
    );

    let pool = db::connect(&args).await.context("connect to database")?;

    let policy_key = signing_key::load(args.policy_key_env.as_deref(), &args.policy_key_path)?;
    tracing::info!(
        pubkey = %hex::encode(policy_key.verifying_key().to_bytes()),
        "policy signing key loaded"
    );

    let service_secret = args
        .service_secret
        .as_ref()
        .context("TUNNET_SERVICE_SECRET is required")?;
    let service_auth = ServiceAuth::new(service_secret.expose_secret())?;

    let audit_config = AuditConfig::from_env().context("audit config")?;
    let hmac_key = audit_config.hmac_key.clone();

    let mut sinks: Vec<Box<dyn AuditSink>> =
        vec![Box::new(PostgresPgSink::new(pool.clone(), hmac_key))];

    // Phase 2: ClickHouse — refuse without entitlement.
    if std::env::var("TUNNET_AUDIT_CLICKHOUSE_URL").is_ok() {
        if entitlements.clickhouse_audit {
            tracing::warn!(
                "TUNNET_AUDIT_CLICKHOUSE_URL set but ClickHouse sink not yet implemented; ignoring"
            );
        } else {
            tracing::warn!(
                "TUNNET_AUDIT_CLICKHOUSE_URL set but license lacks clickhouseAudit; ignoring"
            );
        }
        let _ = &mut sinks;
    }

    let mut streams: Vec<Box<dyn AuditStream>> = Vec::new();
    if let Some(url) = audit_config.webhook_url.clone() {
        streams.push(Box::new(WebhookStream::new(
            url,
            audit_config.webhook_headers.clone(),
        )));
    }

    let audit = start_worker(audit_config, sinks, streams);

    let state = Arc::new(AppState::new(
        args.clone(),
        pool,
        policy_key,
        service_auth,
        audit,
        entitlements,
    ));

    let database_url = args.database_url.expose_secret().to_string();
    let listener_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = pg_notify::run_listener(
            &database_url,
            listener_state.pool.clone(),
            listener_state.policy_key.clone(),
            listener_state.ws_hub.clone(),
            listener_state.listen_connected.clone(),
        )
        .await
        {
            tracing::error!(?e, "postgres listener terminated");
        }
    });

    let evictor_state = state.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            ticker.tick().await;
            if let Err(e) = evictor_state.evict_stale_devices().await {
                tracing::warn!(?e, "evict_stale_devices failed");
            }
            if let Err(e) = evictor_state.purge_expired_ephemera().await {
                tracing::warn!(?e, "purge_expired_ephemera failed");
            }
        }
    });

    let presence_state = state.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            ticker.tick().await;
            if let Err(e) = presence::sweep_stale_connections(&presence_state.pool).await {
                tracing::warn!(?e, "sweep_stale_connections failed");
            }
        }
    });

    let ttl_state = state.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            ticker.tick().await;
            if let Err(e) = tunnels::expire_tunnels(&ttl_state).await {
                tracing::warn!(?e, "expire_tunnels failed");
            }
        }
    });

    let expiry_state = state.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            ticker.tick().await;
            if let Err(e) = device_expiry::run_cleanup(
                &expiry_state.pool,
                &expiry_state.ws_hub,
                &expiry_state.audit,
            )
            .await
            {
                tracing::warn!(?e, "device auto-cleanup failed");
            }
        }
    });

    let admin_state = AdminState::new(state.clone(), env!("CARGO_PKG_VERSION"));
    let admin_bind = args.admin_bind.clone();
    tokio::spawn(async move {
        if let Err(e) = admin::serve(&admin_bind, admin_state).await {
            tracing::error!(?e, "admin API server failed");
        }
    });

    http::serve(state).await
}
