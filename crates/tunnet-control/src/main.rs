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
use clap::Parser;
use secrecy::ExposeSecret;

use crate::admin::AdminState;
use crate::config::Args;
use crate::service_auth::ServiceAuth;
use crate::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();

    let args = Args::parse();
    observability::init(&args)?;

    tracing::info!(?args.bind, "starting tunnet control plane");

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

    let state = Arc::new(AppState::new(args.clone(), pool, policy_key, service_auth));

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
            if let Err(e) =
                device_expiry::run_cleanup(&expiry_state.pool, &expiry_state.ws_hub).await
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
