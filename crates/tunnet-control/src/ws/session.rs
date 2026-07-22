//! Agent WebSocket session loop.

use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use tunnet_common::ws::{ClientMsg, ServerMsg};

use crate::presence::HEARTBEAT_STALE_SECS;
use crate::state::SharedState;

pub async fn run_ws(
    state: SharedState,
    socket: WebSocket,
    endpoint_id: String,
    organization_id: String,
    network_ids: Vec<uuid::Uuid>,
    public_ip: Option<std::net::IpAddr>,
) {
    tracing::info!(%endpoint_id, %organization_id, ?public_ip, "ws connected");

    if let Err(e) = crate::presence::mark_agent_connected(
        &state.pool,
        &endpoint_id,
        public_ip,
        Some(&state.ws_hub),
    )
    .await
    {
        tracing::warn!(?e, %endpoint_id, "failed to mark agent connected");
    }

    // Stamp this session so cleanup does not clear a newer reconnect.
    let session_connected_at: Option<chrono::DateTime<chrono::Utc>> =
        match sqlx::query_scalar("SELECT connected_at FROM devices WHERE endpoint_id = $1")
            .bind(&endpoint_id)
            .fetch_optional(&state.pool)
            .await
        {
            Ok(at) => at,
            Err(e) => {
                tracing::warn!(?e, %endpoint_id, "failed to read session connected_at");
                None
            }
        };

    let (mut ws_tx, mut ws_rx) = socket.split();
    let mut rx = state.ws_hub.register(
        endpoint_id.clone(),
        organization_id.clone(),
        network_ids.clone(),
    );

    if let Ok(snap) =
        crate::snapshot::build_endpoint_snapshot(&state.pool, &state.policy_key, &endpoint_id).await
    {
        let msg = ServerMsg::Snapshot(Box::new(snap));
        if let Ok(txt) = serde_json::to_string(&msg) {
            let _ = ws_tx.send(Message::text(txt)).await;
        }
    }

    // Snapshot omits relay_auth_token; re-push OpenTunnel / StartServe so the
    // agent TunnelManager / ServeManager actually (re)start workloads.
    crate::reconnect::replay_endpoint_workloads(&state, &endpoint_id).await;

    let hub = state.ws_hub.clone();
    let ep_for_cleanup = endpoint_id.clone();

    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let Ok(txt) = serde_json::to_string(&msg) else {
                continue;
            };
            if ws_tx.send(Message::text(txt)).await.is_err() {
                break;
            }
        }
    });

    // Inbound reader with idle timeout (half-open TCP otherwise keeps presence "Online").
    let pool = state.pool.clone();
    let ep = endpoint_id.clone();
    let posture_state = state.clone();
    let recv_task = tokio::spawn(async move {
        let mut last_heartbeat = Instant::now();
        let mut idle_tick = tokio::time::interval(Duration::from_secs(15));
        idle_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let idle_limit = Duration::from_secs(HEARTBEAT_STALE_SECS as u64);

        loop {
            tokio::select! {
                msg = ws_rx.next() => {
                    let Some(Ok(msg)) = msg else {
                        break;
                    };
                    match msg {
                Message::Text(txt) => {
                    match serde_json::from_str::<ClientMsg>(txt.as_str()) {
                        Ok(cm) => {
                        match cm {
                            ClientMsg::Heartbeat { .. } => {
                                last_heartbeat = Instant::now();
                                if let Err(e) = crate::presence::record_heartbeat(&pool, &ep).await
                                {
                                    tracing::warn!(?e, %ep, "heartbeat update failed");
                                }
                            }
                            ClientMsg::ServeReady { serve_id } => {
                                if let Err(e) = sqlx::query(
                                    "UPDATE serves SET status = 'active', updated_at = now() \
                                     WHERE id = $1::uuid AND endpoint_id = $2",
                                )
                                .bind(&serve_id)
                                .bind(&ep)
                                .execute(&pool)
                                .await
                                {
                                    tracing::warn!(?e, %serve_id, "ServeReady update failed");
                                } else {
                                    // Bump so mesh DNS includes the new active serve hostname.
                                    if let Ok(Some(network_id)) = sqlx::query_scalar::<_, uuid::Uuid>(
                                        "SELECT network_id FROM serves WHERE id = $1::uuid",
                                    )
                                    .bind(&serve_id)
                                    .fetch_optional(&pool)
                                    .await
                                    {
                                        let _ = sqlx::query(
                                            "UPDATE networks SET version = version + 1 WHERE id = $1",
                                        )
                                        .bind(network_id)
                                        .execute(&pool)
                                        .await;
                                        let _ = crate::pg_notify::emit_network_changed(
                                            &pool, network_id,
                                        )
                                        .await;
                                    }
                                    if let Err(e) =
                                        crate::entity_notify::notify_serve_status(&pool, &serve_id)
                                            .await
                                    {
                                        tracing::warn!(?e, %serve_id, "serve entity notify failed");
                                    }
                                }
                            }
                            ClientMsg::ServeStopped { serve_id } => {
                                let meta: Option<(String, uuid::Uuid)> = match sqlx::query_as(
                                    "SELECT d.organization_id, s.network_id \
                                     FROM serves s \
                                     JOIN devices d ON d.endpoint_id = s.endpoint_id \
                                     WHERE s.id = $1::uuid AND s.endpoint_id = $2",
                                )
                                .bind(&serve_id)
                                .bind(&ep)
                                .fetch_optional(&pool)
                                .await
                                {
                                    Ok(row) => row,
                                    Err(e) => {
                                        tracing::warn!(?e, %serve_id, "ServeStopped lookup failed");
                                        None
                                    }
                                };

                                if let Some((org_id, network_id)) = meta {
                                    if let Err(e) = sqlx::query(
                                        "DELETE FROM serves \
                                         WHERE id = $1::uuid AND endpoint_id = $2",
                                    )
                                    .bind(&serve_id)
                                    .bind(&ep)
                                    .execute(&pool)
                                    .await
                                    {
                                        tracing::warn!(?e, %serve_id, "ServeStopped delete failed");
                                    } else {
                                        let _ = sqlx::query(
                                            "UPDATE networks SET version = version + 1 WHERE id = $1",
                                        )
                                        .bind(network_id)
                                        .execute(&pool)
                                        .await;
                                        if let Err(e) =
                                            crate::pg_notify::emit_network_changed(&pool, network_id)
                                                .await
                                        {
                                            tracing::warn!(
                                                ?e,
                                                %network_id,
                                                "ServeStopped network notify failed"
                                            );
                                        }
                                        if let Err(e) = crate::entity_notify::emit_serve_changed(
                                            &pool,
                                            &org_id,
                                            &network_id.to_string(),
                                            &serve_id,
                                        )
                                        .await
                                        {
                                            tracing::warn!(
                                                ?e,
                                                %serve_id,
                                                "serve entity notify failed"
                                            );
                                        }
                                    }
                                }
                            }
                            ClientMsg::ServeFailed { serve_id, error } => {
                                if let Err(e) = sqlx::query(
                                    "UPDATE serves SET status = 'error', error_message = $3, \
                                     updated_at = now() \
                                     WHERE id = $1::uuid AND endpoint_id = $2",
                                )
                                .bind(&serve_id)
                                .bind(&ep)
                                .bind(&error)
                                .execute(&pool)
                                .await
                                {
                                    tracing::warn!(?e, %serve_id, "ServeFailed update failed");
                                } else if let Err(e) =
                                    crate::entity_notify::notify_serve_status(&pool, &serve_id)
                                        .await
                                {
                                    tracing::warn!(?e, %serve_id, "serve entity notify failed");
                                }
                            }
                            ClientMsg::ServePeerJoined {
                                serve_id,
                                peer_endpoint_id,
                                peer_hostname,
                            } => {
                                if let Err(e) = sqlx::query(
                                    "INSERT INTO serve_sessions \
                                       (id, serve_id, peer_endpoint_id, peer_hostname, \
                                        connected_at, bytes_in, bytes_out, last_seen_at) \
                                     SELECT gen_random_uuid(), s.id, $2, $3, now(), 0, 0, now() \
                                     FROM serves s \
                                     WHERE s.id = $1::uuid AND s.endpoint_id = $4 \
                                     ON CONFLICT (serve_id, peer_endpoint_id) DO UPDATE SET \
                                       peer_hostname = COALESCE(EXCLUDED.peer_hostname, serve_sessions.peer_hostname), \
                                       connected_at = now(), \
                                       bytes_in = 0, \
                                       bytes_out = 0, \
                                       last_seen_at = now()",
                                )
                                .bind(&serve_id)
                                .bind(&peer_endpoint_id)
                                .bind(&peer_hostname)
                                .bind(&ep)
                                .execute(&pool)
                                .await
                                {
                                    tracing::warn!(?e, %serve_id, "ServePeerJoined upsert failed");
                                } else if let Err(e) =
                                    crate::entity_notify::notify_serve_status(&pool, &serve_id)
                                        .await
                                {
                                    tracing::warn!(?e, %serve_id, "serve entity notify failed");
                                }
                            }
                            ClientMsg::ServePeerLeft {
                                serve_id,
                                peer_endpoint_id,
                                bytes_in,
                                bytes_out,
                            } => {
                                if let Err(e) = sqlx::query(
                                    "DELETE FROM serve_sessions ss \
                                     USING serves s \
                                     WHERE ss.serve_id = s.id \
                                       AND s.id = $1::uuid \
                                       AND s.endpoint_id = $2 \
                                       AND ss.peer_endpoint_id = $3",
                                )
                                .bind(&serve_id)
                                .bind(&ep)
                                .bind(&peer_endpoint_id)
                                .execute(&pool)
                                .await
                                {
                                    tracing::warn!(
                                        ?e,
                                        %serve_id,
                                        bytes_in,
                                        bytes_out,
                                        "ServePeerLeft delete failed"
                                    );
                                } else if let Err(e) =
                                    crate::entity_notify::notify_serve_status(&pool, &serve_id)
                                        .await
                                {
                                    tracing::warn!(?e, %serve_id, "serve entity notify failed");
                                }
                            }
                            ClientMsg::TunnelReady { tunnel_id } => {
                                if let Err(e) = sqlx::query(
                                    "UPDATE tunnels SET status = 'active', updated_at = now() \
                                     WHERE id = $1::uuid AND endpoint_id = $2",
                                )
                                .bind(&tunnel_id)
                                .bind(&ep)
                                .execute(&pool)
                                .await
                                {
                                    tracing::warn!(?e, %tunnel_id, "TunnelReady update failed");
                                } else if let Err(e) =
                                    crate::entity_notify::notify_tunnel_status(&pool, &tunnel_id)
                                        .await
                                {
                                    tracing::warn!(?e, %tunnel_id, "tunnel entity notify failed");
                                }
                            }
                            ClientMsg::TunnelStopped { tunnel_id } => {
                                if let Err(e) = sqlx::query(
                                    "UPDATE tunnels SET status = 'stopped', updated_at = now() \
                                     WHERE id = $1::uuid AND endpoint_id = $2",
                                )
                                .bind(&tunnel_id)
                                .bind(&ep)
                                .execute(&pool)
                                .await
                                {
                                    tracing::warn!(?e, %tunnel_id, "TunnelStopped update failed");
                                } else if let Err(e) =
                                    crate::entity_notify::notify_tunnel_status(&pool, &tunnel_id)
                                        .await
                                {
                                    tracing::warn!(?e, %tunnel_id, "tunnel entity notify failed");
                                }
                            }
                            ClientMsg::TunnelFailed { tunnel_id, error } => {
                                if let Err(e) = sqlx::query(
                                    "UPDATE tunnels SET status = 'error', error_message = $3, \
                                     updated_at = now() \
                                     WHERE id = $1::uuid AND endpoint_id = $2",
                                )
                                .bind(&tunnel_id)
                                .bind(&ep)
                                .bind(&error)
                                .execute(&pool)
                                .await
                                {
                                    tracing::warn!(?e, %tunnel_id, "TunnelFailed update failed");
                                } else if let Err(e) =
                                    crate::entity_notify::notify_tunnel_status(&pool, &tunnel_id)
                                        .await
                                {
                                    tracing::warn!(?e, %tunnel_id, "tunnel entity notify failed");
                                }
                            }
                            ClientMsg::SshSessionStarted {
                                session_id,
                                src_endpoint_id,
                                target_user,
                                src_hostname,
                                recorded,
                            } => {
                                match sqlx::query(
                                    "INSERT INTO ssh_sessions \
                                       (id, organization_id, network_id, src_endpoint_id, dst_endpoint_id, \
                                        src_hostname, dst_hostname, target_user, status, recorded, started_at) \
                                     SELECT $1::uuid, d.organization_id, nm.network_id, $2, $3, \
                                            $4, COALESCE(NULLIF(d.metadata->>'hostname', ''), left(d.endpoint_id, 8)), \
                                            $5, 'active', $6, now() \
                                     FROM devices d \
                                     JOIN network_memberships nm ON nm.endpoint_id = d.endpoint_id \
                                       AND nm.status = 'active' \
                                     WHERE lower(d.endpoint_id) = lower($3) \
                                     LIMIT 1 \
                                     ON CONFLICT (id) DO NOTHING",
                                )
                                .bind(&session_id)
                                .bind(&src_endpoint_id)
                                .bind(&ep)
                                .bind(&src_hostname)
                                .bind(&target_user)
                                .bind(recorded)
                                .execute(&pool)
                                .await
                                {
                                    Ok(res) if res.rows_affected() == 0 => {
                                        tracing::warn!(
                                            %session_id,
                                            dst = %ep,
                                            src = %src_endpoint_id,
                                            "SshSessionStarted insert matched no device/membership row"
                                        );
                                    }
                                    Ok(_) => {
                                        tracing::info!(
                                            %session_id,
                                            dst = %ep,
                                            src = %src_endpoint_id,
                                            %target_user,
                                            "ssh session recorded"
                                        );
                                    }
                                    Err(e) => {
                                        tracing::warn!(?e, %session_id, "SshSessionStarted insert failed");
                                    }
                                }
                            }
                            ClientMsg::SshSessionEnded {
                                session_id,
                                status,
                                duration_ms,
                            } => {
                                let status = if status.is_empty() {
                                    "ended".to_string()
                                } else {
                                    status
                                };
                                if let Err(e) = sqlx::query(
                                    "UPDATE ssh_sessions \
                                     SET status = $2, ended_at = now(), duration_ms = $3 \
                                     WHERE id = $1::uuid AND dst_endpoint_id = $4",
                                )
                                .bind(&session_id)
                                .bind(&status)
                                .bind(duration_ms.map(|v| v as i32))
                                .bind(&ep)
                                .execute(&pool)
                                .await
                                {
                                    tracing::warn!(?e, %session_id, "SshSessionEnded update failed");
                                }
                            }
                            ClientMsg::SshRecordingSaved {
                                session_id,
                                recorder_endpoint_id: _,
                                duration_ms,
                                byte_size: _,
                                content_sha256: _,
                            } => {
                                if let Err(e) = sqlx::query(
                                    "UPDATE ssh_sessions SET recorded = true, \
                                     duration_ms = COALESCE($2, duration_ms) \
                                     WHERE id = $1::uuid",
                                )
                                .bind(&session_id)
                                .bind(duration_ms.map(|v| v as i32))
                                .execute(&pool)
                                .await
                                {
                                    tracing::warn!(
                                        ?e,
                                        %session_id,
                                        "SshRecordingSaved update failed"
                                    );
                                }
                            }
                            ClientMsg::TransferOffer {
                                transfer_id,
                                sender_endpoint_id,
                                receiver_endpoint_id,
                                file_name,
                                size,
                                blake3_hash,
                                status,
                                message,
                            } => {
                                let status = if status.is_empty() {
                                    "offered".to_string()
                                } else {
                                    status
                                };
                                if let Err(e) = sqlx::query(
                                    "INSERT INTO file_transfers \
                                       (id, organization_id, network_id, sender_endpoint_id, \
                                        receiver_endpoint_id, file_name, size_bytes, blake3_hash, \
                                        status, progress_pct, bytes_transferred, message, created_at) \
                                     SELECT $1::uuid, d.organization_id, nm.network_id, $2, $3, \
                                            $4, $5, $6, $7, 0, 0, $8, now() \
                                     FROM devices d \
                                     JOIN network_memberships nm ON nm.endpoint_id = d.endpoint_id \
                                       AND nm.status = 'active' \
                                     WHERE d.endpoint_id = $2 \
                                     LIMIT 1 \
                                     ON CONFLICT (id) DO UPDATE SET \
                                       status = EXCLUDED.status, \
                                       receiver_endpoint_id = COALESCE(EXCLUDED.receiver_endpoint_id, file_transfers.receiver_endpoint_id), \
                                       message = COALESCE(EXCLUDED.message, file_transfers.message)",
                                )
                                .bind(&transfer_id)
                                .bind(&sender_endpoint_id)
                                .bind(&receiver_endpoint_id)
                                .bind(&file_name)
                                .bind(size as i64)
                                .bind(&blake3_hash)
                                .bind(&status)
                                .bind(&message)
                                .execute(&pool)
                                .await
                                {
                                    tracing::warn!(?e, %transfer_id, "TransferOffer upsert failed");
                                }
                            }
                            ClientMsg::TransferProgress {
                                transfer_id,
                                percent,
                                bytes_transferred,
                                bytes_total: _,
                            } => {
                                if let Err(e) = sqlx::query(
                                    "UPDATE file_transfers \
                                     SET status = 'transferring', \
                                         progress_pct = $2, \
                                         bytes_transferred = $3 \
                                     WHERE id = $1::uuid",
                                )
                                .bind(&transfer_id)
                                .bind(percent.round() as i32)
                                .bind(bytes_transferred as i64)
                                .execute(&pool)
                                .await
                                {
                                    tracing::warn!(?e, %transfer_id, "TransferProgress update failed");
                                }
                            }
                            ClientMsg::TransferComplete {
                                transfer_id,
                                inbox_path,
                                duration_ms: _,
                            } => {
                                if let Err(e) = sqlx::query(
                                    "UPDATE file_transfers \
                                     SET status = 'completed', progress_pct = 100, \
                                         inbox_path = $2, completed_at = now() \
                                     WHERE id = $1::uuid",
                                )
                                .bind(&transfer_id)
                                .bind(&inbox_path)
                                .execute(&pool)
                                .await
                                {
                                    tracing::warn!(?e, %transfer_id, "TransferComplete update failed");
                                }
                            }
                            ClientMsg::TransferFailed {
                                transfer_id,
                                error,
                                rejected,
                            } => {
                                let status = if rejected { "rejected" } else { "failed" };
                                if let Err(e) = sqlx::query(
                                    "UPDATE file_transfers \
                                     SET status = $2, error = $3, completed_at = now() \
                                     WHERE id = $1::uuid",
                                )
                                .bind(&transfer_id)
                                .bind(status)
                                .bind(&error)
                                .execute(&pool)
                                .await
                                {
                                    tracing::warn!(?e, %transfer_id, "TransferFailed update failed");
                                }
                            }
                            ClientMsg::PostureReport {
                                full,
                                attributes,
                                collected_at,
                            } => {
                                if let Err(e) = crate::posture::handle_posture_report(
                                    &posture_state,
                                    &ep,
                                    full,
                                    attributes,
                                    collected_at,
                                )
                                .await
                                {
                                    tracing::warn!(?e, %ep, "PostureReport failed");
                                }
                            }
                            ClientMsg::EffectiveConfigReport {
                                config,
                                reported_at,
                            } => {
                                if let Err(e) = crate::org_agent_policy::store_effective_config(
                                    &pool,
                                    &ep,
                                    &config,
                                    reported_at,
                                )
                                .await
                                {
                                    tracing::warn!(?e, %ep, "EffectiveConfigReport failed");
                                }
                            }
                            ClientMsg::Hello { .. } | ClientMsg::Pong { .. } => {}
                        }
                        }
                        Err(e) => {
                            tracing::warn!(
                                ?e,
                                %ep,
                                preview = %txt.chars().take(120).collect::<String>(),
                                "failed to parse client ws message"
                            );
                        }
                    }
                }
                Message::Close(_) => break,
                _ => {}
                    }
                }
                _ = idle_tick.tick() => {
                    if last_heartbeat.elapsed() > idle_limit {
                        tracing::warn!(%ep, "ws idle timeout (no heartbeat)");
                        break;
                    }
                }
            }
        }
    });

    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
    }

    hub.unregister(&ep_for_cleanup, &organization_id, &network_ids);
    if let Err(e) =
        crate::presence::mark_agent_disconnected(&state.pool, &ep_for_cleanup, session_connected_at)
            .await
    {
        tracing::warn!(?e, %ep_for_cleanup, "failed to mark agent disconnected");
    }
    tracing::info!(%ep_for_cleanup, "ws disconnected");
}
