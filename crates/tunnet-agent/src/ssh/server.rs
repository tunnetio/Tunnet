//! russh Handler: mesh-identity auth, policy, PTY, recording.

use std::borrow::Cow;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;

use parking_lot::Mutex;
use russh::server::{Auth, Handler, Msg, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet, Pty};
use tunnet_common::policy::{SshAction, SshEvalCtx, SshPolicyRule, evaluate_ssh};
use tunnet_common::ws::ClientMsg;
use tunnet_core::{AclEngine, ConnPool, RoutingTable, SignedClient};
use uuid::Uuid;

use super::SshSessionRegistry;
use super::pty::{PtyRequest, PtySession, spawn_pty};
use super::sftp::SftpSession;
use super::tee::{
    RecorderTarget, RecordingTee, make_meta, recorder_unavailable, resolve_recorder_target,
};
use crate::recorder::RecordingStore;

type PtyInTx = std::sync::mpsc::Sender<Vec<u8>>;
type PtyResizeTx = std::sync::mpsc::Sender<(u16, u16)>;
type PtyInMap = HashMap<ChannelId, PtyInTx>;
type PtyResizeMap = HashMap<ChannelId, PtyResizeTx>;

#[derive(Clone)]
pub struct SshServeDeps {
    pub routes: RoutingTable,
    pub acl: AclEngine,
    pub sessions: SshSessionRegistry,
    pub cp_tx: Option<tokio::sync::mpsc::Sender<ClientMsg>>,
    pub pool: ConnPool,
    pub store: Option<Arc<RecordingStore>>,
    pub signed: Option<SignedClient>,
    pub hostname: String,
    pub network_name: String,
    #[allow(dead_code)]
    pub self_endpoint_id: String,
}

pub struct SshHandler {
    deps: SshServeDeps,
    peer_addr: SocketAddr,
    peer_hex: String,
    peer_hostname: Option<String>,
    username: String,
    auth_ok: bool,
    pending_reauth_url: Option<String>,
    check_period_secs: u64,
    decision: Option<SshPolicyRule>,
    channels: HashMap<ChannelId, Channel<Msg>>,
    pty_in: Arc<Mutex<PtyInMap>>,
    pty_resize: Arc<Mutex<PtyResizeMap>>,
    term: String,
    width: u16,
    height: u16,
    env_vars: Vec<(String, String)>,
}

impl SshHandler {
    pub fn new(deps: SshServeDeps, peer_addr: SocketAddr) -> Self {
        let ip = match peer_addr.ip() {
            std::net::IpAddr::V4(ip) => ip,
            std::net::IpAddr::V6(_) => std::net::Ipv4Addr::UNSPECIFIED,
        };
        let (peer_hex, peer_hostname) = match deps.routes.lookup_ip(&ip) {
            Some(peer) => {
                let hostname = if peer.hostname.is_empty() {
                    None
                } else {
                    Some(peer.hostname.clone())
                };
                (peer.endpoint_hex.clone(), hostname)
            }
            None => (String::new(), None),
        };
        Self {
            deps,
            peer_addr,
            peer_hex,
            peer_hostname,
            username: String::new(),
            auth_ok: false,
            pending_reauth_url: None,
            check_period_secs: 3600,
            decision: None,
            channels: HashMap::new(),
            pty_in: Arc::new(Mutex::new(HashMap::new())),
            pty_resize: Arc::new(Mutex::new(HashMap::new())),
            term: "xterm-256color".into(),
            width: 80,
            height: 24,
            env_vars: Vec::new(),
        }
    }

    fn emit_cp(&self, msg: ClientMsg) {
        let Some(tx) = &self.deps.cp_tx else {
            tracing::debug!(
                peer = %self.peer_hex,
                "ssh session event dropped (no control-plane channel)"
            );
            return;
        };
        if let Err(e) = tx.try_send(msg) {
            tracing::warn!(
                peer = %self.peer_hex,
                ?e,
                "ssh session event dropped (control-plane channel full or closed)"
            );
        }
    }

    fn evaluate_policy(&mut self, user: &str) -> Option<SshPolicyRule> {
        let empty: Vec<String> = Vec::new();
        let self_id = self.deps.acl.self_id.load();
        let peer_info = self.deps.routes.lookup_endpoint(&self.peer_hex);
        let ctx = SshEvalCtx {
            src_endpoint_hex: &self.peer_hex,
            src_tags: peer_info
                .as_ref()
                .map(|p| p.tags.as_slice())
                .unwrap_or(&empty),
            src_network: &self_id.network,
            dst_endpoint_hex: &self_id.endpoint_hex,
            dst_tags: &self_id.tags,
            dst_network: &self_id.network,
            requested_user: user,
            local_user: "",
        };
        let bundle = self.deps.acl.bundle.load();
        evaluate_ssh(&bundle.ssh_rules, &ctx).cloned()
    }

    async fn verify_check(&self, period: u64) -> bool {
        let Some(client) = self.deps.signed.as_ref() else {
            return false;
        };
        match client.verify_ssh_auth(&self.peer_hex, period, None).await {
            Ok(v) => v.get("status").and_then(|s| s.as_str()) == Some("ok"),
            Err(_) => false,
        }
    }

    async fn mint_reauth_url(&self, period: u64) -> Option<String> {
        let client = self.deps.signed.as_ref()?;
        let eval = client
            .evaluate_ssh_auth(&self.peer_hex, period)
            .await
            .ok()?;
        if eval.get("status").and_then(|s| s.as_str()) == Some("ok") {
            return None;
        }
        eval.get("reauthUrl")
            .and_then(|u| u.as_str())
            .map(|s| s.to_string())
    }

    async fn start_shell(
        &mut self,
        channel: ChannelId,
        command: Option<String>,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        if !self.auth_ok {
            let _ = session.channel_failure(channel);
            return Ok(());
        }

        let recorded = self.decision.as_ref().is_some_and(|r| r.record);
        let enforce_recorder = self.decision.as_ref().is_some_and(|r| r.enforce_recorder);
        let recorder_selector = self.decision.as_ref().and_then(|r| r.recorder.clone());

        let session_id = Uuid::new_v4();
        let mut tee: Option<RecordingTee> = None;
        if recorded {
            let target = resolve_recorder_target(
                &self.deps.routes,
                &self.deps.acl,
                recorder_selector.as_ref(),
            );
            match target {
                None => {
                    if recorder_unavailable(enforce_recorder) {
                        let _ = session.channel_failure(channel);
                        return Ok(());
                    }
                }
                Some(RecorderTarget::Local) => {
                    if let Some(store) = self.deps.store.as_ref() {
                        let meta = make_meta(
                            &session_id.to_string(),
                            &self.peer_hex,
                            self.peer_hostname.clone(),
                            &self.username,
                            &self.deps.hostname,
                            &self.deps.network_name,
                            self.width,
                            self.height,
                            &self.term,
                        );
                        match RecordingTee::local(store, &meta) {
                            Ok(t) => tee = Some(t),
                            Err(e) => {
                                tracing::warn!(?e, "failed to open local recording");
                                if recorder_unavailable(enforce_recorder) {
                                    let _ = session.channel_failure(channel);
                                    return Ok(());
                                }
                            }
                        }
                    } else if recorder_unavailable(enforce_recorder) {
                        let _ = session.channel_failure(channel);
                        return Ok(());
                    }
                }
                Some(RecorderTarget::Remote(peer)) => {
                    let meta = make_meta(
                        &session_id.to_string(),
                        &self.peer_hex,
                        self.peer_hostname.clone(),
                        &self.username,
                        &self.deps.hostname,
                        &self.deps.network_name,
                        self.width,
                        self.height,
                        &self.term,
                    );
                    match RecordingTee::remote(&self.deps.pool, peer, meta).await {
                        Ok(t) => tee = Some(t),
                        Err(e) => {
                            tracing::warn!(?e, "failed to dial recorder");
                            if recorder_unavailable(enforce_recorder) {
                                let _ = session.channel_failure(channel);
                                return Ok(());
                            }
                        }
                    }
                }
            }
        }

        let req = PtyRequest {
            target_user: self.username.clone(),
            term_type: self.term.clone(),
            width: self.width,
            height: self.height,
            env_vars: self.env_vars.clone(),
            command,
        };
        let pty = match spawn_pty(&req) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(peer = %self.peer_hex, ?e, "pty spawn failed");
                let _ = session.channel_failure(channel);
                return Ok(());
            }
        };

        let _ = session.channel_success(channel);
        let actually_recorded = tee.is_some();
        self.emit_cp(ClientMsg::SshSessionStarted {
            session_id: session_id.to_string(),
            src_endpoint_id: self.peer_hex.clone(),
            target_user: self.username.clone(),
            src_hostname: self.peer_hostname.clone(),
            recorded: actually_recorded,
        });

        let PtySession {
            mut reader,
            mut writer,
            mut child_killer,
            master,
        } = pty;

        self.deps.sessions.insert(
            session_id,
            self.peer_hex.clone(),
            self.username.clone(),
            child_killer.clone_killer(),
        );

        let (pty_out_tx, mut pty_out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
        let (pty_in_tx, pty_in_rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let (resize_tx, resize_rx) = std::sync::mpsc::channel::<(u16, u16)>();

        self.pty_in.lock().insert(channel, pty_in_tx);
        self.pty_resize.lock().insert(channel, resize_tx);

        std::thread::spawn(move || {
            let mut buf = [0u8; 16 * 1024];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if pty_out_tx.blocking_send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        std::thread::spawn(move || {
            while let Ok(chunk) = pty_in_rx.recv() {
                if writer.write_all(&chunk).is_err() {
                    break;
                }
                let _ = writer.flush();
            }
        });

        let master_for_resize = master;
        std::thread::spawn(move || {
            while let Ok((cols, rows)) = resize_rx.recv() {
                let _ = master_for_resize.resize(portable_pty::PtySize {
                    rows,
                    cols,
                    pixel_width: 0,
                    pixel_height: 0,
                });
            }
        });

        let handle = session.handle();
        let sessions = self.deps.sessions.clone();
        let cp_tx = self.deps.cp_tx.clone();
        let store = self.deps.store.clone();
        let signed = self.deps.signed.clone();
        let acl = self.deps.acl.clone();
        let peer_hex = self.peer_hex.clone();
        let pty_in = self.pty_in.clone();
        let pty_resize = self.pty_resize.clone();
        let started = std::time::Instant::now();

        tokio::spawn(async move {
            let mut tee = tee;
            while let Some(chunk) = pty_out_rx.recv().await {
                if let Some(t) = tee.as_mut()
                    && let Err(e) = t.write_output(&chunk)
                {
                    tracing::warn!(?e, "recording write failed");
                    if enforce_recorder {
                        break;
                    }
                    tee = None;
                }
                if handle
                    .data(channel, bytes::Bytes::from(chunk))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;

            pty_in.lock().remove(&channel);
            pty_resize.lock().remove(&channel);
            sessions.remove(&session_id);
            let killed = sessions.take_killed(&session_id);
            let _ = child_killer.kill();
            let duration_ms = started.elapsed().as_millis() as u64;

            if let Some(t) = tee {
                match t.finish(store.as_deref(), duration_ms) {
                    Ok(Some((meta, finalized))) => {
                        if let Some(tx) = &cp_tx
                            && let Err(e) = tx.try_send(ClientMsg::SshRecordingSaved {
                                session_id: meta.session_id.clone(),
                                recorder_endpoint_id: acl.self_id.load().endpoint_hex.clone(),
                                duration_ms: Some(duration_ms),
                                byte_size: finalized.byte_size,
                                content_sha256: finalized.sha256_hex.clone(),
                            })
                        {
                            tracing::warn!(?e, "SshRecordingSaved event dropped");
                        }
                        if let Some(client) = &signed {
                            match std::fs::read_to_string(&finalized.path) {
                                Ok(cast_text) => {
                                    if let Err(e) = client
                                        .upload_ssh_recording(
                                            &meta.session_id,
                                            &cast_text,
                                            &finalized.sha256_hex,
                                        )
                                        .await
                                    {
                                        tracing::warn!(?e, "failed to upload local recording");
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(?e, "failed to read local cast for upload")
                                }
                            }
                        }
                    }
                    Ok(None) => {}
                    Err(e) => tracing::warn!(?e, "failed to finalize recording"),
                }
            }

            if let Some(tx) = &cp_tx
                && let Err(e) = tx.try_send(ClientMsg::SshSessionEnded {
                    session_id: session_id.to_string(),
                    status: if killed {
                        "killed".into()
                    } else {
                        "ended".into()
                    },
                    duration_ms: Some(duration_ms),
                })
            {
                tracing::warn!(?e, %session_id, "SshSessionEnded event dropped");
            }
            tracing::debug!(%peer_hex, %session_id, "ssh session finished");
        });

        Ok(())
    }
}

impl Handler for SshHandler {
    type Error = russh::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        self.username = user.to_string();
        if self.peer_hex.is_empty() {
            tracing::warn!(addr = %self.peer_addr, "ssh from unknown mesh IP");
            return Ok(Auth::reject());
        }

        let decision = self.evaluate_policy(user);
        self.decision = decision.clone();
        match decision {
            None => {
                tracing::info!(peer = %self.peer_hex, %user, "ssh denied (no matching rule)");
                Ok(Auth::reject())
            }
            Some(rule) if rule.action == SshAction::Deny => {
                tracing::info!(peer = %self.peer_hex, %user, "ssh denied by policy");
                Ok(Auth::reject())
            }
            Some(rule) if rule.action == SshAction::Check => {
                let period = rule.check_period_secs.unwrap_or(3600);
                self.check_period_secs = period;
                if self.verify_check(period).await {
                    self.auth_ok = true;
                    return Ok(Auth::Accept);
                }
                if let Some(url) = self.mint_reauth_url(period).await {
                    self.pending_reauth_url = Some(url);
                    let mut methods = MethodSet::empty();
                    methods.push(MethodKind::KeyboardInteractive);
                    Ok(Auth::Reject {
                        proceed_with_methods: Some(methods),
                        partial_success: false,
                    })
                } else if self.verify_check(period).await {
                    self.auth_ok = true;
                    Ok(Auth::Accept)
                } else {
                    Ok(Auth::reject())
                }
            }
            Some(_) => {
                self.auth_ok = true;
                Ok(Auth::Accept)
            }
        }
    }

    async fn auth_keyboard_interactive(
        &mut self,
        user: &str,
        _submethods: &str,
        response: Option<russh::server::Response<'_>>,
    ) -> Result<Auth, Self::Error> {
        self.username = user.to_string();
        let Some(url) = self.pending_reauth_url.clone() else {
            return Ok(Auth::reject());
        };
        if response.is_none() {
            return Ok(Auth::Partial {
                name: Cow::Borrowed("Tunnet"),
                instructions: Cow::Owned(format!(
                    "Re-authentication required.\nOpen: {url}\nThen press Enter."
                )),
                prompts: Cow::Borrowed(&[(Cow::Borrowed("Press Enter when done: "), true)]),
            });
        }
        if self.verify_check(self.check_period_secs).await {
            self.auth_ok = true;
            self.pending_reauth_url = None;
            Ok(Auth::Accept)
        } else {
            Ok(Auth::Partial {
                name: Cow::Borrowed("Tunnet"),
                instructions: Cow::Owned(format!(
                    "Still waiting for authentication.\nOpen: {url}\nThen press Enter."
                )),
                prompts: Cow::Borrowed(&[(Cow::Borrowed("Press Enter when done: "), true)]),
            })
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        self.channels.insert(channel.id(), channel);
        Ok(true)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.term = term.to_string();
        self.width = col_width.max(1) as u16;
        self.height = row_height.max(1) as u16;
        session.channel_success(channel)?;
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if matches!(
            variable_name,
            "LANG"
                | "LC_ALL"
                | "LC_CTYPE"
                | "LC_MESSAGES"
                | "COLORTERM"
                | "TERM_PROGRAM"
                | "TERM_PROGRAM_VERSION"
        ) {
            self.env_vars
                .push((variable_name.to_string(), variable_value.to_string()));
        }
        session.channel_success(channel)?;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.auth_ok || name != "sftp" {
            let _ = session.channel_failure(channel);
            return Ok(());
        }

        let Some(ch) = self.channels.remove(&channel) else {
            let _ = session.channel_failure(channel);
            return Ok(());
        };

        let sftp = match SftpSession::new(&self.username) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(peer = %self.peer_hex, user = %self.username, ?e, "sftp start failed");
                let _ = session.channel_failure(channel);
                return Ok(());
            }
        };

        let _ = session.channel_success(channel);
        russh_sftp::server::run(ch.into_stream(), sftp).await;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.start_shell(channel, None, session).await
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).into_owned();
        self.start_shell(channel, Some(command), session).await
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.width = col_width.max(1) as u16;
        self.height = row_height.max(1) as u16;
        if let Some(tx) = self.pty_resize.lock().get(&channel) {
            let _ = tx.send((self.width, self.height));
        }
        session.channel_success(channel)?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(tx) = self.pty_in.lock().get(&channel) {
            let _ = tx.send(data.to_vec());
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.pty_in.lock().remove(&channel);
        self.pty_resize.lock().remove(&channel);
        session.close(channel)?;
        Ok(())
    }
}
