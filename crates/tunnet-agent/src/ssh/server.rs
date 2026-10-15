//! russh Handler: mesh identity, authorization, then platform session execution.

use std::borrow::Cow;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;

use parking_lot::Mutex;
use russh::server::{Auth, ChannelOpenHandle, Handler, Msg, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet, Pty};
use tunnet_common::ws::ClientMsg;
use tunnet_core::{ConnPool, ForwardingStore, RoutingTable, SignedClient};
use uuid::Uuid;

use super::authorize::{
    AuthorizedSession, AuthzFailure, BindingPolicy, CheckState, identify_source,
};
use super::exec::{self, LaunchRequest};
use super::listener::SshBinding;
use super::tee::{
    RecorderTarget, RecordingTee, make_meta, recorder_unavailable, resolve_recorder_target,
};
use crate::actors::ssh_registry::{RegisterSession, SessionEnded, SshRegistryActor};
use crate::recorder::RecordingStore;

type PtyInTx = std::sync::mpsc::Sender<Vec<u8>>;
type PtyResizeTx = std::sync::mpsc::Sender<(u16, u16)>;
type PtyInMap = HashMap<ChannelId, PtyInTx>;
type PtyResizeMap = HashMap<ChannelId, PtyResizeTx>;

#[derive(Clone)]
pub struct SshServeDeps {
    pub routes: RoutingTable,
    pub forwarding: ForwardingStore,
    pub sessions: kameo::actor::ActorRef<SshRegistryActor>,
    pub cp_tx: Option<tokio::sync::mpsc::Sender<ClientMsg>>,
    pub pool: ConnPool,
    pub store: Option<Arc<RecordingStore>>,
    pub signed: Option<SignedClient>,
    pub hostname: String,
    #[allow(dead_code)]
    pub network_name: String,
}

pub struct SshHandler {
    deps: SshServeDeps,
    binding: SshBinding,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    authorized: Option<AuthorizedSession>,
    pending_reauth_url: Option<String>,
    check_period_secs: u64,
    channels: HashMap<ChannelId, Channel<Msg>>,
    pty_in: Arc<Mutex<PtyInMap>>,
    pty_resize: Arc<Mutex<PtyResizeMap>>,
    term: String,
    width: u16,
    height: u16,
    env_vars: Vec<(String, String)>,
}

impl SshHandler {
    pub fn new(
        deps: SshServeDeps,
        binding: SshBinding,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
    ) -> Self {
        Self {
            deps,
            binding,
            peer_addr,
            local_addr,
            authorized: None,
            pending_reauth_url: None,
            check_period_secs: 3600,
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
            return;
        };
        let _ = tx.try_send(msg);
    }

    fn authorize(&self, user: &str) -> Result<AuthorizedSession, AuthzFailure> {
        let source = identify_source(self.peer_addr, self.binding.network_id, &self.deps.routes)?;
        match &self.binding.policy {
            BindingPolicy::Direct { allowed_users } => super::authorize::authorize_direct(
                &source,
                self.binding.network_id,
                user,
                allowed_users,
            ),
            BindingPolicy::Managed => {
                let snap = self.deps.forwarding.load();
                super::authorize::authorize_managed(
                    &source,
                    self.binding.network_id,
                    &self.binding.network_name,
                    &snap.self_id.endpoint_hex,
                    &snap.self_id.tags,
                    user,
                    &snap.ssh_rules(),
                )
            }
        }
    }

    fn reject_direct() -> Auth {
        Auth::Reject {
            proceed_with_methods: Some(MethodSet::empty()),
            partial_success: false,
        }
    }

    async fn verify_check(&self, source: &str, period: u64) -> bool {
        let Some(client) = self.deps.signed.as_ref() else {
            return false;
        };
        match client.verify_ssh_auth(source, period, None).await {
            Ok(v) => v.get("status").and_then(|s| s.as_str()) == Some("ok"),
            Err(_) => false,
        }
    }

    async fn mint_reauth_url(&self, source: &str, period: u64) -> Option<String> {
        let client = self.deps.signed.as_ref()?;
        let eval = client.evaluate_ssh_auth(source, period).await.ok()?;
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
        let Some(authorized) = self.authorized.clone() else {
            let _ = session.channel_failure(channel);
            return Ok(());
        };
        if command.is_some() && !authorized.capabilities.exec {
            let _ = session.channel_failure(channel);
            return Ok(());
        }
        if command.is_none() && !authorized.capabilities.shell {
            let _ = session.channel_failure(channel);
            return Ok(());
        }

        let recorded = authorized.recording.record;
        let enforce_recorder = authorized.recording.enforce_recorder;
        let recorder_selector = authorized.recording.recorder.clone();
        let session_id = Uuid::new_v4();
        let mut tee: Option<RecordingTee> = None;
        if recorded {
            let target = resolve_recorder_target(
                &self.deps.routes,
                &self.deps.forwarding,
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
                            &authorized.source_endpoint,
                            authorized.source_hostname.clone(),
                            &authorized.dest_user,
                            &self.deps.hostname,
                            &self.binding.network_name,
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
                        &authorized.source_endpoint,
                        authorized.source_hostname.clone(),
                        &authorized.dest_user,
                        &self.deps.hostname,
                        &self.binding.network_name,
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

        let launched = match exec::spawn_shell(&LaunchRequest {
            account: authorized.account.clone(),
            term: self.term.clone(),
            width: self.width,
            height: self.height,
            env_vars: self.env_vars.clone(),
            command,
        }) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    peer = %authorized.source_endpoint,
                    source_network = %authorized.source_network,
                    dest_network = %authorized.dest_network,
                    mode = ?authorized.mode,
                    error = %e,
                    "SSH session execution failed"
                );
                let _ = session.channel_failure(channel);
                return Ok(());
            }
        };

        let _ = session.channel_success(channel);
        self.emit_cp(ClientMsg::SshSessionStarted {
            session_id: session_id.to_string(),
            src_endpoint_id: authorized.source_endpoint.clone(),
            target_user: authorized.dest_user.clone(),
            src_hostname: authorized.source_hostname.clone(),
            recorded: tee.is_some(),
        });

        let _ = self
            .deps
            .sessions
            .tell(RegisterSession {
                id: session_id,
                peer_hex: authorized.source_endpoint.clone(),
                target_user: authorized.dest_user.clone(),
                killer: launched.killer,
            })
            .send()
            .await;

        let (pty_out_tx, mut pty_out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
        let (pty_in_tx, pty_in_rx) = std::sync::mpsc::channel::<Vec<u8>>();
        self.pty_in.lock().insert(channel, pty_in_tx);
        if let Some(resize) = launched.resize {
            self.pty_resize.lock().insert(channel, resize);
        }

        let mut reader = launched.reader;
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
        let mut writer = launched.writer;
        std::thread::spawn(move || {
            while let Ok(chunk) = pty_in_rx.recv() {
                if writer.write_all(&chunk).is_err() {
                    break;
                }
                let _ = writer.flush();
            }
        });

        let handle = session.handle();
        let sessions = self.deps.sessions.clone();
        let cp_tx = self.deps.cp_tx.clone();
        let store = self.deps.store.clone();
        let signed = self.deps.signed.clone();
        let forwarding = self.deps.forwarding.clone();
        let peer_hex = authorized.source_endpoint.clone();
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
            let killed = sessions
                .ask(SessionEnded { id: session_id })
                .await
                .unwrap_or(false);
            let duration_ms = started.elapsed().as_millis() as u64;
            if let Some(t) = tee {
                match t.finish(store.as_deref(), duration_ms) {
                    Ok(Some((meta, finalized))) => {
                        if let Some(tx) = &cp_tx {
                            let _ = tx.try_send(ClientMsg::SshRecordingSaved {
                                session_id: meta.session_id.clone(),
                                recorder_endpoint_id: forwarding
                                    .load()
                                    .self_id
                                    .endpoint_hex
                                    .clone(),
                                duration_ms: Some(duration_ms),
                                byte_size: finalized.byte_size,
                                content_sha256: finalized.sha256_hex.clone(),
                            });
                        }
                        if let Some(client) = &signed
                            && let Ok(cast_text) = std::fs::read_to_string(&finalized.path)
                        {
                            let _ = client
                                .upload_ssh_recording(
                                    &meta.session_id,
                                    &cast_text,
                                    &finalized.sha256_hex,
                                )
                                .await;
                        }
                    }
                    Ok(None) => {}
                    Err(e) => tracing::warn!(?e, "failed to finalize recording"),
                }
            }
            if let Some(tx) = &cp_tx {
                let _ = tx.try_send(ClientMsg::SshSessionEnded {
                    session_id: session_id.to_string(),
                    status: if killed {
                        "killed".into()
                    } else {
                        "ended".into()
                    },
                    duration_ms: Some(duration_ms),
                });
            }
            tracing::debug!(%peer_hex, %session_id, "ssh session finished");
        });
        Ok(())
    }
}

impl Handler for SshHandler {
    type Error = russh::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        match self.authorize(user) {
            Err(failure) => {
                tracing::info!(
                    addr = %self.peer_addr,
                    local = %self.local_addr,
                    network = %self.binding.network_id,
                    user,
                    reason = %failure.log_message(),
                    "SSH authorization failed"
                );
                Ok(Self::reject_direct())
            }
            Ok(session) => match session.check {
                CheckState::None => {
                    self.authorized = Some(session);
                    Ok(Auth::Accept)
                }
                CheckState::Required { period_secs } => {
                    self.check_period_secs = period_secs;
                    if self
                        .verify_check(&session.source_endpoint, period_secs)
                        .await
                    {
                        self.authorized = Some(session);
                        return Ok(Auth::Accept);
                    }
                    if let Some(url) = self
                        .mint_reauth_url(&session.source_endpoint, period_secs)
                        .await
                    {
                        self.pending_reauth_url = Some(url);
                        self.authorized = Some(session);
                        let mut methods = MethodSet::empty();
                        methods.push(MethodKind::KeyboardInteractive);
                        Ok(Auth::Reject {
                            proceed_with_methods: Some(methods),
                            partial_success: false,
                        })
                    } else {
                        Ok(Auth::reject())
                    }
                }
            },
        }
    }

    async fn auth_keyboard_interactive(
        &mut self,
        _user: &str,
        _submethods: &str,
        response: Option<russh::server::Response<'_>>,
    ) -> Result<Auth, Self::Error> {
        if !matches!(self.binding.policy, BindingPolicy::Managed) {
            return Ok(Self::reject_direct());
        }
        let Some(url) = self.pending_reauth_url.clone() else {
            return Ok(Auth::reject());
        };
        let Some(session) = self.authorized.as_ref() else {
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
        if self
            .verify_check(&session.source_endpoint, self.check_period_secs)
            .await
        {
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
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
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
        if !self
            .authorized
            .as_ref()
            .is_some_and(|s| s.capabilities.env_forward)
        {
            session.channel_success(channel)?;
            return Ok(());
        }
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
        let Some(authorized) = self.authorized.as_ref() else {
            let _ = session.channel_failure(channel);
            return Ok(());
        };
        if name != "sftp" || !authorized.capabilities.sftp {
            let _ = session.channel_failure(channel);
            return Ok(());
        }
        let Some(ch) = self.channels.remove(&channel) else {
            let _ = session.channel_failure(channel);
            return Ok(());
        };
        match exec::spawn_sftp(&authorized.account) {
            Ok(mut child) => {
                let _ = session.channel_success(channel);
                let stream = ch.into_stream();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut stdin = match child.stdin.take() {
                        Some(s) => s,
                        None => return,
                    };
                    let mut stdout = match child.stdout.take() {
                        Some(s) => s,
                        None => return,
                    };
                    let (mut reader, mut writer) = tokio::io::split(stream);
                    let upload = async {
                        let mut buf = [0u8; 8192];
                        loop {
                            let n = reader.read(&mut buf).await?;
                            if n == 0 {
                                break;
                            }
                            stdin.write_all(&buf[..n]).await?;
                        }
                        Ok::<_, std::io::Error>(())
                    };
                    let download = async {
                        let mut buf = [0u8; 8192];
                        loop {
                            let n = stdout.read(&mut buf).await?;
                            if n == 0 {
                                break;
                            }
                            writer.write_all(&buf[..n]).await?;
                        }
                        Ok::<_, std::io::Error>(())
                    };
                    let _ = tokio::try_join!(upload, download);
                    let _ = child.kill().await;
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "SFTP spawn failed");
                let _ = session.channel_failure(channel);
            }
        }
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
