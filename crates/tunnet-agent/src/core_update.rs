use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use anyhow::{Context, ensure};
use futures_util::StreamExt;
use tokio::io::AsyncWriteExt;
use tunnet_common::local_api::{CoreUpdatePhase, CoreUpdateStatus, LocalEvent};
use tunnet_core::StatePaths;
use tunnet_update::CoreManifest;

pub struct CoreUpdater {
    paths: StatePaths,
    status: tokio::sync::RwLock<CoreUpdateStatus>,
    operation: tokio::sync::Mutex<()>,
    events: parking_lot::RwLock<tokio::sync::broadcast::Sender<LocalEvent>>,
}

static GLOBAL: OnceLock<Arc<CoreUpdater>> = OnceLock::new();

fn http_client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .user_agent(concat!("tunnetd/", env!("CARGO_PKG_VERSION")))
        .build()?)
}

impl CoreUpdater {
    pub fn shared(
        paths: StatePaths,
        events: tokio::sync::broadcast::Sender<LocalEvent>,
    ) -> Arc<Self> {
        let updater = GLOBAL
            .get_or_init(|| {
                let health_check = paths.update_pending_file().exists();
                Arc::new(Self {
                    paths,
                    status: tokio::sync::RwLock::new(CoreUpdateStatus {
                        phase: if health_check {
                            CoreUpdatePhase::HealthCheck
                        } else {
                            CoreUpdatePhase::Idle
                        },
                        current_version: env!("CARGO_PKG_VERSION").into(),
                        available_version: None,
                        api_version: tunnet_common::local_api::API_VERSION,
                        downloaded: 0,
                        total: None,
                        error: None,
                    }),
                    operation: tokio::sync::Mutex::new(()),
                    events: parking_lot::RwLock::new(events.clone()),
                })
            })
            .clone();
        *updater.events.write() = events;
        updater
    }

    pub async fn status(&self) -> CoreUpdateStatus {
        self.status.read().await.clone()
    }

    async fn set(&self, phase: CoreUpdatePhase, mutate: impl FnOnce(&mut CoreUpdateStatus)) {
        let mut status = self.status.write().await;
        status.phase = phase;
        mutate(&mut status);
        let _ = self.events.read().send(LocalEvent::CoreUpdateChanged {
            status: status.clone(),
        });
    }

    pub async fn check(&self) -> anyhow::Result<CoreUpdateStatus> {
        let _guard = self.operation.lock().await;
        self.set(CoreUpdatePhase::Checking, |s| s.error = None)
            .await;
        match self.fetch_manifest().await {
            Ok((_, manifest)) => {
                let current = semver::Version::parse(env!("CARGO_PKG_VERSION"))?;
                let target = semver::Version::parse(manifest.version.trim_start_matches('v'))?;
                self.set(
                    if target > current {
                        CoreUpdatePhase::Available
                    } else {
                        CoreUpdatePhase::Idle
                    },
                    |s| s.available_version = (target > current).then_some(manifest.version),
                )
                .await;
                Ok(self.status().await)
            }
            Err(error) => {
                self.fail(&error).await;
                Ok(self.status().await)
            }
        }
    }

    pub async fn stage_and_activate(
        self: &Arc<Self>,
        force: bool,
    ) -> anyhow::Result<CoreUpdateStatus> {
        let _guard = self.operation.lock().await;
        let result = self.stage(force).await;
        if let Err(error) = &result {
            self.fail(error).await;
        }
        result?;
        self.set(CoreUpdatePhase::Activating, |_| {}).await;
        self.schedule_activation()?;
        Ok(self.status().await)
    }

    async fn stage(&self, force: bool) -> anyhow::Result<()> {
        self.set(CoreUpdatePhase::Checking, |s| {
            s.error = None;
            s.downloaded = 0;
            s.total = None;
        })
        .await;
        let (raw, manifest) = self.fetch_manifest().await?;
        let current = semver::Version::parse(env!("CARGO_PKG_VERSION"))?;
        let target = semver::Version::parse(manifest.version.trim_start_matches('v'))?;
        ensure_upgrade_allowed(&current, &target, force)?;
        let artifact = tunnet_update::current_artifact(&manifest)?.clone();
        let stage = self.paths.update_staging_dir();
        if stage.exists() {
            std::fs::remove_dir_all(&stage)?;
        }
        std::fs::create_dir_all(&stage)?;
        std::fs::write(stage.join("core-manifest.json"), raw)?;
        self.set(CoreUpdatePhase::Downloading, |s| {
            s.available_version = Some(manifest.version.clone())
        })
        .await;
        let response = http_client()?
            .get(&artifact.url)
            .send()
            .await?
            .error_for_status()?;
        let total = response.content_length();
        let archive = stage.join("core.zip");
        let mut file = tokio::fs::File::create(&archive).await?;
        let mut stream = response.bytes_stream();
        let mut downloaded = 0;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            file.write_all(&chunk).await?;
            downloaded += chunk.len() as u64;
            self.set(CoreUpdatePhase::Downloading, |s| {
                s.downloaded = downloaded;
                s.total = total;
            })
            .await;
        }
        file.flush().await?;
        self.set(CoreUpdatePhase::Verifying, |_| {}).await;
        tunnet_update::verify_artifact(&archive, &manifest, &artifact, "tunnetd").await?;
        let payload = stage.join("payload");
        std::fs::create_dir_all(&payload)?;
        zip::ZipArchive::new(std::fs::File::open(&archive)?)?
            .extract_unwrapped_root_dir(&payload, zip::read::root_dir_common_filter)?;
        let root = payload_root(&payload)?;
        for name in unit_names() {
            ensure!(root.join(name).is_file(), "Core archive is missing {name}");
        }
        std::fs::write(
            stage.join("target-version"),
            manifest.version.trim_start_matches('v'),
        )?;
        self.set(CoreUpdatePhase::Staged, |_| {}).await;
        Ok(())
    }

    async fn fetch_manifest(&self) -> anyhow::Result<(Vec<u8>, CoreManifest)> {
        tunnet_update::fetch_manifest(concat!("tunnetd/", env!("CARGO_PKG_VERSION"))).await
    }

    fn schedule_activation(self: &Arc<Self>) -> anyhow::Result<()> {
        #[cfg(windows)]
        {
            let stage = self.paths.update_staging_dir();
            let root = payload_root(&stage.join("payload"))?;
            let worker = stage.join("tunnet-update-worker.exe");
            std::fs::copy(root.join("tunnetd.exe"), &worker)?;
            std::process::Command::new(worker)
                .arg("--activate-core-update")
                .arg(self.paths.root())
                .arg(std::process::id().to_string())
                .creation_flags(0x08000000)
                .spawn()?;
        }
        #[cfg(unix)]
        {
            let paths = self.paths.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                if let Err(error) = activate_staged(&paths).await {
                    tracing::error!(?error, "Core activation failed");
                }
            });
        }
        Ok(())
    }

    async fn fail(&self, error: &anyhow::Error) {
        self.set(CoreUpdatePhase::Error, |s| {
            s.error = Some(format!("{error:#}"))
        })
        .await;
    }
}

fn ensure_upgrade_allowed(
    current: &semver::Version,
    target: &semver::Version,
    force: bool,
) -> anyhow::Result<()> {
    ensure!(target >= current, "refusing to downgrade Tunnet Core");
    ensure!(
        force || target > current,
        "Tunnet Core is already up to date"
    );
    Ok(())
}

pub async fn publish_complete() {
    if let Some(updater) = GLOBAL.get() {
        updater
            .set(CoreUpdatePhase::Complete, |status| {
                status.current_version = env!("CARGO_PKG_VERSION").into();
                status.available_version = None;
                status.error = None;
            })
            .await;
    }
}

#[cfg(windows)]
use std::os::windows::process::CommandExt;

pub fn maybe_run_activation_worker() -> anyhow::Result<bool> {
    let args: Vec<_> = std::env::args_os().collect();
    let mode = args.get(1).and_then(|v| v.to_str());
    if !matches!(
        mode,
        Some("--activate-core-update" | "--rollback-core-update")
    ) {
        return Ok(false);
    }
    let state = args
        .get(2)
        .context("activation worker missing state directory")?;
    #[cfg(windows)]
    let parent: u32 = args
        .get(3)
        .and_then(|v| v.to_str())
        .context("activation worker missing parent PID")?
        .parse()?;
    let paths = StatePaths::resolve(Some(&state.to_string_lossy()));
    if mode == Some("--rollback-core-update") {
        #[cfg(windows)]
        stop_service_and_wait_for_parent(parent);
        crate::auto_update::revert_to_previous_worker(&paths)?;
    } else {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let manifest = runtime.block_on(load_staged_and_verify(&paths))?;
        #[cfg(windows)]
        stop_service_and_wait_for_parent(parent);
        activate_verified(&paths, &manifest)?;
    }
    Ok(true)
}

#[cfg(windows)]
pub fn schedule_rollback(paths: &StatePaths) -> anyhow::Result<()> {
    let previous = paths.update_previous_dir();
    let worker = paths.update_dir().join("tunnet-rollback-worker.exe");
    std::fs::copy(previous.join("tunnetd.exe"), &worker)?;
    std::process::Command::new(worker)
        .arg("--rollback-core-update")
        .arg(paths.root())
        .arg(std::process::id().to_string())
        .creation_flags(0x08000000)
        .spawn()?;
    Ok(())
}

#[cfg(not(windows))]
pub async fn activate_staged(paths: &StatePaths) -> anyhow::Result<()> {
    let manifest = load_staged_and_verify(paths).await?;
    activate_verified(paths, &manifest)
}

async fn load_staged_and_verify(paths: &StatePaths) -> anyhow::Result<CoreManifest> {
    let stage = paths.update_staging_dir();
    let raw = std::fs::read(stage.join("core-manifest.json"))?;
    let manifest = tunnet_update::parse_manifest(&raw)?;
    let artifact = tunnet_update::current_artifact(&manifest)?;
    let archive = stage.join("core.zip");
    tunnet_update::verify_artifact(&archive, &manifest, artifact, "tunnetd-worker").await?;
    Ok(manifest)
}

fn activate_verified(paths: &StatePaths, manifest: &CoreManifest) -> anyhow::Result<()> {
    let stage = paths.update_staging_dir();
    let root = payload_root(&stage.join("payload"))?;
    #[cfg(windows)]
    let install = tunnet_service::installed_bin_dir(None);
    #[cfg(not(windows))]
    let install = std::env::current_exe()?
        .parent()
        .context("daemon executable has no parent")?
        .to_path_buf();
    let previous = paths.update_previous_dir();
    if previous.exists() {
        std::fs::remove_dir_all(&previous)?;
    }
    std::fs::create_dir_all(&previous)?;
    for name in unit_names() {
        let dest = install.join(name);
        if dest.is_file() {
            std::fs::copy(&dest, previous.join(name))?;
        }
    }
    let activate = (|| -> anyhow::Result<()> {
        for name in unit_names() {
            replace_file(&root.join(name), &install.join(name))?;
        }
        crate::auto_update::stage_pending(
            paths,
            env!("CARGO_PKG_VERSION"),
            manifest.version.trim_start_matches('v'),
            manifest.api_version,
            30,
        )?;
        #[cfg(windows)]
        {
            tunnet_service::start(None)
        }
        #[cfg(not(windows))]
        {
            crate::cmds_update::apply_service_reload(false)
        }
    })();
    if let Err(error) = activate {
        let _ = restore_previous_unit(&previous, &install);
        let _ = std::fs::remove_file(paths.update_pending_file());
        #[cfg(windows)]
        let _ = tunnet_service::start(None);
        return Err(
            error.context("Core activation failed; restored the previous installation unit")
        );
    }
    Ok(())
}

fn restore_previous_unit(previous: &Path, install: &Path) -> anyhow::Result<()> {
    for name in unit_names() {
        let source = previous.join(name);
        if source.is_file() {
            replace_file(&source, &install.join(name))?;
        }
    }
    Ok(())
}

fn payload_root(root: &Path) -> anyhow::Result<PathBuf> {
    if root.join(unit_names()[0]).is_file() {
        return Ok(root.into());
    }
    for entry in std::fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() && path.join(unit_names()[0]).is_file() {
            return Ok(path);
        }
    }
    anyhow::bail!("Core archive has no payload directory")
}

#[cfg(windows)]
fn unit_names() -> &'static [&'static str] {
    &["tunnet.exe", "tunnetd.exe"]
}
#[cfg(not(windows))]
fn unit_names() -> &'static [&'static str] {
    &["tunnet", "tunnetd"]
}

fn replace_file(source: &Path, dest: &Path) -> anyhow::Result<()> {
    let staged = dest.with_extension("new");
    let replaced = dest.with_extension("replaced");
    let _ = std::fs::remove_file(&staged);
    let _ = std::fs::remove_file(&replaced);
    std::fs::copy(source, &staged)?;
    if dest.exists() {
        std::fs::rename(dest, &replaced)?;
    }
    std::fs::rename(staged, dest)?;
    let _ = std::fs::remove_file(replaced);
    Ok(())
}

#[cfg(windows)]
fn process_is_running(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return false;
        }
        CloseHandle(handle);
        true
    }
}

#[cfg(windows)]
fn stop_service_and_wait_for_parent(parent: u32) {
    let _ = tunnet_service::stop(None);
    for _ in 0..100 {
        if !process_is_running(parent) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upgrade_policy_never_allows_downgrades() {
        let current = semver::Version::new(2, 0, 0);
        let older = semver::Version::new(1, 9, 9);
        let same = current.clone();
        let newer = semver::Version::new(2, 0, 1);

        assert!(ensure_upgrade_allowed(&current, &older, false).is_err());
        assert!(ensure_upgrade_allowed(&current, &older, true).is_err());
        assert!(ensure_upgrade_allowed(&current, &same, false).is_err());
        assert!(ensure_upgrade_allowed(&current, &same, true).is_ok());
        assert!(ensure_upgrade_allowed(&current, &newer, false).is_ok());
    }
}
