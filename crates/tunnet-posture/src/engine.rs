use crate::collector::PostureCollector;
use crate::collectors::{
    AntivirusCollector, AppCheckConfig, ApplicationCheckCollector, CustomScriptCollector,
    CustomScriptConfig as LocalScriptConfig, DiskEncryptionCollector, DomainJoinedCollector,
    FileCheckCollector, FileCheckConfig, FirewallCollector, MacSecurityCollector, MdmCollector,
    OsCollector, OsUpdatesCollector, ScreenLockCollector, SecureBootCollector, TpmCollector,
};
use crate::error::PostureError;
use crate::score::{PostureScoringConfig, inject_posture_score};
use crate::value::PostureValue;
use jiff::Timestamp;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock, broadcast};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};
use tunnet_common::posture::CustomScriptConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectorStatus {
    Ok,
    Error,
    Unavailable,
}

#[derive(Debug, Clone)]
pub struct PostureState {
    pub attributes: HashMap<String, PostureValue>,
    pub last_collected: HashMap<String, Timestamp>,
    pub collector_statuses: HashMap<String, CollectorStatus>,
    pub state_hash: String,
}

#[derive(Debug, Clone)]
pub struct PostureCollection {
    pub attributes: HashMap<String, PostureValue>,
    pub state_hash: String,
    pub collected_at: Timestamp,
}

#[derive(Debug, Clone)]
pub struct PostureEngineConfig {
    pub interval: Duration,
    pub enabled_collectors: Option<Vec<String>>,
    pub tunnet_version: String,
    pub app_checks: Vec<AppCheckConfig>,
    pub file_checks: Vec<FileCheckConfig>,
    pub custom_scripts: Vec<CustomScriptConfig>,
    pub custom_scripts_dir: PathBuf,
    pub scoring: PostureScoringConfig,
}

impl Default for PostureEngineConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(300),
            enabled_collectors: None,
            tunnet_version: env!("CARGO_PKG_VERSION").into(),
            app_checks: Vec::new(),
            file_checks: Vec::new(),
            custom_scripts: Vec::new(),
            custom_scripts_dir: default_scripts_dir(),
            scoring: PostureScoringConfig::default_weights(),
        }
    }
}

fn default_scripts_dir() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/etc/tunnet/posture.d")
    }
    #[cfg(windows)]
    {
        PathBuf::from(r"C:\ProgramData\Tunnet\posture.d")
    }
    #[cfg(not(any(unix, windows)))]
    {
        PathBuf::from("./posture.d")
    }
}

pub struct PostureEngine {
    collectors: RwLock<Vec<Box<dyn PostureCollector>>>,
    collection: Mutex<()>,
    config: RwLock<PostureEngineConfig>,
    state: Arc<RwLock<PostureState>>,
    change_tx: broadcast::Sender<PostureCollection>,
}

impl PostureEngine {
    pub fn new(collectors: Vec<Box<dyn PostureCollector>>, config: PostureEngineConfig) -> Self {
        let (change_tx, _) = broadcast::channel(64);
        Self {
            collectors: RwLock::new(collectors),
            collection: Mutex::new(()),
            config: RwLock::new(config),
            state: Arc::new(RwLock::new(PostureState {
                attributes: HashMap::new(),
                last_collected: HashMap::new(),
                collector_statuses: HashMap::new(),
                state_hash: String::new(),
            })),
            change_tx,
        }
    }

    pub fn with_default_collectors(config: PostureEngineConfig) -> Self {
        let collectors = Self::default_collectors(&config);
        Self::new(collectors, config)
    }

    pub fn default_collectors(config: &PostureEngineConfig) -> Vec<Box<dyn PostureCollector>> {
        let mut collectors: Vec<Box<dyn PostureCollector>> = vec![
            Box::new(OsCollector::new(config.tunnet_version.clone())),
            Box::new(DiskEncryptionCollector),
            Box::new(FirewallCollector),
            Box::new(AntivirusCollector),
            Box::new(SecureBootCollector),
            Box::new(TpmCollector),
            Box::new(ScreenLockCollector),
            Box::new(OsUpdatesCollector),
            Box::new(MdmCollector),
            Box::new(DomainJoinedCollector),
            Box::new(MacSecurityCollector),
        ];

        if !config.app_checks.is_empty() {
            collectors.push(Box::new(ApplicationCheckCollector::new(
                config.app_checks.clone(),
            )));
        }
        if !config.file_checks.is_empty() {
            collectors.push(Box::new(FileCheckCollector::new(
                config.file_checks.clone(),
            )));
        }
        collectors.push(Box::new(CustomScriptCollector::new(
            config.custom_scripts_dir.clone(),
            config
                .custom_scripts
                .iter()
                .map(|s| LocalScriptConfig {
                    name: s.name.clone(),
                    path: PathBuf::from(&s.path),
                })
                .collect(),
        )));

        collectors.retain(|c| {
            c.is_available()
                && config
                    .enabled_collectors
                    .as_ref()
                    .is_none_or(|enabled| enabled.iter().any(|name| name == c.name()))
        });
        collectors
    }

    pub fn subscribe(&self) -> broadcast::Receiver<PostureCollection> {
        self.change_tx.subscribe()
    }

    pub async fn state(&self) -> PostureState {
        self.state.read().await.clone()
    }

    pub async fn apply_config(
        &self,
        interval: Duration,
        enabled_collectors: Option<Vec<String>>,
        custom_scripts: Vec<CustomScriptConfig>,
    ) {
        let mut config = self.config.write().await;
        config.interval = interval;
        config.enabled_collectors = enabled_collectors.clone();
        config.custom_scripts = custom_scripts;
        let mut collectors = Self::default_collectors(&config);
        if let Some(enabled) = &enabled_collectors {
            collectors.retain(|c| enabled.iter().any(|name| name == c.name()));
        }
        *self.collectors.write().await = collectors;
    }

    pub async fn collect_once(&self) -> Result<PostureCollection, PostureError> {
        let event = self.run_collection().await?;
        let _ = self.change_tx.send(event.clone());
        Ok(event)
    }

    pub async fn run(self: Arc<Self>, cancel: CancellationToken) {
        loop {
            let collection = tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                result = self.collect_once() => result,
            };
            match collection {
                Ok(_) => {}
                Err(error) => warn!(%error, "posture collection cycle failed"),
            }
            let interval = self
                .config
                .read()
                .await
                .interval
                .min(Duration::from_secs(300));
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(interval.max(Duration::from_secs(30))) => {}
            }
        }
    }

    async fn run_collection(&self) -> Result<PostureCollection, PostureError> {
        let _collection = self.collection.lock().await;
        let now = Timestamp::now();
        let mut new_attrs = HashMap::new();
        let mut statuses = HashMap::new();

        let collectors = self.collectors.read().await;
        let mut results = Vec::new();
        for collector in collectors.iter() {
            let name = collector.name().to_string();
            let result = if collector.is_available() {
                tokio::time::timeout(Duration::from_secs(30), collector.collect())
                    .await
                    .unwrap_or_else(|_| {
                        Err(PostureError::collector_failed(
                            &name,
                            "collection timed out",
                        ))
                    })
            } else {
                Err(PostureError::NotAvailable {
                    collector: name.clone(),
                })
            };
            results.push((name, result));
        }
        drop(collectors);

        for (name, result) in results {
            match result {
                Ok(attrs) => {
                    statuses.insert(name.clone(), CollectorStatus::Ok);
                    for (k, v) in attrs.attributes {
                        new_attrs.insert(k, v);
                    }
                    if let Some(err) = attrs.error {
                        warn!(collector = %name, error = %err, "collector reported partial error");
                    }
                }
                Err(PostureError::NotAvailable { .. }) => {
                    statuses.insert(name, CollectorStatus::Unavailable);
                }
                Err(e) => {
                    warn!(collector = %name, error = %e, "collector failed");
                    statuses.insert(name, CollectorStatus::Error);
                }
            }
        }

        let scoring = self.config.read().await.scoring.clone();
        inject_posture_score(&mut new_attrs, &scoring);

        let mut state = self.state.write().await;
        state.attributes = new_attrs;
        state.collector_statuses = statuses;
        state.last_collected = state
            .collector_statuses
            .keys()
            .map(|name| (name.clone(), now))
            .collect();
        state.state_hash = compute_state_hash(&state.attributes);

        debug!(
            total_attrs = state.attributes.len(),
            "posture collection complete"
        );

        Ok(PostureCollection {
            attributes: state.attributes.clone(),
            state_hash: state.state_hash.clone(),
            collected_at: now,
        })
    }
}

pub fn compute_state_hash(attrs: &HashMap<String, PostureValue>) -> String {
    let mut keys: Vec<&String> = attrs.keys().collect();
    keys.sort();

    let mut hasher = blake3::Hasher::new();
    for key in keys {
        if let Some(val) = attrs.get(key) {
            hasher.update(key.as_bytes());
            hasher.update(b"=");
            hasher.update(val.to_string().as_bytes());
            hasher.update(b";");
        }
    }
    hasher.finalize().to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Platform, PostureAttributes};
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Probe(Arc<AtomicBool>);

    #[async_trait::async_trait]
    impl PostureCollector for Probe {
        fn name(&self) -> &'static str {
            "probe"
        }
        fn namespace(&self) -> &'static str {
            "probe"
        }
        fn supported_platforms(&self) -> &[Platform] {
            &[Platform::Windows, Platform::Linux]
        }
        fn is_available(&self) -> bool {
            true
        }
        async fn collect(&self) -> Result<PostureAttributes, PostureError> {
            if self.0.load(Ordering::SeqCst) {
                Ok(PostureAttributes::new("probe")
                    .with_attribute("probe:healthy", PostureValue::Bool(true)))
            } else {
                Err(PostureError::collector_failed("probe", "unavailable"))
            }
        }
    }

    #[tokio::test]
    async fn unchanged_reports_refresh_and_failed_evidence_is_removed() {
        let healthy = Arc::new(AtomicBool::new(true));
        let engine = PostureEngine::new(
            vec![Box::new(Probe(healthy.clone()))],
            PostureEngineConfig::default(),
        );
        let mut reports = engine.subscribe();
        for _ in 0..2 {
            engine.collect_once().await.unwrap();
            assert_eq!(
                reports
                    .recv()
                    .await
                    .unwrap()
                    .attributes
                    .get("probe:healthy"),
                Some(&PostureValue::Bool(true))
            );
        }
        healthy.store(false, Ordering::SeqCst);
        engine.collect_once().await.unwrap();
        assert!(
            !reports
                .recv()
                .await
                .unwrap()
                .attributes
                .contains_key("probe:healthy")
        );
        assert_eq!(
            engine.state().await.collector_statuses["probe"],
            CollectorStatus::Error
        );
        healthy.store(true, Ordering::SeqCst);
        engine.collect_once().await.unwrap();
        assert_eq!(
            reports
                .recv()
                .await
                .unwrap()
                .attributes
                .get("probe:healthy"),
            Some(&PostureValue::Bool(true))
        );
    }
}
