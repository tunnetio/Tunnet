use serde::{Deserialize, Serialize};

/// Custom script collector configuration pushed from control plane.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CustomScriptConfig {
    pub name: String,
    pub path: String,
    pub timeout_secs: u64,
}

/// Per-posture evaluation result sent to agents / management.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PostureEvalResult {
    pub name: String,
    pub passed: bool,
    #[serde(default)]
    pub failing_assertions: Vec<String>,
}

/// Org-level posture enforcement settings (embedded in policy bundle).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PostureEnforcementConfig {
    /// `monitor` | `warn` | `enforce`
    #[serde(default = "default_enforcement_mode")]
    pub mode: String,
    #[serde(default = "default_grace_period_minutes")]
    pub grace_period_minutes: u32,
    #[serde(default = "default_recheck_on_fail_secs")]
    pub recheck_on_fail_secs: u64,
    #[serde(default = "default_true")]
    pub notify_user: bool,
    #[serde(default)]
    pub notify_admin: bool,
    #[serde(default = "default_true")]
    pub auto_reauthorize: bool,
}

fn default_enforcement_mode() -> String {
    "monitor".into()
}

fn default_grace_period_minutes() -> u32 {
    30
}

fn default_recheck_on_fail_secs() -> u64 {
    60
}

fn default_true() -> bool {
    true
}

impl Default for PostureEnforcementConfig {
    fn default() -> Self {
        Self {
            mode: default_enforcement_mode(),
            grace_period_minutes: default_grace_period_minutes(),
            recheck_on_fail_secs: default_recheck_on_fail_secs(),
            notify_user: true,
            notify_admin: false,
            auto_reauthorize: true,
        }
    }
}
