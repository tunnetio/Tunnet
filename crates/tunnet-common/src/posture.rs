use serde::{Deserialize, Serialize};

pub const POSTURE_RECEIPT_BOUND_SECS: u64 = 600;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PeerPosture {
    #[default]
    Unknown,
    Verified {
        passed_named_checks: Vec<String>,
        valid_until: jiff::Timestamp,
    },
}

impl PeerPosture {
    pub fn verified(
        names: impl IntoIterator<Item = impl Into<String>>,
        valid_until: jiff::Timestamp,
    ) -> Self {
        let mut passed_named_checks: Vec<String> = names.into_iter().map(Into::into).collect();
        passed_named_checks.sort();
        passed_named_checks.dedup();
        Self::Verified {
            passed_named_checks,
            valid_until,
        }
    }

    pub fn valid_until(&self) -> Option<jiff::Timestamp> {
        match self {
            Self::Unknown => None,
            Self::Verified { valid_until, .. } => Some(*valid_until),
        }
    }

    pub fn expired(&self, now: jiff::Timestamp) -> bool {
        match self {
            Self::Unknown => false,
            Self::Verified { valid_until, .. } => now >= *valid_until,
        }
    }

    pub fn satisfies(&self, required: &[String], now: jiff::Timestamp) -> bool {
        if required.is_empty() {
            return true;
        }
        let Self::Verified {
            passed_named_checks,
            valid_until,
        } = self
        else {
            return false;
        };
        if now >= *valid_until {
            return false;
        }
        required
            .iter()
            .any(|name| passed_named_checks.iter().any(|passed| passed == name))
    }

    // Freshness renewal preserves authorization identity.
    pub fn fingerprint(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        match self {
            Self::Unknown => 0u8.hash(&mut hasher),
            Self::Verified {
                passed_named_checks,
                ..
            } => {
                1u8.hash(&mut hasher);
                passed_named_checks.hash(&mut hasher);
            }
        }
        hasher.finish()
    }
}

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
