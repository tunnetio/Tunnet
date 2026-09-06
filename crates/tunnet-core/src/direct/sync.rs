use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DirectSignalMsg {
    JoinPrepare {
        hostname: String,
        invite_id: Option<String>,
    },
    JoinCommit {
        hostname: String,
        invite_id: Option<String>,
    },
    UpgradeToManaged {
        control_url: String,
        enrollment_token: String,
        network_id: String,
    },
}
