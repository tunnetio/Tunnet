//! OCSF class UIDs and Tunnet extension classes.

/// OCSF Category 7: Audit Activity
pub const CATEGORY_AUDIT: u16 = 7;

/// Standard OCSF classes
pub const ACCOUNT_CHANGE: u16 = 7001;
pub const AUTH_AUDIT: u16 = 7002;
pub const ENTITY_MGMT: u16 = 7003;

/// Tunnet extension classes (70xx)
pub const NETWORK_ACTIVITY: u16 = 7101;
pub const DEVICE_ACTIVITY: u16 = 7102;
pub const POLICY_ACTIVITY: u16 = 7103;
pub const TUNNEL_ACTIVITY: u16 = 7104;
pub const SSH_SESSION: u16 = 7105;
pub const RELAY_ACTIVITY: u16 = 7106;
pub const POSTURE_ACTIVITY: u16 = 7107;
pub const CERTIFICATE_ACTIVITY: u16 = 7108;
pub const FILE_TRANSFER: u16 = 7109;
pub const SERVE_ACTIVITY: u16 = 7110;
pub const API_KEY_ACTIVITY: u16 = 7111;

/// OCSF activity IDs
pub const ACTIVITY_CREATE: u8 = 1;
pub const ACTIVITY_READ: u8 = 2;
pub const ACTIVITY_UPDATE: u8 = 3;
pub const ACTIVITY_DELETE: u8 = 4;
pub const ACTIVITY_OTHER: u8 = 99;

/// OCSF severity
pub const SEVERITY_INFO: u8 = 1;
pub const SEVERITY_LOW: u8 = 2;
pub const SEVERITY_MEDIUM: u8 = 3;
pub const SEVERITY_HIGH: u8 = 4;
pub const SEVERITY_CRITICAL: u8 = 5;

/// OCSF status
pub const STATUS_UNKNOWN: u8 = 0;
pub const STATUS_SUCCESS: u8 = 1;
pub const STATUS_FAILURE: u8 = 2;

pub fn type_uid(class_uid: u16, activity_id: u8) -> u32 {
    (class_uid as u32) * 100 + (activity_id as u32)
}
