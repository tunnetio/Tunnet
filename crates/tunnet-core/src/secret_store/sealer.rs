//! Host-provided wrap/unwrap for the data-encryption key.
//!
//! The host never sees identity semantics. It only encrypts opaque bytes with a
//! platform key that must not be exportable into application memory.

use std::sync::Arc;

use parking_lot::Mutex;
use thiserror::Error;

static SEALER: Mutex<Option<Arc<dyn PlatformSealer>>> = Mutex::new(None);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealErrorKind {
    NotInstalled,
    KeyUnavailable,
    KeyInvalidated,
    CiphertextInvalid,
    DecryptFailed,
    OperationFailed,
    Unsupported,
}

#[derive(Debug, Clone, Error)]
#[error("{kind:?}: {message}")]
pub struct SealError {
    pub kind: SealErrorKind,
    message: String,
}

impl SealError {
    pub fn new(kind: SealErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

pub trait PlatformSealer: Send + Sync {
    fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>, SealError>;
    fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>, SealError>;
}

pub fn set_platform_sealer(sealer: Arc<dyn PlatformSealer>) {
    *SEALER.lock() = Some(sealer);
}

pub fn clear_platform_sealer() {
    *SEALER.lock() = None;
}

pub(super) fn wrap_with_platform(plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
    current()?.wrap(plaintext)
}

pub(super) fn unwrap_with_platform(wrapped: &[u8]) -> Result<Vec<u8>, SealError> {
    current()?.unwrap(wrapped)
}

fn current() -> Result<Arc<dyn PlatformSealer>, SealError> {
    SEALER
        .lock()
        .clone()
        .ok_or_else(|| SealError::new(SealErrorKind::NotInstalled, "no platform sealer installed"))
}
