//! Tunnet audit logging: OCSF events, HMAC hash chain, Postgres sink.

pub mod chain;
pub mod class;
pub mod config;
pub mod emitter;
pub mod event;
pub mod sink;
pub mod stream;
pub mod worker;

#[cfg(feature = "postgres")]
pub mod postgres;

#[cfg(feature = "postgres")]
pub mod verify;

pub use chain::{CURRENT_SCHEMA_VERSION, GENESIS_HASH, canonical_v1, compute_entry_hash};
pub use class::*;
pub use config::AuditConfig;
pub use emitter::{AuditEmitter, start_worker};
pub use event::{Actor, AuditEvent, AuditIngestEvent, AuditIngestRequest, Diff, Target};
pub use sink::AuditSink;
pub use stream::{AuditStream, WebhookStream};

#[cfg(feature = "postgres")]
pub use postgres::PostgresPgSink;

#[cfg(feature = "postgres")]
pub use verify::{VerifyReport, verify_org_chain};
