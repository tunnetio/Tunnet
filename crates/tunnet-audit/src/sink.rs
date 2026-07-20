use async_trait::async_trait;

use crate::event::AuditEvent;

#[async_trait]
pub trait AuditSink: Send + Sync {
    fn name(&self) -> &str;

    /// Persist a batch. May mutate events to fill hash-chain fields.
    async fn write_batch(&self, events: &mut [AuditEvent]) -> anyhow::Result<()>;

    async fn read_last_chain_state(&self, org_id: &str) -> anyhow::Result<Option<(i64, String)>>;
}
