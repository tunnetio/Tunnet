use tokio::sync::mpsc;

use crate::config::AuditConfig;
use crate::event::AuditEvent;
use crate::worker::AuditWorker;

#[derive(Clone)]
pub struct AuditEmitter {
    tx: mpsc::Sender<AuditEvent>,
}

impl AuditEmitter {
    pub fn new(config: AuditConfig) -> (Self, mpsc::Receiver<AuditEvent>) {
        let (tx, rx) = mpsc::channel(config.buffer_capacity);
        (Self { tx }, rx)
    }

    /// Fire-and-forget. Never blocks the caller.
    pub fn emit(&self, event: AuditEvent) {
        tracing::info!(
            target: "audit",
            category_uid = event.category_uid,
            class_uid = event.class_uid,
            activity_id = event.activity_id,
            organization_id = %event.organization_id,
            actor_id = %event.actor.actor_id,
            target_id = %event.target.target_id,
            message = %event.message,
            "audit_event"
        );

        match self.tx.try_send(event) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(e)) => {
                tracing::warn!(
                    organization_id = %e.organization_id,
                    "audit buffer full, event dropped — increase TUNNET_AUDIT_BUFFER_SIZE"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::error!("audit worker has shut down");
            }
        }
    }
}

/// Spawn the audit worker task. Returns the emitter handle.
pub fn start_worker(
    config: AuditConfig,
    sinks: Vec<Box<dyn crate::sink::AuditSink>>,
    streams: Vec<Box<dyn crate::stream::AuditStream>>,
) -> AuditEmitter {
    let batch_size = config.batch_size;
    let flush_interval = config.flush_interval;
    let (emitter, rx) = AuditEmitter::new(config);
    let worker = AuditWorker::new(rx, sinks, streams, batch_size, flush_interval);
    tokio::spawn(async move {
        worker.run().await;
    });
    emitter
}
