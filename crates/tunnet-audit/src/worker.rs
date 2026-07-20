use std::collections::HashMap;
use std::time::Duration;

use tokio::sync::mpsc;

use crate::event::AuditEvent;
use crate::sink::AuditSink;
use crate::stream::AuditStream;

pub struct AuditWorker {
    rx: mpsc::Receiver<AuditEvent>,
    sinks: Vec<Box<dyn AuditSink>>,
    streams: Vec<Box<dyn AuditStream>>,
    batch_size: usize,
    flush_interval: Duration,
}

impl AuditWorker {
    pub fn new(
        rx: mpsc::Receiver<AuditEvent>,
        sinks: Vec<Box<dyn AuditSink>>,
        streams: Vec<Box<dyn AuditStream>>,
        batch_size: usize,
        flush_interval: Duration,
    ) -> Self {
        Self {
            rx,
            sinks,
            streams,
            batch_size,
            flush_interval,
        }
    }

    pub async fn run(mut self) {
        let mut batch: Vec<AuditEvent> = Vec::with_capacity(self.batch_size);
        let mut interval = tokio::time::interval(self.flush_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                maybe = self.rx.recv() => {
                    match maybe {
                        Some(event) => {
                            batch.push(event);
                            if batch.len() >= self.batch_size {
                                self.flush(&mut batch).await;
                            }
                        }
                        None => {
                            if !batch.is_empty() {
                                self.flush(&mut batch).await;
                            }
                            break;
                        }
                    }
                }
                _ = interval.tick() => {
                    if !batch.is_empty() {
                        self.flush(&mut batch).await;
                    }
                }
            }
        }
    }

    async fn flush(&self, batch: &mut Vec<AuditEvent>) {
        let mut by_org: HashMap<String, Vec<AuditEvent>> = HashMap::new();
        for event in batch.drain(..) {
            by_org
                .entry(event.organization_id.clone())
                .or_default()
                .push(event);
        }

        let mut chained_all: Vec<AuditEvent> = Vec::new();

        for (_org, mut events) in by_org {
            // Primary sink chains under advisory lock and fills hash fields.
            if let Some(primary) = self.sinks.first()
                && let Err(e) = primary.write_batch(&mut events).await
            {
                tracing::error!(?e, sink = primary.name(), "audit sink write failed");
                continue;
            }
            // Secondary sinks (e.g. ClickHouse later) get already-chained events.
            for sink in self.sinks.iter().skip(1) {
                if let Err(e) = sink.write_batch(&mut events).await {
                    tracing::error!(?e, sink = sink.name(), "audit sink write failed");
                }
            }
            chained_all.append(&mut events);
        }

        if !self.streams.is_empty() && !chained_all.is_empty() {
            for stream in &self.streams {
                let events = chained_all.clone();
                let stream = stream.clone_box();
                tokio::spawn(async move {
                    stream.send_with_retry(&events, 5).await;
                });
            }
        }
    }
}
