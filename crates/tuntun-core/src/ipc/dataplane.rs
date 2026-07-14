//! Handle for pausing / resuming the agent data plane (TUN + DNS + routes).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::{mpsc, oneshot};

pub enum DataPlaneCmd {
    Up(oneshot::Sender<Result<(), String>>),
    Down(oneshot::Sender<Result<(), String>>),
}

/// Cloneable control surface used by the IPC server.
#[derive(Clone)]
pub struct DataPlaneHandle {
    up: Arc<AtomicBool>,
    tx: mpsc::Sender<DataPlaneCmd>,
}

impl DataPlaneHandle {
    pub fn new(buffer: usize) -> (Self, mpsc::Receiver<DataPlaneCmd>) {
        let (tx, rx) = mpsc::channel(buffer);
        (
            Self {
                up: Arc::new(AtomicBool::new(true)),
                tx,
            },
            rx,
        )
    }

    pub fn is_up(&self) -> bool {
        self.up.load(Ordering::SeqCst)
    }

    pub fn set_up(&self, v: bool) {
        self.up.store(v, Ordering::SeqCst);
    }

    pub async fn bring_up(&self) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(DataPlaneCmd::Up(tx))
            .await
            .map_err(|_| "data plane controller stopped".to_string())?;
        rx.await
            .map_err(|_| "data plane controller dropped reply".to_string())?
    }

    pub async fn bring_down(&self) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(DataPlaneCmd::Down(tx))
            .await
            .map_err(|_| "data plane controller stopped".to_string())?;
        rx.await
            .map_err(|_| "data plane controller dropped reply".to_string())?
    }

    /// Agent-side: drain commands (used by the runtime controller loop).
    pub(crate) fn take_cmd(cmd: DataPlaneCmd) -> (bool, oneshot::Sender<Result<(), String>>) {
        match cmd {
            DataPlaneCmd::Up(tx) => (true, tx),
            DataPlaneCmd::Down(tx) => (false, tx),
        }
    }
}

/// Re-export cmd receiver type for the agent runtime.
pub type DataPlaneCmdRx = mpsc::Receiver<DataPlaneCmd>;

pub async fn recv_cmd(
    rx: &mut DataPlaneCmdRx,
) -> Option<(bool, oneshot::Sender<Result<(), String>>)> {
    let cmd = rx.recv().await?;
    Some(DataPlaneHandle::take_cmd(cmd))
}
