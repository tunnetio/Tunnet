//! Latest-wins byte slot between the agent runtime and a host FFI.
//!
//! Publishers never wait for a consumer. A slow or missing host skips
//! intermediate snapshots and always receives the newest encoded payload.

use std::sync::{Arc, Condvar, Mutex};

struct SlotState {
    payload: Option<Arc<[u8]>>,
    seq: u64,
    closed: bool,
}

/// Cross-thread latest snapshot bytes. Used by JNI (and later other hosts).
pub struct LatestSlot {
    state: Mutex<SlotState>,
    cv: Condvar,
}

impl LatestSlot {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(SlotState {
                payload: None,
                seq: 0,
                closed: false,
            }),
            cv: Condvar::new(),
        }
    }

    pub fn publish(&self, bytes: Vec<u8>) {
        let mut g = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if g.closed {
            return;
        }
        g.payload = Some(Arc::from(bytes.into_boxed_slice()));
        g.seq = g.seq.wrapping_add(1);
        self.cv.notify_all();
    }

    /// Current payload without waiting. `None` if nothing has been published.
    pub fn current(&self) -> Option<(u64, Arc<[u8]>)> {
        let g = self.state.lock().unwrap_or_else(|e| e.into_inner());
        Some((g.seq, g.payload.clone()?))
    }

    /// Block until `gen` moves past `seen`, or the slot is closed.
    pub fn wait_after(&self, seen: u64) -> Option<(u64, Arc<[u8]>)> {
        let mut g = self.state.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if g.seq != seen
                && let Some(payload) = g.payload.clone()
            {
                return Some((g.seq, payload));
            }
            if g.closed {
                return None;
            }
            g = self.cv.wait(g).unwrap_or_else(|e| e.into_inner());
        }
    }

    pub fn close(&self) {
        let mut g = self.state.lock().unwrap_or_else(|e| e.into_inner());
        g.closed = true;
        self.cv.notify_all();
    }

    pub fn is_closed(&self) -> bool {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).closed
    }
}

impl Default for LatestSlot {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn wait_after_zero_returns_the_first_payload() {
        let slot = LatestSlot::new();
        slot.publish(vec![1, 2, 3]);
        let (seq, bytes) = slot.wait_after(0).expect("payload");
        assert!(seq > 0);
        assert_eq!(&bytes[..], &[1, 2, 3]);
    }

    #[test]
    fn later_wait_sees_updates_and_skips_intermediates() {
        let slot = LatestSlot::new();
        slot.publish(vec![1]);
        let (g1, _) = slot.wait_after(0).unwrap();
        slot.publish(vec![2]);
        slot.publish(vec![3]);
        let (_, bytes) = slot.wait_after(g1).unwrap();
        assert_eq!(&bytes[..], &[3]);
    }

    #[test]
    fn close_unblocks_waiters() {
        let slot = Arc::new(LatestSlot::new());
        let waiter = slot.clone();
        let t = std::thread::spawn(move || waiter.wait_after(0));
        slot.close();
        assert!(t.join().unwrap().is_none());
    }

    #[test]
    fn slow_consumer_does_not_block_publish() {
        let slot = Arc::new(LatestSlot::new());
        slot.publish(vec![0]);
        let (seen, _) = slot.wait_after(0).unwrap();
        let consumer = slot.clone();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(80));
            consumer.wait_after(seen)
        });
        let start = Instant::now();
        for i in 1..200u8 {
            slot.publish(vec![i]);
        }
        assert!(
            start.elapsed() < Duration::from_millis(40),
            "publish waited on the consumer"
        );
        let (_, last) = t.join().unwrap().unwrap();
        assert_eq!(last[0], 199);
    }

    #[test]
    fn publish_after_close_is_ignored() {
        let slot = LatestSlot::new();
        slot.publish(vec![1]);
        slot.close();
        slot.publish(vec![2]);
        let (_, bytes) = slot.current().expect("first payload remains");
        assert_eq!(&bytes[..], &[1]);
    }

    #[test]
    fn current_is_none_before_the_first_publish() {
        assert!(LatestSlot::new().current().is_none());
    }

    #[test]
    fn replacing_a_payload_drops_the_previous_buffer() {
        let slot = LatestSlot::new();
        slot.publish(vec![1, 2, 3]);
        let weak = {
            let (_, bytes) = slot.current().unwrap();
            Arc::downgrade(&bytes)
        };
        slot.publish(vec![4]);
        assert!(
            weak.upgrade().is_none(),
            "replaced snapshot bytes must be dropped"
        );
    }

    #[test]
    fn waiter_sees_the_last_payload_then_none_after_close() {
        let slot = LatestSlot::new();
        slot.publish(vec![7]);
        let (seq, bytes) = slot.wait_after(0).unwrap();
        assert_eq!(&bytes[..], &[7]);
        slot.close();
        assert!(slot.wait_after(seq).is_none());
    }

    #[test]
    fn close_wakes_a_waiter_that_has_already_caught_up() {
        let slot = Arc::new(LatestSlot::new());
        slot.publish(vec![1]);
        let (seen, _) = slot.wait_after(0).unwrap();
        let waiter = slot.clone();
        let t = std::thread::spawn(move || waiter.wait_after(seen));
        slot.close();
        assert!(t.join().unwrap().is_none());
    }

    #[test]
    fn close_is_idempotent() {
        let slot = LatestSlot::new();
        slot.publish(vec![1]);
        let (seq, _) = slot.wait_after(0).unwrap();
        slot.close();
        slot.close();
        assert!(slot.is_closed());
        assert!(slot.wait_after(seq).is_none());
    }
}
