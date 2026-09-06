//! Centrally owned Tunnet QUIC transport profile for the mesh dataplane.
//!
//! Replaces implicit Iroh/noq defaults with one explicit configuration.
//! Baseline: CUBIC, small DATAGRAM send buffer (64 KiB), GSO on, DPLPMTUD on.
//! BBRv3 is an opt-in benchmark experiment, never the silent default.

use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::{AckFrequencyConfig, QuicTransportConfig, VarInt};

/// Tunnet DATAGRAM send buffer: 64 KiB. Large enough for pacing/bursts,
/// small enough that ~80 Mbps serializes it in ~6 ms instead of ~100 ms.
/// Diagnostic override via `TUNNET_QUIC_DATAGRAM_BUFFER_KB` (e.g. 64 vs
/// 128 vs 256 A/B runs); clamped to [4 KiB, 1 MiB] like `with_send_buffer`.
pub const DATAGRAM_SEND_BUFFER: usize = 64 * 1024;
/// Receive buffer: 256 KiB (generous inbound headroom, still bounded).
pub const DATAGRAM_RECV_BUFFER: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionControl {
    /// Safe production baseline.
    Cubic,
    /// Benchmark experiment only.
    Bbr3,
    /// Control for experiments.
    NewReno,
}

#[derive(Debug, Clone)]
pub struct TunnetTransportProfile {
    pub congestion: CongestionControl,
    pub datagram_send_buffer: usize,
    pub datagram_recv_buffer: usize,
    pub initial_rtt: Duration,
    pub initial_mtu: u16,
    pub ack_frequency_packets: Option<u64>,
}

impl Default for TunnetTransportProfile {
    fn default() -> Self {
        let send_buffer = std::env::var("TUNNET_QUIC_DATAGRAM_BUFFER_KB")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .map(|kb| kb.saturating_mul(1024).clamp(4096, 1024 * 1024))
            .unwrap_or(DATAGRAM_SEND_BUFFER);
        Self {
            congestion: CongestionControl::Cubic,
            datagram_send_buffer: send_buffer,
            datagram_recv_buffer: DATAGRAM_RECV_BUFFER,
            initial_rtt: Duration::from_millis(90),
            initial_mtu: 1200,
            ack_frequency_packets: None,
        }
    }
}

impl TunnetTransportProfile {
    pub fn bbr3_experiment() -> Self {
        Self {
            congestion: CongestionControl::Bbr3,
            ..Self::default()
        }
    }

    /// Override the DATAGRAM send buffer for the §19 experiment matrix
    /// (16/32/64/128 KiB, 64 KiB control). The application queue and the QUIC
    /// staging queue are one queueing budget: at ~80 Mbps even 64 KiB is
    /// several milliseconds, so smaller is not automatically worse.
    pub fn with_send_buffer(mut self, bytes: usize) -> Self {
        self.datagram_send_buffer = bytes.clamp(4096, 1024 * 1024);
        self
    }

    pub fn build(&self) -> QuicTransportConfig {
        let b = QuicTransportConfig::builder();
        let b = b
            .datagram_send_buffer_size(self.datagram_send_buffer)
            .datagram_receive_buffer_size(Some(self.datagram_recv_buffer))
            .initial_rtt(self.initial_rtt)
            .initial_mtu(self.initial_mtu)
            // Never raise min MTU aggressively on arbitrary internet paths.
            .min_mtu(1200)
            // GSO stays enabled: valuable pacing/offload, on by default.
            .enable_segmentation_offload(true);
        // Multipath intentionally left at Iroh default (disabled unless both
        // ends negotiate) so NAT traversal behavior is unchanged.
        let b = match self.congestion {
            CongestionControl::Cubic => b.congestion_controller_factory(Arc::new(
                noq_proto::congestion::CubicConfig::default(),
            )),
            CongestionControl::NewReno => b.congestion_controller_factory(Arc::new(
                noq_proto::congestion::NewRenoConfig::default(),
            )),
            CongestionControl::Bbr3 => b.congestion_controller_factory(Arc::new(
                noq_proto::congestion::Bbr3Config::default(),
            )),
        };
        let b = if let Some(n) = self.ack_frequency_packets
            && let Ok(v) = VarInt::from_u64(n)
        {
            let mut cfg = AckFrequencyConfig::default();
            cfg.ack_eliciting_threshold(v);
            b.ack_frequency_config(Some(cfg))
        } else {
            b
        };
        b.build()
    }

    /// Apply to an Iroh endpoint builder (single choke point for mesh endpoints).
    pub fn apply(&self, builder: iroh::endpoint::Builder) -> iroh::endpoint::Builder {
        builder.transport_config(self.build())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profile_builds() {
        let p = TunnetTransportProfile::default();
        assert_eq!(p.datagram_send_buffer, 64 * 1024);
        let _cfg = p.build();
    }

    #[test]
    fn bbr3_is_explicit_experiment() {
        let p = TunnetTransportProfile::bbr3_experiment();
        assert_eq!(p.congestion, CongestionControl::Bbr3);
        assert_eq!(
            TunnetTransportProfile::default().congestion,
            CongestionControl::Cubic
        );
    }
}
