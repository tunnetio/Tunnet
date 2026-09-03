//! `tunnetd` binary. All logic lives in the library so that embedders which
//! cannot spawn a process (Android's `VpnService`) share one runtime.

fn main() {
    tunnet_agent::run_cli();
}
