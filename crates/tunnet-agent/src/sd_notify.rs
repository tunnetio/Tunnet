//! Minimal systemd sd_notify helpers (no extra crate).
//!
//! Used so `Type=notify-reload` services become "active" immediately, even while
//! the agent is idle waiting for `create` / `join` / `enroll`.

#![cfg(unix)]

use std::os::unix::net::UnixDatagram;

/// Tell systemd the daemon is up (`READY=1`). Safe to call more than once.
pub fn ready(status: &str) {
    let mut msg = String::from("READY=1\n");
    if !status.is_empty() {
        msg.push_str("STATUS=");
        msg.push_str(status);
        msg.push('\n');
    }
    send(&msg);
}

fn send(payload: &str) {
    let Some(raw) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let path = raw.to_string_lossy();
    if path.is_empty() {
        return;
    }

    let sock = match UnixDatagram::unbound() {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(?e, "sd_notify: unbound socket failed");
            return;
        }
    };

    if let Err(e) = connect_notify(&sock, &path) {
        tracing::debug!(?e, path = %path, "sd_notify: connect failed");
        return;
    }
    if let Err(e) = sock.send(payload.as_bytes()) {
        tracing::debug!(?e, "sd_notify: send failed");
        return;
    }
    tracing::debug!(path = %path, "sd_notify sent");
}

fn connect_notify(sock: &UnixDatagram, path: &str) -> std::io::Result<()> {
    // Abstract-namespace sockets: `std::os::linux` is Linux-only, and Android
    // has no systemd, so NOTIFY_SOCKET is never set there.
    #[cfg(target_os = "linux")]
    {
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::SocketAddr;
        if let Some(name) = path.strip_prefix('@') {
            let addr = SocketAddr::from_abstract_name(name.as_bytes())?;
            return sock.connect_addr(&addr);
        }
    }
    sock.connect(path)
}
