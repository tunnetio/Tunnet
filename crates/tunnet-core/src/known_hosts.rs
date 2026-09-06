//! Rewrite the Tunnet `known_hosts` file from peer membership host keys.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Context;
use tunnet_common::PeerEntry;

/// Build a single OpenSSH known_hosts line for a peer.
///
/// `openssh_pubkey` is `ssh-ed25519 AAAA... [comment]`.
pub fn known_hosts_line(hosts: &[&str], openssh_pubkey: &str) -> Option<String> {
    let key = openssh_pubkey.trim();
    if key.is_empty() || hosts.is_empty() {
        return None;
    }
    let mut parts = key.split_whitespace();
    let key_type = parts.next()?;
    let key_data = parts.next()?;
    if key_type.is_empty() || key_data.is_empty() {
        return None;
    }
    let mut host_list = Vec::new();
    for h in hosts {
        let h = h.trim();
        if !h.is_empty() && !host_list.iter().any(|x: &String| x == h) {
            host_list.push(h.to_string());
        }
    }
    if host_list.is_empty() {
        return None;
    }
    Some(format!("{} {} {}", host_list.join(","), key_type, key_data))
}

/// Rewrite `state_dir/known_hosts` from peers that advertise an SSH host key.
pub fn sync_known_hosts(
    state_dir: &Path,
    peers: &[PeerEntry],
    dns_suffix: &str,
) -> anyhow::Result<()> {
    let path = state_dir.join("known_hosts");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create known_hosts dir {}", parent.display()))?;
    }

    // Deduplicate by endpoint so multi-network peers don't emit twice.
    let mut by_endpoint: BTreeMap<&str, &PeerEntry> = BTreeMap::new();
    for p in peers {
        if p.ssh_host_key
            .as_ref()
            .is_some_and(|k| !k.trim().is_empty())
        {
            by_endpoint.insert(p.endpoint_id.as_str(), p);
        }
    }

    let mut lines = Vec::new();
    for p in by_endpoint.values() {
        let Some(key) = p.ssh_host_key.as_deref() else {
            continue;
        };
        let ip = p.ip.to_string();
        let mut hosts: Vec<&str> = vec![ip.as_str()];
        let fqdn;
        if !p.hostname.is_empty() {
            hosts.push(p.hostname.as_str());
            fqdn = format!("{}.{}", p.hostname, dns_suffix.trim_matches('.'));
            hosts.push(fqdn.as_str());
        }
        if let Some(line) = known_hosts_line(&hosts, key) {
            lines.push(line);
        }
    }
    lines.sort();
    lines.dedup();

    let mut body = lines.join("\n");
    if !body.is_empty() {
        body.push('\n');
    }
    std::fs::write(&path, body).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Upsert one peer's host key into an existing known_hosts file (gossip path).
pub fn upsert_known_hosts_entry(
    state_dir: &Path,
    hosts: &[&str],
    openssh_pubkey: &str,
) -> anyhow::Result<()> {
    let Some(new_line) = known_hosts_line(hosts, openssh_pubkey) else {
        return Ok(());
    };
    let path = state_dir.join("known_hosts");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let host_set: std::collections::HashSet<&str> = hosts.iter().copied().collect();
    let mut kept = Vec::new();
    for line in existing.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            kept.push(line.to_string());
            continue;
        }
        let Some((host_field, _)) = line.split_once(char::is_whitespace) else {
            kept.push(line.to_string());
            continue;
        };
        let overlaps = host_field.split(',').any(|h| host_set.contains(h));
        if !overlaps {
            kept.push(line.to_string());
        }
    }
    kept.push(new_line);
    kept.sort();
    kept.dedup();
    let mut body = kept.join("\n");
    if !body.is_empty() {
        body.push('\n');
    }
    std::fs::write(&path, body)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn formats_known_hosts_line() {
        let line = known_hosts_line(
            &["10.21.0.1", "db"],
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake comment",
        )
        .unwrap();
        assert_eq!(
            line,
            "10.21.0.1,db ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake"
        );
    }

    #[test]
    fn sync_writes_file() {
        let dir = tempfile::tempdir().unwrap();
        let peers = vec![PeerEntry {
            ip: Ipv4Addr::new(10, 21, 0, 2),
            endpoint_id: "abcd".into(),
            hostname: "db".into(),
            tags: vec![],
            ssh_host_key: Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest".into()),
        }];
        sync_known_hosts(dir.path(), &peers, "tunnet").unwrap();
        let body = std::fs::read_to_string(dir.path().join("known_hosts")).unwrap();
        assert!(body.contains("10.21.0.2"));
        assert!(body.contains("db.tunnet"));
        assert!(body.contains("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest"));
    }
}
