//! Rewrite the Tunnet `known_hosts` file from peer membership host keys.

use std::path::Path;

use anyhow::Context;

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
    std::fs::write(&path, body).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_hosts_line() {
        let line = known_hosts_line(
            &["db", "db.tunnet", "10.21.0.2"],
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample comment",
        )
        .unwrap();
        assert!(
            line.starts_with("db,db.tunnet,10.21.0.2 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample")
        );
    }
}
