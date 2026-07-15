use std::collections::HashMap;

use anyhow::Context;
use clap::{Args, Subcommand};
use tuntun_core::{
    AgentIdentity, ManagedState, PersistedState, SealPolicy, StatePaths, load_agent,
};

#[derive(Subcommand, Debug)]
pub enum LabelsCommand {
    /// Set or update labels (key=value pairs)
    Set(LabelsSetArgs),
    /// Show current labels
    Get,
    /// Delete a label by key
    Delete(LabelsDeleteArgs),
}

#[derive(Args, Debug)]
pub struct LabelsSetArgs {
    /// Label pairs as key=value (e.g. user_id=customer-42)
    pub pairs: Vec<String>,
}

#[derive(Args, Debug)]
pub struct LabelsDeleteArgs {
    pub key: String,
}

#[derive(Subcommand, Debug)]
pub enum MachineCommand {
    /// Set inactivity expiry (e.g. 7d, 12h, never)
    SetExpiry(MachineSetExpiryArgs),
}

#[derive(Args, Debug)]
pub struct MachineSetExpiryArgs {
    /// Duration until auto-delete after last contact, or `never`
    pub duration: String,
}

pub async fn run_labels(command: LabelsCommand, state_dir: Option<&str>) -> anyhow::Result<()> {
    let client = signed_client(state_dir).await?;
    match command {
        LabelsCommand::Set(args) => {
            let patch = parse_label_pairs(&args.pairs)?;
            let labels = client.patch_device_labels(&patch).await?;
            print_labels(&labels);
        }
        LabelsCommand::Get => {
            let labels = client.get_device_labels().await?;
            print_labels(&labels);
        }
        LabelsCommand::Delete(args) => {
            let mut patch = HashMap::new();
            patch.insert(args.key, None);
            let labels = client.patch_device_labels(&patch).await?;
            print_labels(&labels);
        }
    }
    Ok(())
}

pub async fn run_machine(command: MachineCommand, state_dir: Option<&str>) -> anyhow::Result<()> {
    let client = signed_client(state_dir).await?;
    match command {
        MachineCommand::SetExpiry(args) => {
            let duration = args.duration.trim();
            let value = if duration.eq_ignore_ascii_case("never") {
                None
            } else {
                Some(duration)
            };
            client.patch_device_expiry(value).await?;
            match value {
                Some(d) => println!("Expiry set to {d}"),
                None => println!("Auto-expiry disabled"),
            }
        }
    }
    Ok(())
}

pub fn parse_label_csv(raw: &str) -> anyhow::Result<HashMap<String, String>> {
    let mut labels = HashMap::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (key, value) = part
            .split_once('=')
            .with_context(|| format!("invalid label pair: {part}"))?;
        if key.trim().is_empty() {
            anyhow::bail!("label key cannot be empty");
        }
        labels.insert(key.trim().to_string(), value.trim().to_string());
    }
    Ok(labels)
}

pub fn parse_labels_json(raw: &str) -> anyhow::Result<HashMap<String, String>> {
    let value: serde_json::Value = serde_json::from_str(raw).context("invalid labels JSON")?;
    let obj = value.as_object().context("labels JSON must be an object")?;
    let mut labels = HashMap::new();
    for (k, v) in obj {
        let s = v
            .as_str()
            .with_context(|| format!("label {k} must be a string"))?;
        labels.insert(k.clone(), s.to_string());
    }
    Ok(labels)
}

fn parse_label_pairs(pairs: &[String]) -> anyhow::Result<HashMap<String, Option<String>>> {
    let mut patch = HashMap::new();
    for pair in pairs {
        let (key, value) = pair
            .split_once('=')
            .with_context(|| format!("invalid label pair: {pair}"))?;
        if key.trim().is_empty() {
            anyhow::bail!("label key cannot be empty");
        }
        patch.insert(key.trim().to_string(), Some(value.trim().to_string()));
    }
    if patch.is_empty() {
        anyhow::bail!("provide at least one key=value pair");
    }
    Ok(patch)
}

fn print_labels(labels: &HashMap<String, String>) {
    if labels.is_empty() {
        println!("(no labels)");
        return;
    }
    let mut keys: Vec<_> = labels.keys().collect();
    keys.sort();
    for key in keys {
        println!("{key}={}", labels[key]);
    }
}

async fn signed_client(state_dir: Option<&str>) -> anyhow::Result<tuntun_core::SignedClient> {
    let paths = StatePaths::resolve(state_dir);
    let policy = SealPolicy::from_env_and_flag(false);
    let (identity, persisted, _) = load_agent(&paths, policy)?;
    let managed = match persisted {
        PersistedState::Managed(m) => m,
        _ => anyhow::bail!("not enrolled in Managed mode"),
    };
    build_signed_client(&identity, &managed)
}

fn build_signed_client(
    identity: &AgentIdentity,
    managed: &ManagedState,
) -> anyhow::Result<tuntun_core::SignedClient> {
    tuntun_core::SignedClient::new(
        managed.control_url.clone(),
        identity.endpoint_id_hex(),
        identity.signing_key.clone(),
    )
}
