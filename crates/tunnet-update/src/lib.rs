use std::path::Path;

use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const CHANNEL_URL: &str = "https://get.tunnet.io/core/latest.json";
const MANIFEST_SCHEMA_VERSION: u32 = 1;
const REPOSITORY_OWNER: &str = "tunnetio";
const REPOSITORY_NAME: &str = "Tunnet";
const RELEASE_WORKFLOW: &str = ".github/workflows/release-binaries.yml";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoreArtifact {
    pub platform: String,
    pub arch: String,
    #[serde(default)]
    pub environment: Option<String>,
    pub url: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoreManifest {
    pub schema_version: u32,
    pub version: String,
    pub api_version: u32,
    pub artifacts: Vec<CoreArtifact>,
}

pub async fn fetch_manifest(user_agent: &str) -> anyhow::Result<(Vec<u8>, CoreManifest)> {
    let raw = client(user_agent)?
        .get(CHANNEL_URL)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?
        .to_vec();
    let manifest = parse_manifest(&raw)?;
    Ok((raw, manifest))
}

pub fn parse_manifest(raw: &[u8]) -> anyhow::Result<CoreManifest> {
    let manifest: CoreManifest = serde_json::from_slice(raw)?;
    ensure!(
        manifest.schema_version == MANIFEST_SCHEMA_VERSION,
        "unsupported Core manifest schema"
    );
    ensure!(
        manifest.api_version > 0,
        "invalid target Core Local API version"
    );
    semver::Version::parse(manifest.version.trim_start_matches('v'))?;
    ensure!(
        !manifest.artifacts.is_empty(),
        "Core manifest has no artifacts"
    );
    for artifact in &manifest.artifacts {
        validate_artifact_url(&manifest, artifact)?;
        ensure!(
            artifact.sha256.len() == 64
                && artifact.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "invalid Core artifact SHA-256"
        );
    }
    Ok(manifest)
}

pub fn current_artifact(manifest: &CoreManifest) -> anyhow::Result<&CoreArtifact> {
    let environment = if cfg!(target_env = "musl") {
        "musl"
    } else if cfg!(windows) {
        "msvc"
    } else if cfg!(target_os = "linux") {
        "gnu"
    } else {
        ""
    };
    manifest
        .artifacts
        .iter()
        .find(|artifact| {
            artifact.platform == std::env::consts::OS
                && artifact.arch == std::env::consts::ARCH
                && artifact.environment.as_deref().unwrap_or("") == environment
        })
        .context("Core channel has no artifact for this platform and architecture")
}

pub async fn verify_artifact(
    archive: &Path,
    manifest: &CoreManifest,
    artifact: &CoreArtifact,
    user_agent: &str,
) -> anyhow::Result<()> {
    validate_artifact_url(manifest, artifact)?;
    let actual = hex::encode(Sha256::digest(std::fs::read(archive)?));
    ensure!(
        actual.eq_ignore_ascii_case(&artifact.sha256),
        "Core archive SHA-256 mismatch"
    );

    let workflow = workflow_identity(manifest);
    let digest = sigstore_verify::types::Sha256Hash::from_hex(&actual)
        .context("parse Core artifact digest")?;
    let root = sigstore_verify::trust_root::TrustedRoot::production()
        .await
        .context("load Sigstore production trust root")?;
    let policy = sigstore_verify::VerificationPolicy::new(
        workflow.as_str(),
        "https://token.actions.githubusercontent.com",
    );
    let bundles = fetch_attestation_bundles(&actual, user_agent).await?;
    let mut errors = Vec::new();
    for bundle_json in bundles {
        let bundle = match sigstore_verify::types::Bundle::from_json(&bundle_json) {
            Ok(bundle) => bundle,
            Err(error) => {
                errors.push(format!("parse bundle: {error}"));
                continue;
            }
        };
        match sigstore_verify::verify(digest, &bundle, &policy, &root) {
            Ok(_) => return Ok(()),
            Err(error) => errors.push(error.to_string()),
        }
    }
    anyhow::bail!(
        "no valid GitHub Artifact Attestation for {workflow}: {}",
        errors.join("; ")
    )
}

fn workflow_identity(manifest: &CoreManifest) -> String {
    format!(
        "https://github.com/{REPOSITORY_OWNER}/{REPOSITORY_NAME}/{RELEASE_WORKFLOW}@refs/tags/v{}",
        manifest.version.trim_start_matches('v')
    )
}

fn validate_artifact_url(manifest: &CoreManifest, artifact: &CoreArtifact) -> anyhow::Result<()> {
    let version = manifest.version.trim_start_matches('v');
    let target = artifact_target(artifact)?;
    let extension = if artifact.platform == "windows" {
        "zip"
    } else {
        "tar.gz"
    };
    let expected = format!(
        "https://github.com/{REPOSITORY_OWNER}/{REPOSITORY_NAME}/releases/download/v{version}/tunnet-headless-{version}-{target}.{extension}"
    );
    ensure!(
        artifact.url == expected,
        "Core artifact URL does not match the pinned immutable release asset"
    );
    Ok(())
}

fn artifact_target(artifact: &CoreArtifact) -> anyhow::Result<String> {
    let environment = artifact.environment.as_deref().unwrap_or("");
    match (
        artifact.platform.as_str(),
        artifact.arch.as_str(),
        environment,
    ) {
        ("windows", "x86_64" | "aarch64", "msvc") => {
            Ok(format!("{}-pc-windows-msvc", artifact.arch))
        }
        ("linux", "x86_64" | "aarch64", "gnu" | "musl") => {
            Ok(format!("{}-unknown-linux-{environment}", artifact.arch))
        }
        ("macos", "aarch64", "") => Ok("aarch64-apple-darwin".into()),
        _ => anyhow::bail!("unsupported Core artifact platform, architecture, or environment"),
    }
}

#[derive(Deserialize)]
struct GitHubAttestationsResponse {
    attestations: Vec<GitHubAttestation>,
}

#[derive(Deserialize)]
struct GitHubAttestation {
    #[serde(default)]
    bundle: Option<serde_json::Value>,
    #[serde(default)]
    bundle_url: Option<String>,
}

async fn fetch_attestation_bundles(sha256: &str, user_agent: &str) -> anyhow::Result<Vec<String>> {
    let endpoint = format!(
        "https://api.github.com/repos/{REPOSITORY_OWNER}/{REPOSITORY_NAME}/attestations/sha256:{sha256}?predicate_type=provenance&per_page=100"
    );
    let http = client(user_agent)?;
    let response: GitHubAttestationsResponse = http
        .get(endpoint)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    ensure!(
        !response.attestations.is_empty(),
        "GitHub returned no Artifact Attestations for the Core artifact digest"
    );
    let mut bundles = Vec::with_capacity(response.attestations.len());
    for attestation in response.attestations {
        if let Some(bundle) = attestation.bundle {
            bundles.push(serde_json::to_string(&bundle)?);
        } else if let Some(url) = attestation.bundle_url {
            ensure!(
                url.starts_with("https://"),
                "GitHub attestation bundle URL is not HTTPS"
            );
            bundles.push(
                http.get(url)
                    .send()
                    .await?
                    .error_for_status()?
                    .text()
                    .await?,
            );
        }
    }
    ensure!(
        !bundles.is_empty(),
        "GitHub Artifact Attestation response contained no Sigstore bundles"
    );
    Ok(bundles)
}

fn client(user_agent: &str) -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder().user_agent(user_agent).build()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_accepts_newer_target_api_and_enforces_immutable_repository_urls() {
        let mut manifest = CoreManifest {
            schema_version: 1,
            version: "1.2.3".into(),
            api_version: tunnet_common::local_api::API_VERSION + 1,
            artifacts: vec![CoreArtifact {
                platform: "windows".into(),
                arch: "x86_64".into(),
                environment: Some("msvc".into()),
                url: "https://github.com/tunnetio/Tunnet/releases/download/v1.2.3/tunnet-headless-1.2.3-x86_64-pc-windows-msvc.zip".into(),
                sha256: "a".repeat(64),
            }],
        };
        assert_eq!(
            parse_manifest(&serde_json::to_vec(&manifest).unwrap()).unwrap(),
            manifest
        );
        assert_eq!(
            workflow_identity(&manifest),
            "https://github.com/tunnetio/Tunnet/.github/workflows/release-binaries.yml@refs/tags/v1.2.3"
        );
        manifest.api_version = 0;
        assert!(parse_manifest(&serde_json::to_vec(&manifest).unwrap()).is_err());
        manifest.api_version = tunnet_common::local_api::API_VERSION + 1;
        manifest.artifacts[0].url = "https://example.com/core.zip".into();
        assert!(parse_manifest(&serde_json::to_vec(&manifest).unwrap()).is_err());
    }
}
