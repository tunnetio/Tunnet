//! `tuntun login` / `tuntun logout` - OAuth device authorization (RFC 8628).

use anyhow::{Context, bail};
use clap::Args;
use tuntun_core::{CliAuthTokens, StatePaths};

#[derive(Args, Debug)]
pub struct LoginArgs {
    /// Management API base URL (e.g. http://localhost:3000)
    #[arg(long, env = "MANAGEMENT_URL")]
    pub management_url: Option<String>,
    #[arg(long, env = "TUNTUN_STATE_DIR")]
    pub state_dir: Option<String>,
}

#[derive(Args, Debug)]
pub struct LogoutArgs {
    #[arg(long, env = "TUNTUN_STATE_DIR")]
    pub state_dir: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CliAuthConfig {
    client_id: String,
    device_code_endpoint: String,
    device_token_endpoint: String,
    verification_uri: String,
    scopes: Vec<String>,
}

#[derive(serde::Deserialize)]
struct DeviceCodeResponse {
    device_code: String,
    user_code: String,
    verification_uri: Option<String>,
    verification_uri_complete: Option<String>,
    expires_in: Option<u64>,
    interval: Option<u64>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(serde::Deserialize)]
struct DeviceTokenResponse {
    access_token: Option<String>,
    refresh_token: Option<String>,
    token_type: Option<String>,
    scope: Option<String>,
    expires_in: Option<u64>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(serde::Deserialize)]
struct UserInfo {
    email: Option<String>,
    name: Option<String>,
}

pub async fn run_login(args: LoginArgs) -> anyhow::Result<()> {
    let paths = StatePaths::resolve(args.state_dir.as_deref());
    paths.ensure()?;

    let management_url = args
        .management_url
        .or_else(|| std::env::var("MANAGEMENT_URL").ok())
        .unwrap_or_else(|| "http://localhost:3000".into())
        .trim_end_matches('/')
        .to_string();

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("tuntun-cli")
        .build()?;

    let config: CliAuthConfig = http
        .get(format!("{management_url}/auth/cli/config"))
        .send()
        .await
        .context("fetch /auth/cli/config")?
        .error_for_status()
        .context("management /auth/cli/config")?
        .json()
        .await
        .context("parse /auth/cli/config")?;

    let scope = config.scopes.join(" ");
    let code_body = urlencoding_form(&[
        ("client_id", config.client_id.as_str()),
        ("scope", scope.as_str()),
    ]);
    let code_res = http
        .post(&config.device_code_endpoint)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(code_body)
        .send()
        .await
        .context("device code request")?;
    let code_status = code_res.status();
    let codes: DeviceCodeResponse = code_res.json().await.context("parse device code")?;
    if !code_status.is_success() || codes.error.is_some() {
        bail!(
            "device code failed: {}",
            codes
                .error_description
                .or(codes.error)
                .unwrap_or_else(|| code_status.to_string())
        );
    }

    let verification = codes
        .verification_uri_complete
        .or(codes.verification_uri)
        .unwrap_or_else(|| format!("{}?user_code={}", config.verification_uri, codes.user_code));

    println!("TunTun device login");
    println!();
    println!("  Visit:  {}", config.verification_uri);
    println!("  Code:   {}", display_user_code(&codes.user_code));
    println!();
    println!("Opening browser…");
    if let Err(e) = open_browser(&verification) {
        eprintln!("warning: could not open browser ({e})");
        eprintln!("Open this URL manually:\n  {verification}");
    }

    let interval = codes.interval.unwrap_or(5).max(1);
    let deadline = std::time::Instant::now()
        + std::time::Duration::from_secs(codes.expires_in.unwrap_or(1800));

    println!("Waiting for approval…");
    let tokens = poll_for_token(
        &http,
        &config.device_token_endpoint,
        &config.client_id,
        &codes.device_code,
        interval,
        deadline,
    )
    .await?;

    let access_token = tokens
        .access_token
        .context("token response missing access_token")?;

    let now = chrono::Utc::now();
    let expires_at = tokens
        .expires_in
        .map(|secs| now + chrono::Duration::seconds(secs as i64));

    let stored = CliAuthTokens {
        management_url: management_url.clone(),
        access_token: access_token.clone(),
        refresh_token: tokens.refresh_token,
        token_type: tokens.token_type.unwrap_or_else(|| "Bearer".into()),
        scope: tokens.scope,
        expires_at,
        obtained_at: now,
    };
    stored.save(&paths)?;

    if let Ok(Some(info)) = fetch_session_user(&http, &management_url, &access_token).await {
        println!(
            "✓ Logged in as {} ({})",
            info.name
                .or(info.email.clone())
                .unwrap_or_else(|| "user".into()),
            info.email.unwrap_or_default()
        );
    } else {
        println!("✓ Logged in");
    }
    println!("  tokens sealed in {}", paths.secrets_file().display());
    Ok(())
}

pub async fn run_logout(args: LogoutArgs) -> anyhow::Result<()> {
    let paths = StatePaths::resolve(args.state_dir.as_deref());
    CliAuthTokens::clear(&paths)?;
    println!("✓ Logged out");
    Ok(())
}

#[allow(dead_code)]
pub fn load_tokens(state_dir: Option<&str>) -> anyhow::Result<Option<CliAuthTokens>> {
    let paths = StatePaths::resolve(state_dir);
    tuntun_core::secret_store::load_auth(&paths)
}

async fn poll_for_token(
    http: &reqwest::Client,
    token_endpoint: &str,
    client_id: &str,
    device_code: &str,
    mut interval_secs: u64,
    deadline: std::time::Instant,
) -> anyhow::Result<DeviceTokenResponse> {
    loop {
        if std::time::Instant::now() >= deadline {
            bail!("device code expired - run `tuntun login` again");
        }
        tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;

        let body = urlencoding_form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", device_code),
            ("client_id", client_id),
        ]);
        let res = http
            .post(token_endpoint)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .context("device token poll")?;
        let tokens: DeviceTokenResponse = res.json().await.context("parse device token")?;

        if tokens.access_token.is_some() {
            return Ok(tokens);
        }

        match tokens.error.as_deref() {
            Some("authorization_pending") | None => {}
            Some("slow_down") => {
                interval_secs += 5;
                println!("  slowing poll to {interval_secs}s…");
            }
            Some("access_denied") => bail!("authorization denied in browser"),
            Some("expired_token") => bail!("device code expired - run `tuntun login` again"),
            Some(other) => bail!(
                "device token error: {} ({})",
                tokens.error_description.unwrap_or_default(),
                other
            ),
        }
    }
}

async fn fetch_session_user(
    http: &reqwest::Client,
    management_url: &str,
    access_token: &str,
) -> anyhow::Result<Option<UserInfo>> {
    let res = http
        .get(format!("{management_url}/api/auth/get-session"))
        .bearer_auth(access_token)
        .send()
        .await?;
    if !res.status().is_success() {
        return Ok(None);
    }
    #[derive(serde::Deserialize)]
    struct SessionEnvelope {
        user: Option<UserInfo>,
    }
    let env: SessionEnvelope = res.json().await?;
    Ok(env.user)
}

fn display_user_code(code: &str) -> String {
    let compact: String = code.chars().filter(|c| *c != '-').collect();
    if compact.len() == 8 {
        format!("{}-{}", &compact[..4], &compact[4..])
    } else {
        code.to_string()
    }
}

fn urlencoding_form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", form_encode(k), form_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn form_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                out.push(char::from(b"0123456789ABCDEF"[(b >> 4) as usize]));
                out.push(char::from(b"0123456789ABCDEF"[(b & 0xf) as usize]));
            }
        }
    }
    out
}

fn open_browser(url: &str) -> anyhow::Result<()> {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .spawn()
            .context("failed to open browser")?;
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(url)
            .spawn()
            .context("failed to open browser")?;
        Ok(())
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::process::Command::new("xdg-open")
            .arg(url)
            .spawn()
            .context("failed to open browser")?;
        Ok(())
    }
    #[cfg(not(any(target_os = "windows", unix)))]
    {
        let _ = url;
        bail!("cannot open browser on this platform");
    }
}
