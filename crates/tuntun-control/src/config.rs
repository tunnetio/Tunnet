use clap::Parser;
use secrecy::SecretString;

#[derive(Parser, Debug, Clone)]
#[command(name = "tuntun-control", about = "TunTun control plane")]
pub struct Args {
    #[arg(long, env = "TUNTUN_BIND", default_value = "0.0.0.0:8080")]
    pub bind: String,

    /// Internal bind for /metrics and /ready (do NOT expose publicly).
    #[arg(long, env = "TUNTUN_INTERNAL_BIND", default_value = "127.0.0.1:9090")]
    pub internal_bind: String,

    /// Admin bind for HMAC-protected /internal/v1 (management service only).
    #[arg(long, env = "TUNTUN_ADMIN_BIND", default_value = "127.0.0.1:9091")]
    pub admin_bind: String,

    /// Shared HMAC secret for management → control-plane internal API.
    #[arg(long, env = "TUNTUN_SERVICE_SECRET")]
    pub service_secret: Option<SecretString>,

    /// AES-256 key for decrypting internal-CA leaf private keys (same as management).
    /// 64-char hex or 32-byte base64. Falls back to insecure local-dev key when unset.
    #[arg(long, env = "TUNTUN_CA_ENCRYPTION_KEY")]
    pub ca_encryption_key: Option<String>,

    /// Base64-encoded 32-byte Ed25519 policy signing key (shared across replicas).
    #[arg(long, env = "TUNTUN_POLICY_KEY")]
    pub policy_key_env: Option<String>,

    /// Postgres URL, e.g. postgres://user:pass@host/db
    #[arg(long, env = "DATABASE_URL")]
    pub database_url: SecretString,

    /// Path to policy signing key file when TUNTUN_POLICY_KEY env is unset (dev only).
    #[arg(long, env = "TUNTUN_POLICY_KEY_PATH", default_value = "./policy.key")]
    pub policy_key_path: String,

    /// Enable JSON structured logging (recommended in production).
    #[arg(long, env = "TUNTUN_JSON_LOGS")]
    pub json_logs: bool,

    /// OTLP collector endpoint. When set, tracing is exported.
    #[arg(long, env = "TUNTUN_OTLP_ENDPOINT")]
    pub otlp_endpoint: Option<String>,

    /// TTL (seconds) beyond which a device without heartbeats is evicted from its IP.
    #[arg(long, env = "TUNTUN_STALE_TTL_SECS", default_value_t = 90)]
    pub stale_ttl_secs: u64,

    /// Rate limit for /v1/enroll (requests / minute / source).
    #[arg(long, env = "TUNTUN_RL_ENROLL", default_value_t = 10)]
    pub rl_enroll_per_min: u32,

    /// Rate limit for other authenticated endpoints (requests / minute / source).
    #[arg(long, env = "TUNTUN_RL_DEFAULT", default_value_t = 60)]
    pub rl_default_per_min: u32,
}
