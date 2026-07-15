use anyhow::Context;
use chrono::Utc;
use ed25519_dalek::SigningKey;
use reqwest::{Method, header::HeaderValue};
use tuntun_common::{
    EndpointSnapshot, EnrollRequest, EnrollResponse, HDR_ENDPOINT_ID, HDR_SIGNATURE, HDR_TIMESTAMP,
    PollRequest, RegisterRequest, signing,
};

pub struct UnauthedClient {
    base: String,
    http: reqwest::Client,
}

impl UnauthedClient {
    pub fn new(base: String) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()?;
        Ok(Self { base, http })
    }

    pub async fn enroll(&self, req: EnrollRequest) -> anyhow::Result<EnrollResponse> {
        let url = format!("{}/v1/enroll", self.base);
        let resp = self
            .http
            .post(&url)
            .json(&req)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        let status = resp.status();
        let body = resp.text().await?;
        if !status.is_success() {
            anyhow::bail!("enroll failed: {status}: {body}");
        }
        Ok(serde_json::from_str(&body)?)
    }

    pub async fn enroll_status(
        &self,
        req: tuntun_common::EnrollStatusRequest,
    ) -> anyhow::Result<tuntun_common::EnrollStatusResponse> {
        let url = format!("{}/v1/enroll/status", self.base);
        let resp = self
            .http
            .post(&url)
            .json(&req)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        let status = resp.status();
        let body = resp.text().await?;
        if !status.is_success() {
            anyhow::bail!("enroll status failed: {status}: {body}");
        }
        Ok(serde_json::from_str(&body)?)
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SdkRegisterApiResponse {
    organization_id: String,
    network_id: uuid::Uuid,
    network_name: String,
    #[allow(dead_code)]
    assigned_ip: String,
    #[allow(dead_code)]
    network_cidr: String,
    snapshot: EndpointSnapshot,
}

pub struct ManagementClient {
    base: String,
    http: reqwest::Client,
}

impl ManagementClient {
    pub fn new(base: String) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()?;
        Ok(Self { base, http })
    }

    pub async fn register_sdk_node(
        &self,
        api_key: &str,
        organization_id: &str,
        network_id: uuid::Uuid,
        endpoint_id: &str,
        hostname: &str,
        metadata: Option<serde_json::Value>,
    ) -> anyhow::Result<EnrollResponse> {
        let url = format!(
            "{}/api/v1/organizations/{organization_id}/networks/{network_id}/sdk-nodes",
            self.base.trim_end_matches('/')
        );
        let mut body = serde_json::json!({
            "endpointId": endpoint_id,
            "hostname": hostname,
        });
        if let Some(meta) = metadata
            && let Some(obj) = meta.as_object()
        {
            for (k, v) in obj {
                body[k] = v.clone();
            }
        }
        let resp = self
            .http
            .post(&url)
            .bearer_auth(api_key)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            anyhow::bail!("sdk register failed: {status}: {text}");
        }
        let parsed: SdkRegisterApiResponse = serde_json::from_str(&text)?;
        Ok(EnrollResponse {
            organization_id: parsed.organization_id,
            network_id: parsed.network_id,
            network_name: parsed.network_name,
            status: "active".into(),
            snapshot: parsed.snapshot,
        })
    }
}

pub struct SignedClient {
    pub base: String,
    pub http: reqwest::Client,
    pub endpoint_id: String,
    pub signing_key: SigningKey,
}

impl Clone for SignedClient {
    fn clone(&self) -> Self {
        Self {
            base: self.base.clone(),
            http: self.http.clone(),
            endpoint_id: self.endpoint_id.clone(),
            signing_key: self.signing_key.clone(),
        }
    }
}

impl SignedClient {
    pub fn new(base: String, endpoint_id: String, signing_key: SigningKey) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()?;
        Ok(Self {
            base,
            http,
            endpoint_id,
            signing_key,
        })
    }

    fn sign(&self, method: &str, path: &str, body: &[u8]) -> (i64, String) {
        let ts = Utc::now().timestamp();
        let sig = signing::sign(&self.signing_key, method, path, ts, body);
        (ts, sig)
    }

    async fn do_get<T: serde::de::DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        let url = format!("{}{}", self.base, path);
        let (ts, sig) = self.sign("GET", path, b"");
        let resp = self
            .http
            .request(Method::GET, &url)
            .header(HDR_ENDPOINT_ID, HeaderValue::from_str(&self.endpoint_id)?)
            .header(HDR_TIMESTAMP, HeaderValue::from_str(&ts.to_string())?)
            .header(HDR_SIGNATURE, HeaderValue::from_str(&sig)?)
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            anyhow::bail!("GET {} => {status}: {text}", path);
        }
        Ok(serde_json::from_str(&text)?)
    }

    async fn do_post<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &(impl serde::Serialize + ?Sized),
    ) -> anyhow::Result<T> {
        let url = format!("{}{}", self.base, path);
        let json = serde_json::to_vec(body)?;
        let (ts, sig) = self.sign("POST", path, &json);
        let resp = self
            .http
            .request(Method::POST, &url)
            .header(HDR_ENDPOINT_ID, HeaderValue::from_str(&self.endpoint_id)?)
            .header(HDR_TIMESTAMP, HeaderValue::from_str(&ts.to_string())?)
            .header(HDR_SIGNATURE, HeaderValue::from_str(&sig)?)
            .header("content-type", "application/json")
            .body(json)
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            anyhow::bail!("POST {} => {status}: {text}", path);
        }
        Ok(serde_json::from_str(&text)?)
    }

    async fn do_patch<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &(impl serde::Serialize + ?Sized),
    ) -> anyhow::Result<T> {
        let url = format!("{}{}", self.base, path);
        let json = serde_json::to_vec(body)?;
        let (ts, sig) = self.sign("PATCH", path, &json);
        let resp = self
            .http
            .request(Method::PATCH, &url)
            .header(HDR_ENDPOINT_ID, HeaderValue::from_str(&self.endpoint_id)?)
            .header(HDR_TIMESTAMP, HeaderValue::from_str(&ts.to_string())?)
            .header(HDR_SIGNATURE, HeaderValue::from_str(&sig)?)
            .header("content-type", "application/json")
            .body(json)
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            anyhow::bail!("PATCH {} => {status}: {text}", path);
        }
        Ok(serde_json::from_str(&text)?)
    }

    pub async fn get_device_labels(
        &self,
    ) -> anyhow::Result<std::collections::HashMap<String, String>> {
        self.do_get("/v1/device/labels").await
    }

    pub async fn patch_device_labels(
        &self,
        patch: &std::collections::HashMap<String, Option<String>>,
    ) -> anyhow::Result<std::collections::HashMap<String, String>> {
        self.do_patch("/v1/device/labels", patch).await
    }

    pub async fn patch_device_expiry(&self, expires_in: Option<&str>) -> anyhow::Result<()> {
        let body = serde_json::json!({ "expires_in": expires_in });
        let _: serde_json::Value = self.do_patch("/v1/device/expiry", &body).await?;
        Ok(())
    }

    pub async fn register(
        &self,
        hostname: &str,
        agent_version: &str,
        metadata: Option<serde_json::Value>,
    ) -> anyhow::Result<EndpointSnapshot> {
        let req = RegisterRequest {
            endpoint_id: self.endpoint_id.clone(),
            hostname: hostname.into(),
            agent_version: agent_version.into(),
            metadata,
        };
        self.do_post("/v1/register", &req).await
    }

    pub async fn poll(&self, known_version: u64) -> anyhow::Result<EndpointSnapshot> {
        let req = PollRequest {
            endpoint_id: self.endpoint_id.clone(),
            known_version,
        };
        self.do_post("/v1/poll", &req).await
    }

    pub async fn create_tunnel(
        &self,
        local_port: u16,
        protocol: &str,
        subdomain: Option<&str>,
        relay: Option<&str>,
    ) -> anyhow::Result<CreateTunnelResponse> {
        let body = serde_json::json!({
            "localPort": local_port,
            "protocol": protocol,
            "subdomain": subdomain,
            "relay": relay,
        });
        self.do_post("/v1/tunnels", &body).await
    }

    pub async fn tunnel_ready(&self, tunnel_id: &str) -> anyhow::Result<()> {
        let body = serde_json::json!({ "tunnelId": tunnel_id });
        let _: serde_json::Value = self.do_post("/v1/tunnels/ready", &body).await?;
        Ok(())
    }

    pub async fn tunnel_stopped(&self, tunnel_id: &str) -> anyhow::Result<()> {
        let body = serde_json::json!({ "tunnelId": tunnel_id });
        let _: serde_json::Value = self.do_post("/v1/tunnels/stopped", &body).await?;
        Ok(())
    }

    pub async fn tunnel_failed(&self, tunnel_id: &str, error: &str) -> anyhow::Result<()> {
        let body = serde_json::json!({ "tunnelId": tunnel_id, "error": error });
        let _: serde_json::Value = self.do_post("/v1/tunnels/failed", &body).await?;
        Ok(())
    }

    pub async fn create_subnet_route(
        &self,
        cidr: &str,
        description: Option<&str>,
    ) -> anyhow::Result<String> {
        let body = serde_json::json!({
            "cidr": cidr,
            "description": description,
        });
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Resp {
            cidr: String,
        }
        let resp: Resp = self.do_post("/v1/subnet-routes", &body).await?;
        Ok(resp.cidr)
    }

    pub async fn upload_ssh_recording(
        &self,
        session_id: &str,
        cast_text: &str,
        content_sha256: &str,
    ) -> anyhow::Result<()> {
        if cast_text.len() > 16 * 1024 * 1024 {
            anyhow::bail!("recording too large to upload ({} bytes)", cast_text.len());
        }
        let body = serde_json::json!({
            "sessionId": session_id,
            "castText": cast_text,
            "contentSha256": content_sha256,
        });
        // Large casts need a longer timeout than the default SignedClient.
        let url = format!("{}/v1/ssh-recordings", self.base);
        let json = serde_json::to_vec(&body)?;
        let (ts, sig) = self.sign("POST", "/v1/ssh-recordings", &json);
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()?;
        let resp = http
            .request(Method::POST, &url)
            .header(HDR_ENDPOINT_ID, HeaderValue::from_str(&self.endpoint_id)?)
            .header(HDR_TIMESTAMP, HeaderValue::from_str(&ts.to_string())?)
            .header(HDR_SIGNATURE, HeaderValue::from_str(&sig)?)
            .header("content-type", "application/json")
            .body(json)
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            anyhow::bail!("POST /v1/ssh-recordings => {status}: {text}");
        }
        Ok(())
    }

    pub async fn list_ssh_sessions(
        &self,
        limit: u32,
        status: Option<&str>,
    ) -> anyhow::Result<serde_json::Value> {
        let mut path = format!("/v1/ssh-sessions?limit={limit}");
        if let Some(s) = status {
            path.push_str(&format!("&status={s}"));
        }
        // Sign without query string (server uses uri.path()).
        let url = format!("{}{}", self.base, path);
        let (ts, sig) = self.sign("GET", "/v1/ssh-sessions", b"");
        let resp = self
            .http
            .request(Method::GET, &url)
            .header(HDR_ENDPOINT_ID, HeaderValue::from_str(&self.endpoint_id)?)
            .header(HDR_TIMESTAMP, HeaderValue::from_str(&ts.to_string())?)
            .header(HDR_SIGNATURE, HeaderValue::from_str(&sig)?)
            .send()
            .await?;
        let status_code = resp.status();
        let text = resp.text().await?;
        if !status_code.is_success() {
            anyhow::bail!("GET /v1/ssh-sessions => {status_code}: {text}");
        }
        Ok(serde_json::from_str(&text)?)
    }

    pub async fn list_ssh_recordings(&self, limit: u32) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}/v1/ssh-recordings/list?limit={limit}", self.base);
        let (ts, sig) = self.sign("GET", "/v1/ssh-recordings/list", b"");
        let resp = self
            .http
            .request(Method::GET, &url)
            .header(HDR_ENDPOINT_ID, HeaderValue::from_str(&self.endpoint_id)?)
            .header(HDR_TIMESTAMP, HeaderValue::from_str(&ts.to_string())?)
            .header(HDR_SIGNATURE, HeaderValue::from_str(&sig)?)
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            anyhow::bail!("GET /v1/ssh-recordings/list => {status}: {text}");
        }
        Ok(serde_json::from_str(&text)?)
    }

    pub async fn get_ssh_recording_cast(
        &self,
        session_id: &str,
    ) -> anyhow::Result<serde_json::Value> {
        let path = format!("/v1/ssh-recordings/{session_id}/cast");
        self.do_get(&path).await
    }

    pub async fn evaluate_ssh_auth(
        &self,
        peer_endpoint_id: &str,
        check_period_secs: u64,
    ) -> anyhow::Result<serde_json::Value> {
        let body = serde_json::json!({
            "peerEndpointId": peer_endpoint_id,
            "checkPeriodSecs": check_period_secs,
        });
        self.do_post("/v1/ssh/auth/evaluate", &body).await
    }

    pub async fn poll_ssh_auth(&self, challenge_token: &str) -> anyhow::Result<serde_json::Value> {
        let body = serde_json::json!({ "challengeToken": challenge_token });
        self.do_post("/v1/ssh/auth/poll", &body).await
    }

    pub async fn verify_ssh_auth(
        &self,
        peer_endpoint_id: &str,
        check_period_secs: u64,
        auth_token: Option<&str>,
    ) -> anyhow::Result<serde_json::Value> {
        let body = serde_json::json!({
            "peerEndpointId": peer_endpoint_id,
            "checkPeriodSecs": check_period_secs,
            "authToken": auth_token,
        });
        self.do_post("/v1/ssh/auth/verify", &body).await
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTunnelResponse {
    pub tunnel_id: String,
    pub subdomain: String,
    pub public_hostname: String,
    pub protocol: String,
    pub local_port: u16,
    pub relay_endpoint_id: String,
    pub relay_domain: String,
    pub auth_token: String,
    #[serde(default)]
    pub redirect_rules: Vec<tuntun_common::RedirectRule>,
}

pub fn basic_metadata(hostname: &str, agent_version: &str, kind: &str) -> serde_json::Value {
    serde_json::json!({
        "hostname": hostname,
        "agentVersion": agent_version,
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "family": std::env::consts::FAMILY,
        "kind": kind, // "agent" | "sdk"
        "reportedAt": chrono::Utc::now().to_rfc3339(),
    })
}
