use anyhow::Context;
use ed25519_dalek::SigningKey;
use jiff::Timestamp;
use reqwest::{Method, Url, header::HeaderValue, redirect::Policy};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use tunnet_common::{
    EndpointSnapshot, EnrollRequest, EnrollResponse, HDR_ENDPOINT_ID, HDR_SIGNATURE, HDR_TIMESTAMP,
    PollRequest, RegisterRequest, signing,
};

const ALLOW_PRIVATE_CONTROL_ENDPOINTS: &str = "TUNNET_ALLOW_PRIVATE_CONTROL_ENDPOINTS";

/// An outbound control-plane or management endpoint that cannot be redirected
/// or resolved to a local network address unless the service operator opted in.
#[derive(Clone)]
struct ServiceEndpoint {
    base: Url,
    host: String,
    resolved_addrs: Vec<SocketAddr>,
}

impl ServiceEndpoint {
    fn parse(raw: &str) -> anyhow::Result<Self> {
        Self::parse_with_private_endpoints_allowed(raw, private_endpoints_allowed())
    }

    fn parse_with_private_endpoints_allowed(
        raw: &str,
        private_endpoints_allowed: bool,
    ) -> anyhow::Result<Self> {
        let mut base = Url::parse(raw).context("invalid service endpoint URL")?;
        if !matches!(base.scheme(), "http" | "https") {
            anyhow::bail!("service endpoint must use http or https");
        }
        if !base.username().is_empty() || base.password().is_some() {
            anyhow::bail!("service endpoint must not contain credentials");
        }
        if base.query().is_some() || base.fragment().is_some() {
            anyhow::bail!("service endpoint must not contain a query or fragment");
        }

        let host = base
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("service endpoint must include a host"))?
            .to_ascii_lowercase();
        let port = base
            .port_or_known_default()
            .ok_or_else(|| anyhow::anyhow!("service endpoint has no known port"))?;
        let resolved_addrs = (host.as_str(), port)
            .to_socket_addrs()
            .with_context(|| format!("resolve service endpoint {host}"))?
            .collect::<Vec<_>>();
        if resolved_addrs.is_empty() {
            anyhow::bail!("service endpoint {host} did not resolve to an address");
        }

        if !private_endpoints_allowed
            && resolved_addrs
                .iter()
                .any(|addr| is_private_or_local(addr.ip()))
        {
            anyhow::bail!(
                "service endpoint {host} resolves to a private or local address; set {ALLOW_PRIVATE_CONTROL_ENDPOINTS}=1 only for an explicitly trusted self-hosted deployment"
            );
        }

        if !base.path().ends_with('/') {
            let path = format!("{}/", base.path());
            base.set_path(&path);
        }

        Ok(Self {
            base,
            host,
            resolved_addrs,
        })
    }

    fn url(&self, path: &str) -> anyhow::Result<Url> {
        self.base
            .join(path)
            .with_context(|| format!("build endpoint URL for {path}"))
    }
}

fn private_endpoints_allowed() -> bool {
    std::env::var(ALLOW_PRIVATE_CONTROL_ENDPOINTS)
        .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

fn is_private_or_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.octets()[0] == 0
                || (ip.octets()[0] == 100 && (64..128).contains(&ip.octets()[1]))
                || (ip.octets()[0] == 198 && (18..20).contains(&ip.octets()[1]))
                || (ip.octets()[0] == 192 && ip.octets()[1] == 0 && ip.octets()[2] == 0)
                || (ip.octets()[0] == 192 && ip.octets()[1] == 0 && ip.octets()[2] == 2)
                || (ip.octets()[0] == 198 && ip.octets()[1] == 51 && ip.octets()[2] == 100)
                || (ip.octets()[0] == 203 && ip.octets()[1] == 0 && ip.octets()[2] == 113)
                || ip.octets()[0] >= 240
        }
        IpAddr::V6(ip) => {
            ip.to_ipv4_mapped()
                .is_some_and(|ipv4| is_private_or_local(IpAddr::V4(ipv4)))
                || ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || (ip.segments()[0] & 0xfe00 == 0xfc00)
                || (ip.segments()[0] & 0xffc0 == 0xfe80)
                || (ip.segments()[0] == 0x2001 && ip.segments()[1] == 0x0db8)
        }
    }
}

fn service_http_client(
    endpoint: &ServiceEndpoint,
    timeout: std::time::Duration,
) -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(timeout)
        .redirect(Policy::none())
        .resolve_to_addrs(&endpoint.host, &endpoint.resolved_addrs)
        .build()?)
}

pub struct UnauthedClient {
    endpoint: ServiceEndpoint,
    http: reqwest::Client,
}

#[cfg(test)]
mod endpoint_tests {
    use super::*;

    #[test]
    fn unauthed_client_rejects_a_loopback_control_plane() {
        assert!(UnauthedClient::new("http://127.0.0.1:8080".into()).is_err());
    }

    #[test]
    fn management_client_rejects_a_link_local_address() {
        assert!(ManagementClient::new("http://169.254.169.254".into()).is_err());
    }

    #[test]
    fn clients_accept_a_public_https_endpoint() {
        assert!(UnauthedClient::new("https://1.1.1.1".into()).is_ok());
        assert!(ManagementClient::new("https://1.1.1.1/api".into()).is_ok());
    }

    #[test]
    fn endpoint_rejects_credentials_and_redirectable_url_parts() {
        assert!(UnauthedClient::new("https://token@example.com".into()).is_err());
        assert!(UnauthedClient::new("https://example.com?next=/internal".into()).is_err());
    }

    #[test]
    fn private_endpoint_opt_in_is_explicit() {
        assert!(
            ServiceEndpoint::parse_with_private_endpoints_allowed("http://127.0.0.1:8080", true,)
                .is_ok()
        );
    }

    #[test]
    fn private_address_detection_covers_ssrf_targets() {
        for address in [
            "10.0.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "192.0.2.1",
            "10.21.0.1",
            "[::1]",
            "[fc00::1]",
            "[fe80::1]",
            "[::ffff:127.0.0.1]",
        ] {
            let address = address
                .trim_matches(['[', ']'])
                .parse()
                .expect("test address is valid");
            assert!(is_private_or_local(address), "{address}");
        }
    }
}

impl UnauthedClient {
    pub fn new(base: String) -> anyhow::Result<Self> {
        let endpoint = ServiceEndpoint::parse(&base)?;
        let http = service_http_client(&endpoint, std::time::Duration::from_secs(15))?;
        Ok(Self { endpoint, http })
    }

    pub async fn enroll(&self, req: EnrollRequest) -> anyhow::Result<EnrollResponse> {
        let url = self.endpoint.url("v1/enroll")?;
        let resp = self
            .http
            .post(url.clone())
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
        req: tunnet_common::EnrollStatusRequest,
    ) -> anyhow::Result<tunnet_common::EnrollStatusResponse> {
        let url = self.endpoint.url("v1/enroll/status")?;
        let resp = self
            .http
            .post(url.clone())
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
    endpoint: ServiceEndpoint,
    http: reqwest::Client,
}

impl ManagementClient {
    pub fn new(base: String) -> anyhow::Result<Self> {
        let endpoint = ServiceEndpoint::parse(&base)?;
        let http = service_http_client(&endpoint, std::time::Duration::from_secs(15))?;
        Ok(Self { endpoint, http })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn register_sdk_node(
        &self,
        api_key: &str,
        organization_id: &str,
        network_id: uuid::Uuid,
        endpoint_id: &str,
        hostname: &str,
        metadata: Option<serde_json::Value>,
        kind: Option<&str>,
        labels: Option<&std::collections::HashMap<String, String>>,
        expires_in: Option<&str>,
        tags: Option<&[String]>,
    ) -> anyhow::Result<EnrollResponse> {
        let url = self.endpoint.url(&format!(
            "api/v1/organizations/{organization_id}/networks/{network_id}/sdk-nodes"
        ))?;
        let mut body = serde_json::json!({
            "endpointId": endpoint_id,
            "hostname": hostname,
        });
        if let Some(meta) = metadata
            && let Some(obj) = meta.as_object()
        {
            // Nested under metadata key for free-form fields (not top-level merge).
            body["metadata"] = serde_json::Value::Object(obj.clone());
        }
        if let Some(k) = kind {
            body["kind"] = serde_json::Value::String(k.to_string());
        }
        if let Some(labels) = labels {
            body["labels"] = serde_json::to_value(labels)?;
        }
        if let Some(exp) = expires_in {
            body["expiresIn"] = serde_json::Value::String(exp.to_string());
        }
        if let Some(tags) = tags {
            body["tags"] = serde_json::to_value(tags)?;
        }
        let resp = self
            .http
            .post(url.clone())
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
            management_url: None,
            dashboard_url: None,
        })
    }

    pub async fn delete_devices(
        &self,
        api_key: &str,
        organization_id: &str,
        items: &[(uuid::Uuid, &str)],
    ) -> anyhow::Result<u32> {
        let url = self
            .endpoint
            .url(&format!("api/v1/organizations/{organization_id}/sdk-nodes"))?;
        let body = serde_json::json!({
            "items": items.iter().map(|(network_id, endpoint_id)| {
                serde_json::json!({
                    "networkId": network_id,
                    "endpointId": endpoint_id,
                })
            }).collect::<Vec<_>>(),
        });
        let resp = self
            .http
            .delete(url.clone())
            .bearer_auth(api_key)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("DELETE {url}"))?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            anyhow::bail!("device delete failed: {status}: {text}");
        }
        let parsed: serde_json::Value = serde_json::from_str(&text)?;
        Ok(parsed.get("deleted").and_then(|v| v.as_u64()).unwrap_or(0) as u32)
    }
}

pub struct SignedClient {
    endpoint: ServiceEndpoint,
    http: reqwest::Client,
    pub endpoint_id: String,
    pub signing_key: SigningKey,
}

impl Clone for SignedClient {
    fn clone(&self) -> Self {
        Self {
            endpoint: self.endpoint.clone(),
            http: self.http.clone(),
            endpoint_id: self.endpoint_id.clone(),
            signing_key: self.signing_key.clone(),
        }
    }
}

impl SignedClient {
    pub fn new(base: String, endpoint_id: String, signing_key: SigningKey) -> anyhow::Result<Self> {
        let endpoint = ServiceEndpoint::parse(&base)?;
        let http = service_http_client(&endpoint, std::time::Duration::from_secs(15))?;
        Ok(Self {
            endpoint,
            http,
            endpoint_id,
            signing_key,
        })
    }

    fn sign(&self, method: &str, path: &str, body: &[u8]) -> (i64, String) {
        let ts = Timestamp::now().as_second();
        let sig = signing::sign(&self.signing_key, method, path, ts, body);
        (ts, sig)
    }

    async fn do_get<T: serde::de::DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        let url = self.endpoint.url(path.trim_start_matches('/'))?;
        let (ts, sig) = self.sign("GET", path, b"");
        let resp = self
            .http
            .request(Method::GET, url.clone())
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
        let url = self.endpoint.url(path.trim_start_matches('/'))?;
        let json = serde_json::to_vec(body)?;
        let (ts, sig) = self.sign("POST", path, &json);
        let resp = self
            .http
            .request(Method::POST, url.clone())
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
        let url = self.endpoint.url(path.trim_start_matches('/'))?;
        let json = serde_json::to_vec(body)?;
        let (ts, sig) = self.sign("PATCH", path, &json);
        let resp = self
            .http
            .request(Method::PATCH, url.clone())
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

    pub async fn get_device_tags(&self) -> anyhow::Result<Vec<String>> {
        let v: serde_json::Value = self.do_get("/v1/device/tags").await?;
        Ok(v.get("tags")
            .and_then(|t| t.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default())
    }

    pub async fn patch_device_tags(
        &self,
        add: &[String],
        remove: &[String],
    ) -> anyhow::Result<Vec<String>> {
        let body = serde_json::json!({ "add": add, "remove": remove });
        let v: serde_json::Value = self.do_patch("/v1/device/tags", &body).await?;
        Ok(v.get("tags")
            .and_then(|t| t.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default())
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
        edge: Option<&str>,
    ) -> anyhow::Result<CreateTunnelResponse> {
        let body = serde_json::json!({
            "localPort": local_port,
            "protocol": protocol,
            "subdomain": subdomain,
            "edge": edge,
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
        let url = self.endpoint.url("v1/ssh-recordings")?;
        let json = serde_json::to_vec(&body)?;
        let (ts, sig) = self.sign("POST", "/v1/ssh-recordings", &json);
        let http = service_http_client(&self.endpoint, std::time::Duration::from_secs(120))?;
        let resp = http
            .request(Method::POST, url.clone())
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
        let url = self.endpoint.url(path.trim_start_matches('/'))?;
        let (ts, sig) = self.sign("GET", "/v1/ssh-sessions", b"");
        let resp = self
            .http
            .request(Method::GET, url.clone())
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
        let url = self
            .endpoint
            .url(&format!("v1/ssh-recordings/list?limit={limit}"))?;
        let (ts, sig) = self.sign("GET", "/v1/ssh-recordings/list", b"");
        let resp = self
            .http
            .request(Method::GET, url.clone())
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
    pub edge_endpoint_id: String,
    pub edge_domain: String,
    pub auth_token: String,
    #[serde(default)]
    pub redirect_rules: Vec<tunnet_common::RedirectRule>,
}

pub fn basic_metadata(hostname: &str, agent_version: &str, kind: &str) -> serde_json::Value {
    serde_json::json!({
        "hostname": hostname,
        "agentVersion": agent_version,
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "family": std::env::consts::FAMILY,
        "kind": kind, // "agent" | "sdk"
        "reportedAt": Timestamp::now().to_string(),
    })
}
