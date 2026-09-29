use anyhow::{Context, Result};
use reqwest::Client;
use serde::Serialize;
use std::time::Duration;

#[derive(Clone, Debug, Serialize)]
pub struct ProxyReport {
    pub v6: String,
    pub port: u16,
    pub v4: String,
    pub group: usize,
    pub slot: usize,
    pub auth: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locked_at: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct Heartbeat<'a> {
    pub v: u8,
    pub v6_root: &'a str,
    pub box_v6: &'a str,
    pub box_v4: &'a str,
    pub hostname: &'a str,
    pub phase: &'a str,
    pub locked_count: usize,
    pub cycling_count: usize,
    pub seen_v4_count: usize,
    pub stale_count: usize,
    pub uptime: i64,
    pub cpu_pct: f64,
    pub mem_used_mb: u64,
    pub mem_total_mb: u64,
    pub cpu_history: &'a [f64],
    pub proxies_delta: &'a [ProxyReport],
}

#[derive(Debug, Serialize)]
struct RegisterProxies<'a> {
    v: u8,
    v6_root: &'a str,
    box_v6: &'a str,
    box_v4: &'a str,
    hostname: &'a str,
    proxies: &'a [ProxyReport],
}

pub struct RemoteReporter {
    base_url: String,
    psk: String,
    client: Client,
}

impl RemoteReporter {
    /// Build a reporter compatible with the existing warp-orchestrator API.
    ///
    /// # Errors
    /// Returns an error if the URL is not HTTPS or the TLS client cannot be built.
    pub fn new(base_url: String, psk: String) -> Result<Self> {
        if !base_url.starts_with("https://") {
            anyhow::bail!("orchestrator URL must use HTTPS");
        }
        if psk.is_empty() {
            anyhow::bail!("orchestrator PSK must not be empty");
        }

        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let tls = rustls::ClientConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .context("failed to configure TLS protocol versions")?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let client = Client::builder()
            .tls_backend_preconfigured(tls)
            .timeout(Duration::from_secs(10))
            .build()
            .context("failed to build orchestrator HTTP client")?;

        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            psk,
            client,
        })
    }

    pub async fn heartbeat(&self, heartbeat: &Heartbeat<'_>) -> Result<()> {
        self.post("/api/warp-pool/heartbeat", heartbeat).await
    }

    pub async fn register(
        &self,
        v6_root: &str,
        box_v6: &str,
        box_v4: &str,
        hostname: &str,
        proxies: &[ProxyReport],
    ) -> Result<()> {
        self.post(
            "/api/warp-pool/register_proxies",
            &RegisterProxies {
                v: 1,
                v6_root,
                box_v6,
                box_v4,
                hostname,
                proxies,
            },
        )
        .await
    }

    async fn post<T: Serialize + ?Sized>(&self, path: &str, body: &T) -> Result<()> {
        let response = self
            .client
            .post(format!("{}{}", self.base_url, path))
            .bearer_auth(&self.psk)
            .json(body)
            .send()
            .await
            .with_context(|| format!("orchestrator POST {path} failed"))?;
        response
            .error_for_status()
            .with_context(|| format!("orchestrator POST {path} returned an error"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_schema_keeps_legacy_field_names() -> Result<()> {
        let report = ProxyReport {
            v6: "2001:db8::1".to_string(),
            port: 20_000,
            v4: "104.16.1.1".to_string(),
            group: 0,
            slot: 0,
            auth: "user:pass".to_string(),
            locked_at: Some(123),
        };
        let value = serde_json::to_value(&report)?;
        assert_eq!(value["v6"], "2001:db8::1");
        assert_eq!(value["port"], 20_000);
        assert_eq!(value["auth"], "user:pass");
        assert_eq!(value["locked_at"], 123);
        Ok(())
    }
}
