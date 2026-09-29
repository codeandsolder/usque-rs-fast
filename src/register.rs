use anyhow::{bail, Context, Result};
use base64::Engine;
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::Generate;
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};

const API_URL: &str = "https://api.cloudflareclient.com";
const API_VERSION: &str = "v0a4471";
const DEFAULT_USER_AGENT: &str = "WARP for Android";
const CF_CLIENT_VERSION: &str = "a-6.35-4471";

#[derive(Serialize)]
struct Registration {
    key: String,
    install_id: String,
    fcm_token: String,
    tos: String,
    model: String,
    serial_number: String,
    os_version: String,
    key_type: String,
    tunnel_type: String,
    locale: String,
}

#[derive(Serialize)]
struct DeviceUpdate {
    key: String,
    key_type: String,
    tunnel_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AccountData {
    pub id: String,
    #[serde(default)]
    pub token: String,
    pub account: Account,
    pub config: WarpConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Account {
    pub license: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct WarpConfig {
    pub peers: Vec<Peer>,
    pub interface: Interface,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Peer {
    pub public_key: String,
    pub endpoint: Endpoint,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Endpoint {
    pub v4: String,
    pub v6: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Interface {
    pub addresses: Addresses,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Addresses {
    pub v4: String,
    pub v6: String,
}

#[derive(Debug, Deserialize)]
pub struct ApiError {
    pub errors: Vec<ErrorInfo>,
}

#[derive(Debug, Deserialize)]
pub struct ErrorInfo {
    pub message: String,
}

fn random_wg_pubkey() -> Result<String> {
    let mut key = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut key)
        .map_err(|_| anyhow::anyhow!("RNG failure"))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(key))
}

fn random_android_serial() -> Result<String> {
    let mut serial = [0u8; 8];
    ring::rand::SystemRandom::new()
        .fill(&mut serial)
        .map_err(|_| anyhow::anyhow!("RNG failure"))?;
    Ok(format!("{:016x}", u64::from_be_bytes(serial)))
}

fn cf_time_string() -> String {
    let now = time::OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}+00:00",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        now.millisecond(),
    )
}

fn build_client() -> Result<reqwest::Client> {
    use reqwest::header::{HeaderMap, HeaderValue};
    let mut headers = HeaderMap::new();
    headers.insert("User-Agent", HeaderValue::from_static(DEFAULT_USER_AGENT));
    headers.insert(
        "CF-Client-Version",
        HeaderValue::from_static(CF_CLIENT_VERSION),
    );
    headers.insert(
        "Content-Type",
        HeaderValue::from_static("application/json; charset=UTF-8"),
    );
    headers.insert("Connection", HeaderValue::from_static("Keep-Alive"));

    // Reqwest 0.13 defaults to AWS-LC and platform-native roots. Keep the
    // client self-contained for static router builds while reusing the ring
    // provider already present elsewhere in the dependency graph.
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

    reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .default_headers(headers)
        .build()
        .context("failed to build HTTP client")
}

pub async fn register(model: &str, locale: &str, jwt: Option<&str>) -> Result<AccountData> {
    let client = build_client()?;
    let wg_key = random_wg_pubkey()?;
    let serial = random_android_serial()?;

    let reg = Registration {
        key: wg_key,
        install_id: String::new(),
        fcm_token: String::new(),
        tos: cf_time_string(),
        model: model.to_string(),
        serial_number: serial,
        os_version: String::new(),
        key_type: "curve25519".to_string(),
        tunnel_type: "wireguard".to_string(),
        locale: locale.to_string(),
    };

    let url = format!("{API_URL}/{API_VERSION}/reg");
    let mut req = client.post(&url).json(&reg);
    if let Some(jwt) = jwt {
        req = req.header("CF-Access-Jwt-Assertion", jwt);
    }

    let resp = req.send().await.context("registration request failed")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("registration failed: {status} - {body}");
    }

    resp.json::<AccountData>()
        .await
        .context("failed to parse registration response")
}

pub fn generate_ec_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    let signing_key = SigningKey::generate();

    let priv_key_der = signing_key
        .to_pkcs8_der()
        .context("failed to encode private key to DER")?;
    let pub_key_spki = signing_key
        .verifying_key()
        .to_public_key_der()
        .context("failed to encode public key to DER")?;

    Ok((
        priv_key_der.as_bytes().to_vec(),
        pub_key_spki.as_bytes().to_vec(),
    ))
}

pub async fn enroll_key(
    account: &AccountData,
    pub_key_der: &[u8],
    device_name: Option<&str>,
) -> Result<AccountData> {
    let client = build_client()?;
    let pub_key_b64 = base64::engine::general_purpose::STANDARD.encode(pub_key_der);

    let update = DeviceUpdate {
        key: pub_key_b64,
        key_type: "secp256r1".to_string(),
        tunnel_type: "masque".to_string(),
        name: device_name.map(String::from),
    };

    let url = format!("{API_URL}/{API_VERSION}/reg/{}", account.id);
    let resp = client
        .patch(&url)
        .header("Authorization", format!("Bearer {}", account.token))
        .json(&update)
        .send()
        .await
        .context("enrollment request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if let Ok(api_err) = serde_json::from_str::<ApiError>(&body) {
            let msgs: Vec<_> = api_err.errors.iter().map(|e| e.message.as_str()).collect();
            bail!("enrollment failed: {status} - {}", msgs.join("; "));
        }
        bail!("enrollment failed: {status} - {body}");
    }

    resp.json::<AccountData>()
        .await
        .context("failed to parse enrollment response")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_client_builds_with_explicit_ring_and_webpki_roots() {
        build_client().expect("registration HTTP client should build");
    }

    #[test]
    fn cloudflare_timestamp_keeps_expected_shape() {
        let timestamp = cf_time_string();
        assert_eq!(timestamp.len(), 29);
        assert!(timestamp.ends_with("+00:00"));
        assert_eq!(&timestamp[4..5], "-");
        assert_eq!(&timestamp[7..8], "-");
        assert_eq!(&timestamp[10..11], "T");
        assert_eq!(&timestamp[13..14], ":");
        assert_eq!(&timestamp[16..17], ":");
        assert_eq!(&timestamp[19..20], ".");
    }
}
