use anyhow::{Context, Result, bail};
use base64::Engine;
use boring::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::PKey,
};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Method, Request, StatusCode,
    client::conn::http1,
    header::{AUTHORIZATION, CONNECTION, CONTENT_TYPE, HOST, HeaderName, HeaderValue, USER_AGENT},
};
use hyper_util::rt::TokioIo;
use ring::rand::SecureRandom;
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const API_HOST: &str = "api.cloudflareclient.com";
const API_VERSION: &str = "v0a4471";
const DEFAULT_USER_AGENT: &str = "WARP for Android";
const CF_CLIENT_VERSION: &str = "a-6.35-4471";
const API_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_API_RESPONSE_BYTES: usize = 1024 * 1024;

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

use crate::account::AccountData;

#[derive(Debug, Deserialize)]
pub struct ApiError {
    pub errors: Vec<ErrorInfo>,
}

#[derive(Debug, Deserialize)]
pub struct ErrorInfo {
    pub message: String,
}

struct ApiResponse {
    status: StatusCode,
    body: Bytes,
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

fn registration_tls_config() -> Result<Arc<ClientConfig>> {
    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config =
        ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .context("failed to configure TLS protocol versions")?
            .with_root_certificates(roots)
            .with_no_client_auth();
    Ok(Arc::new(config))
}

async fn api_request(
    method: Method,
    path: &str,
    body: Vec<u8>,
    extra_headers: &[(HeaderName, HeaderValue)],
) -> Result<ApiResponse> {
    tokio::time::timeout(
        API_REQUEST_TIMEOUT,
        api_request_inner(method, path, body, extra_headers),
    )
    .await
    .context("Cloudflare registration API request timed out")?
}

async fn api_request_inner(
    method: Method,
    path: &str,
    body: Vec<u8>,
    extra_headers: &[(HeaderName, HeaderValue)],
) -> Result<ApiResponse> {
    let tcp = TcpStream::connect((API_HOST, 443))
        .await
        .context("failed to connect to Cloudflare registration API")?;
    let server_name =
        ServerName::try_from(API_HOST).context("invalid Cloudflare registration API hostname")?;
    let tls = TlsConnector::from(registration_tls_config()?)
        .connect(server_name, tcp)
        .await
        .context("registration TLS handshake failed")?;

    let (mut sender, connection) = http1::Builder::new()
        .handshake::<_, Full<Bytes>>(TokioIo::new(tls))
        .await
        .context("registration HTTP handshake failed")?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            log::debug!("registration HTTP connection ended with error: {error}");
        }
    });

    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(HOST, API_HOST)
        .header(USER_AGENT, DEFAULT_USER_AGENT)
        .header("CF-Client-Version", CF_CLIENT_VERSION)
        .header(CONTENT_TYPE, "application/json; charset=UTF-8")
        .header(CONNECTION, "Keep-Alive");
    for (name, value) in extra_headers {
        request = request.header(name, value);
    }
    let request = request
        .body(Full::new(Bytes::from(body)))
        .context("failed to build registration HTTP request")?;

    let response = sender
        .send_request(request)
        .await
        .context("registration HTTP request failed")?;
    let status = response.status();
    let body = Limited::new(response.into_body(), MAX_API_RESPONSE_BYTES)
        .collect()
        .await
        .map_err(|error| anyhow::anyhow!("failed to read registration response body: {error}"))?
        .to_bytes();
    Ok(ApiResponse { status, body })
}

fn response_text(body: &Bytes) -> String {
    String::from_utf8_lossy(body).into_owned()
}

/// Register a new WARP device.
///
/// # Errors
///
/// Returns an error if randomness, TLS/HTTP, or response decoding fails, or if
/// Cloudflare rejects registration.
pub async fn register(model: &str, locale: &str, jwt: Option<&str>) -> Result<AccountData> {
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
    let body = serde_json::to_vec(&reg).context("failed to encode registration request")?;
    let mut headers = Vec::new();
    if let Some(jwt) = jwt {
        headers.push((
            HeaderName::from_static("cf-access-jwt-assertion"),
            HeaderValue::from_str(jwt).context("invalid access JWT header value")?,
        ));
    }
    let response =
        api_request(Method::POST, &format!("/{API_VERSION}/reg"), body, &headers).await?;
    if !response.status.is_success() {
        bail!(
            "registration failed: {} - {}",
            response.status,
            response_text(&response.body)
        );
    }
    serde_json::from_slice::<AccountData>(&response.body)
        .context("failed to parse registration response")
}

/// Generate the EC key pair used for MASQUE device enrollment.
///
/// # Errors
///
/// Returns an error if the generated keys cannot be encoded to DER.
pub fn generate_ec_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    let group =
        EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).context("failed to select P-256 group")?;
    let ec_key = EcKey::generate(&group).context("failed to generate P-256 key")?;
    let key = PKey::from_ec_key(ec_key).context("failed to wrap P-256 key")?;
    let private_key = key
        .private_key_to_der_pkcs8()
        .context("failed to encode private key as PKCS#8 DER")?;
    let public_key = key
        .public_key_to_der()
        .context("failed to encode public key as SPKI DER")?;
    Ok((private_key, public_key))
}

/// Replace the registration key with the generated MASQUE EC public key.
///
/// # Errors
///
/// Returns an error if TLS/HTTP or response decoding fails, or if Cloudflare
/// rejects the update.
pub async fn enroll_key(
    account: &AccountData,
    pub_key_der: &[u8],
    device_name: Option<&str>,
) -> Result<AccountData> {
    let pub_key_b64 = base64::engine::general_purpose::STANDARD.encode(pub_key_der);
    let update = DeviceUpdate {
        key: pub_key_b64,
        key_type: "secp256r1".to_string(),
        tunnel_type: "masque".to_string(),
        name: device_name.map(String::from),
    };
    let body = serde_json::to_vec(&update).context("failed to encode enrollment request")?;
    let authorization = HeaderValue::from_str(&format!("Bearer {}", account.token))
        .context("invalid registration bearer token")?;
    let response = api_request(
        Method::PATCH,
        &format!("/{API_VERSION}/reg/{}", account.id),
        body,
        &[(AUTHORIZATION, authorization)],
    )
    .await?;

    if !response.status.is_success() {
        let text = response_text(&response.body);
        if let Ok(api_err) = serde_json::from_slice::<ApiError>(&response.body) {
            let msgs: Vec<_> = api_err
                .errors
                .iter()
                .map(|error| error.message.as_str())
                .collect();
            bail!(
                "enrollment failed: {} - {}",
                response.status,
                msgs.join("; ")
            );
        }
        bail!("enrollment failed: {} - {text}", response.status);
    }

    serde_json::from_slice::<AccountData>(&response.body)
        .context("failed to parse enrollment response")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_tls_config_builds_with_explicit_ring_and_webpki_roots() {
        assert!(registration_tls_config().is_ok());
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
