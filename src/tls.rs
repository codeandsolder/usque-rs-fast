use anyhow::{Context, Result};
use p256::ecdsa::SigningKey;
use p256::pkcs8::DecodePrivateKey;
use p256::SecretKey;
use rcgen::{CertificateParams, KeyPair};
use std::io::Write;
use std::time::Duration;
use tempfile::NamedTempFile;

use crate::config::Config;

pub(crate) const DGRAM_QUEUE_LEN: usize = 1000;

/// Holds temporary PEM files for quiche TLS config and the pinned endpoint key.
pub struct TlsMaterial {
    pub cert_pem_file: NamedTempFile,
    pub key_pem_file: NamedTempFile,
    pub endpoint_pub_key_spki_der: Vec<u8>,
}

fn parse_signing_key(priv_key_der: &[u8]) -> Result<SigningKey> {
    match SigningKey::from_pkcs8_der(priv_key_der) {
        Ok(key) => Ok(key),
        Err(pkcs8_error) => match SecretKey::from_sec1_der(priv_key_der) {
            Ok(key) => Ok(SigningKey::from(key)),
            Err(sec1_error) => Err(anyhow::anyhow!(
                "failed to parse ECDSA private key from config as PKCS#8 ({pkcs8_error}) or SEC1 ({sec1_error})"
            )),
        },
    }
}

/// Generate self-signed client cert from the config private key and prepare
/// temp PEM files that quiche can load.
pub fn prepare_tls_material(config: &Config) -> Result<TlsMaterial> {
    let priv_key_der = config.get_ec_private_key_der()?;
    let signing_key = parse_signing_key(&priv_key_der)?;

    let key_pair_pem =
        p256::pkcs8::EncodePrivateKey::to_pkcs8_pem(&signing_key, p256::pkcs8::LineEnding::LF)
            .context("failed to encode private key to PEM")?;

    let key_pair =
        KeyPair::from_pem(key_pair_pem.as_ref()).context("failed to load key pair into rcgen")?;

    let mut params = CertificateParams::new(Vec::<String>::new())
        .context("failed to create certificate params")?;
    params.not_before = time::OffsetDateTime::now_utc();
    params.not_after = time::OffsetDateTime::now_utc() + Duration::from_secs(24 * 60 * 60);

    let cert = params
        .self_signed(&key_pair)
        .context("failed to generate self-signed certificate")?;

    let cert_pem = cert.pem();

    let mut cert_file = NamedTempFile::new().context("failed to create temp cert file")?;
    cert_file.write_all(cert_pem.as_bytes())?;
    cert_file.flush()?;

    let mut key_file = NamedTempFile::new().context("failed to create temp key file")?;
    key_file.write_all(key_pair_pem.as_bytes())?;
    key_file.flush()?;

    let endpoint_pub_key_spki_der = config.get_endpoint_pub_key_der()?;

    Ok(TlsMaterial {
        cert_pem_file: cert_file,
        key_pem_file: key_file,
        endpoint_pub_key_spki_der,
    })
}

/// Validate that TLS material can be built from the MASQUE config.
pub fn validate_config(config: &Config) -> Result<()> {
    prepare_tls_material(config).map(|_| ())
}

/// Build the shared QUIC configuration used by both the native TUN and
/// reusable packet-stream paths.
pub fn build_quic_config(
    tls_material: &TlsMaterial,
    max_datagram_size: usize,
) -> Result<quiche::Config> {
    let mut quic_config = quiche::Config::new(quiche::PROTOCOL_VERSION)
        .map_err(|error| anyhow::anyhow!("quiche config: {error}"))?;

    // Endpoint identity is verified below the TLS stack by pinning the peer
    // certificate SPKI to the key returned by WARP registration.
    quic_config.verify_peer(false);
    quic_config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .map_err(|error| anyhow::anyhow!("set ALPN: {error}"))?;

    // Boring 5 enables hybrid post-quantum groups by default. This project
    // intentionally keeps the smaller classical handshake used on
    // resource-constrained routers; revisit this explicitly if PQC is added.
    quic_config
        .set_curves_list("X25519:P-256:P-384")
        .map_err(|error| anyhow::anyhow!("set TLS curves: {error}"))?;

    let cert_path = tls_material
        .cert_pem_file
        .path()
        .to_str()
        .context("temporary certificate path is not valid UTF-8")?;
    let key_path = tls_material
        .key_pem_file
        .path()
        .to_str()
        .context("temporary private-key path is not valid UTF-8")?;

    quic_config
        .load_cert_chain_from_pem_file(cert_path)
        .map_err(|error| anyhow::anyhow!("load cert: {error}"))?;
    quic_config
        .load_priv_key_from_pem_file(key_path)
        .map_err(|error| anyhow::anyhow!("load key: {error}"))?;

    quic_config.set_max_idle_timeout(0);
    quic_config.set_max_recv_udp_payload_size(max_datagram_size);
    quic_config.set_max_send_udp_payload_size(max_datagram_size);
    quic_config.set_initial_max_data(10_000_000);
    quic_config.set_initial_max_stream_data_bidi_local(1_000_000);
    quic_config.set_initial_max_stream_data_bidi_remote(1_000_000);
    quic_config.set_initial_max_stream_data_uni(1_000_000);
    quic_config.set_initial_max_streams_bidi(100);
    quic_config.set_initial_max_streams_uni(100);
    quic_config.set_disable_active_migration(true);
    quic_config.enable_dgram(true, DGRAM_QUEUE_LEN, DGRAM_QUEUE_LEN);

    Ok(quic_config)
}

/// Verify a peer's DER certificate against the pinned SPKI public key.
/// Returns true if the peer cert's `SubjectPublicKeyInfo` matches.
pub fn verify_endpoint_key(peer_cert_der: &[u8], expected_spki_der: &[u8]) -> bool {
    use x509_cert::der::{Decode, Encode};

    let Ok(cert) = x509_cert::Certificate::from_der(peer_cert_der) else {
        log::warn!("failed to parse peer certificate for key pinning");
        return false;
    };
    let Ok(spki_der) = cert.tbs_certificate().subject_public_key_info().to_der() else {
        log::warn!("failed to encode peer certificate public key for key pinning");
        return false;
    };
    spki_der == expected_spki_der
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_legacy_sec1_private_key() {
        let secret = SecretKey::from_slice(&[1u8; 32]).expect("valid P-256 scalar");
        let sec1 = secret.to_sec1_der().expect("encode SEC1");
        let parsed = parse_signing_key(sec1.as_ref()).expect("parse legacy SEC1 key");
        assert_eq!(parsed.to_bytes().as_slice(), secret.to_bytes().as_slice());
    }
}
