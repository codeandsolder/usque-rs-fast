use anyhow::{Context, Result};
use boring::{
    asn1::Asn1Time,
    bn::BigNum,
    ec::EcKey,
    hash::MessageDigest,
    pkey::{PKey, Private},
    sha::sha256,
    ssl::{SslContextBuilder, SslMethod},
    x509::{X509, X509NameBuilder},
};

use crate::config::Config;

#[cfg(feature = "tun")]
pub(crate) const DGRAM_QUEUE_LEN: usize = 1000;

/// In-memory TLS material for the WARP client connection.
pub struct TlsMaterial {
    certificate: X509,
    private_key: PKey<Private>,
    pub endpoint_pub_key_spki_der: Vec<u8>,
}

fn parse_private_key(priv_key_der: &[u8]) -> Result<PKey<Private>> {
    if let Ok(key) = PKey::private_key_from_der(priv_key_der) {
        return Ok(key);
    }
    let ec_key = EcKey::private_key_from_der(priv_key_der)
        .context("failed to parse EC private key as PKCS#8 or SEC1 DER")?;
    PKey::from_ec_key(ec_key).context("failed to wrap EC private key")
}

fn self_signed_certificate(private_key: &PKey<Private>) -> Result<X509> {
    let mut name = X509NameBuilder::new().context("failed to create X.509 name")?;
    name.append_entry_by_text("CN", "rcgen self signed cert")
        .context("failed to set X.509 common name")?;
    let name = name.build();

    // Match rcgen's default serial derivation: the first 20 bytes of the
    // SHA-256 digest of SubjectPublicKeyInfo, with the sign bit cleared.
    let spki = private_key
        .public_key_to_der()
        .context("failed to encode public key for X.509 serial")?;
    let digest = sha256(&spki);
    let mut serial_bytes = digest[..20].to_vec();
    serial_bytes[0] &= 0x7f;
    let serial = BigNum::from_slice(&serial_bytes)
        .context("failed to build X.509 serial")?
        .to_asn1_integer()
        .context("failed to encode X.509 serial")?;

    let not_before = Asn1Time::days_from_now(0).context("failed to set certificate start time")?;
    let not_after = Asn1Time::days_from_now(1).context("failed to set certificate expiry")?;

    let mut cert = X509::builder().context("failed to create X.509 builder")?;
    cert.set_version(2).context("failed to set X.509 version")?;
    cert.set_serial_number(&serial)
        .context("failed to set X.509 serial")?;
    cert.set_subject_name(&name)
        .context("failed to set X.509 subject")?;
    cert.set_issuer_name(&name)
        .context("failed to set X.509 issuer")?;
    cert.set_not_before(&not_before)
        .context("failed to set X.509 not-before")?;
    cert.set_not_after(&not_after)
        .context("failed to set X.509 not-after")?;
    cert.set_pubkey(private_key)
        .context("failed to set X.509 public key")?;
    cert.sign(private_key, MessageDigest::sha256())
        .context("failed to sign self-signed client certificate")?;
    Ok(cert.build())
}

/// Generate the ephemeral self-signed client certificate used for WARP.
///
/// # Errors
///
/// Returns an error if configured key material is invalid or `BoringSSL` cannot
/// construct the certificate.
pub fn prepare_tls_material(config: &Config) -> Result<TlsMaterial> {
    let priv_key_der = config.get_ec_private_key_der()?;
    let private_key = parse_private_key(&priv_key_der)?;
    let certificate = self_signed_certificate(&private_key)?;
    let endpoint_pub_key_spki_der = config.get_endpoint_pub_key_der()?;

    Ok(TlsMaterial {
        certificate,
        private_key,
        endpoint_pub_key_spki_der,
    })
}

/// Validate that TLS material can be built from the MASQUE config.
///
/// # Errors
///
/// Returns any error encountered while preparing TLS material.
pub fn validate_config(config: &Config) -> Result<()> {
    prepare_tls_material(config).map(|_| ())
}

fn build_ssl_context(tls_material: &TlsMaterial) -> Result<SslContextBuilder> {
    let mut builder = SslContextBuilder::new(SslMethod::tls())
        .context("failed to create BoringSSL client context")?;
    builder
        .set_certificate(&tls_material.certificate)
        .context("failed to configure client certificate")?;
    builder
        .set_private_key(&tls_material.private_key)
        .context("failed to configure client private key")?;
    builder
        .check_private_key()
        .context("client certificate/private key mismatch")?;
    Ok(builder)
}

fn base_quic_config(tls_material: &TlsMaterial) -> Result<quiche::Config> {
    let ssl = build_ssl_context(tls_material)?;
    let mut config = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, ssl)
        .map_err(|error| anyhow::anyhow!("quiche config: {error}"))?;
    config.verify_peer(false);
    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .map_err(|error| anyhow::anyhow!("set ALPN: {error}"))?;
    config
        .set_curves_list("X25519:P-256:P-384")
        .map_err(|error| anyhow::anyhow!("set TLS curves: {error}"))?;
    Ok(config)
}

/// Build the QUIC configuration used by the native TUN transport.
///
/// # Errors
///
/// Returns an error if `BoringSSL` or quiche rejects the configuration.
#[cfg(feature = "tun")]
pub fn build_quic_config(
    tls_material: &TlsMaterial,
    max_datagram_size: usize,
) -> Result<quiche::Config> {
    let mut quic_config = base_quic_config(tls_material)?;
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

#[cfg(any(
    feature = "http-proxy",
    feature = "https-proxy",
    feature = "socks5-proxy"
))]
/// Build the QUIC configuration used by the direct L4 HTTP/3 CONNECT transport.
///
/// # Errors
/// Returns an error if `BoringSSL` or quiche rejects the configuration.
pub fn build_l4_quic_config(
    tls_material: &TlsMaterial,
    max_datagram_size: usize,
) -> Result<quiche::Config> {
    let mut quic_config = base_quic_config(tls_material)?;
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
    Ok(quic_config)
}

/// Verify a peer's DER certificate against the pinned SPKI public key.
#[must_use]
pub fn verify_endpoint_key(peer_cert_der: &[u8], expected_spki_der: &[u8]) -> bool {
    let Ok(cert) = X509::from_der(peer_cert_der) else {
        log::warn!("failed to parse peer certificate for key pinning");
        return false;
    };
    let Ok(public_key) = cert.public_key() else {
        log::warn!("failed to extract peer certificate public key");
        return false;
    };
    let Ok(spki_der) = public_key.public_key_to_der() else {
        log::warn!("failed to encode peer certificate public key for key pinning");
        return false;
    };
    spki_der == expected_spki_der
}

#[cfg(test)]
mod tests {
    use super::*;
    use boring::{ec::EcGroup, nid::Nid};

    #[test]
    fn accepts_legacy_sec1_private_key() -> Result<()> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let key = EcKey::generate(&group)?;
        let sec1 = key.private_key_to_der()?;
        let parsed = parse_private_key(&sec1)?;
        assert_eq!(
            parsed.public_key_to_der()?,
            PKey::from_ec_key(key)?.public_key_to_der()?
        );
        Ok(())
    }

    #[test]
    fn generates_matching_in_memory_certificate() -> Result<()> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let key = PKey::from_ec_key(EcKey::generate(&group)?)?;
        let cert = self_signed_certificate(&key)?;
        assert!(cert.verify(&key)?);
        Ok(())
    }
}
