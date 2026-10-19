// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Proxy
// SPDX-License-Identifier: Apache-2.0

//! Bootstrap certificate - self-issued leaf cert for the proxy's own hostname.
//!
//! Sentin8:Proxy serves HTTPS on port 443, but Sentin8:Acme - the CA that
//! issues its certificate - is itself behind Sentin8:Proxy. To break this
//! chicken-and-egg problem, the proxy self-issues a bootstrap leaf
//! certificate at startup using `rcgen` (same pattern as acme's
//! bootstrap cert, .
//!
//! The bootstrap cert is valid for 24 hours - more than enough for Acme
//! to come up and issue a proper cert. It includes the local IP in the
//! SAN list so internal ServiceDiscovery connections work during the
//! bootstrap window.
//!
//! Design:

use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose,
};

/// A self-issued bootstrap certificate (PEM-encoded cert + key).
/// The bootstrapcert type.
pub struct BootstrapCert {
    /// The hostname.
    pub hostname: String,
    /// The cert PEM.
    pub cert_pem: Vec<u8>,
    /// The key PEM.
    pub key_pem: Vec<u8>,
}

/// Generate a self-signed bootstrap leaf certificate for the proxy's
/// own hostname.
///
/// The cert is valid for `validity_secs` (default 24 hours) and includes:
/// - The proxy hostname as the CN and primary SAN (e.g. `proxy.ops.sys.sentin8.local`)
/// - The local IP as an additional SAN (from `SENTIN8_CAPTAIN_LOCAL_IP`)
///
/// The cert is self-signed (no CA hierarchy) - it is only used to bootstrap
/// TLS until Acme issues a proper cert. Once Acme is healthy, the cert
/// resolver hot-swaps to the Acme-issued cert.
/// Generate bootstrap cert.
pub fn generate_bootstrap_cert(
    hostname: &str,
    local_ip: Option<&str>,
    validity_secs: u64,
) -> Result<BootstrapCert, String> {
    let key = KeyPair::generate().map_err(|e| format!("generate bootstrap key: {e}"))?;

    // Build SAN list: hostname + optional local IP.
    let mut san_names = vec![hostname.to_string()];
    if let Some(ip) = local_ip {
        if !ip.is_empty() {
            san_names.push(ip.to_string());
        }
    }

    let mut params = CertificateParams::new(san_names.clone())
        .map_err(|e| format!("bootstrap cert params: {e}"))?;

    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, hostname);

    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::seconds(validity_secs as i64);

    // Self-sign (no CA - this is a bootstrap cert, not a CA-issued cert).
    let cert = params
        .self_signed(&key)
        .map_err(|e| format!("self-sign bootstrap cert: {e}"))?;

    let cert_pem = cert.pem().into_bytes();
    let key_pem = key.serialize_pem().into_bytes();

    tracing::info!(
        hostname = %hostname,
        sans = ?san_names,
        validity_secs,
        "proxy: generated bootstrap cert"
    );

    Ok(BootstrapCert {
        hostname: hostname.to_string(),
        cert_pem,
        key_pem,
    })
}

/// Derive the proxy's hostname from the Sentin8 domain.
///
/// The proxy's platform domain is `proxy.ops.sys.{sentin8_domain}`.
/// Handle proxy hostname.
pub fn proxy_hostname(sentin8_domain: &str) -> String {
    format!("proxy.ops.sys.{sentin8_domain}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_bootstrap_cert_roundtrip() {
        let cert = generate_bootstrap_cert("proxy.ops.sys.sentin8.local", Some("127.0.0.1"), 86400)
            .unwrap();
        assert_eq!(cert.hostname, "proxy.ops.sys.sentin8.local");
        assert!(!cert.cert_pem.is_empty());
        assert!(!cert.key_pem.is_empty());
        // Cert should be PEM-encoded.
        assert!(cert.cert_pem.starts_with(b"-----BEGIN CERTIFICATE-----"));
        assert!(cert.key_pem.starts_with(b"-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn generate_bootstrap_cert_without_ip() {
        let cert = generate_bootstrap_cert("proxy.ops.sys.sentin8.local", None, 3600).unwrap();
        assert!(!cert.cert_pem.is_empty());
    }

    #[test]
    fn proxy_hostname_derivation() {
        assert_eq!(
            proxy_hostname("sentin8.local"),
            "proxy.ops.sys.sentin8.local"
        );
        assert_eq!(proxy_hostname("example.com"), "proxy.ops.sys.example.com");
    }
}
