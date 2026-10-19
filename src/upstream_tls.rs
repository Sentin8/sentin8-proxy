// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Proxy
// SPDX-License-Identifier: Apache-2.0

//! Re-encryption to backends - opens a new TLS (or plain HTTP) connection
//! to the selected backend instance.
//!
//! In `offload` mode (default for v1/dev), the proxy forwards plain HTTP
//! to the backend - acceptable when proxy and backend are on the same
//! machine (loopback).
//!
//! In `bridge` mode (production), the proxy opens a new TLS connection
//! to the backend using its own mTLS client certificate. The backend's
//! `sentin8-tls` terminates this TLS and verifies the proxy's cert
//! thumbprint.
//!
//! Design:

use std::time::Duration;

use crate::config::BackendTlsMode;

/// An upstream connection - either plain TCP (offload mode) or TLS (bridge mode).
/// The upstreamconnection type.
// Request-scoped connection wrapper: the TLS variant's buffer set is bounded and the value lives for one request - the size delta is accepted.
#[allow(clippy::large_enum_variant)]
pub enum UpstreamConnection {
    /// Plain TCP stream - forward HTTP without TLS (offload mode).
    Plain(tokio::net::TcpStream),
    /// TLS stream - re-encrypted to backend (bridge mode).
    Tls(tokio_rustls::client::TlsStream<tokio::net::TcpStream>),
}

/// Configuration for upstream connections.
/// Configuration for upstreamtls.
pub struct UpstreamTlsConfig {
    /// The mode.
    pub mode: BackendTlsMode,
    /// The connect timeout.
    pub connect_timeout: Duration,
    /// Path to the proxy's mTLS client cert (bridge mode only).
    /// The mtls cert path.
    pub mtls_cert_path: Option<String>,
    /// Path to the proxy's mTLS client key (bridge mode only).
    /// The mtls key path.
    pub mtls_key_path: Option<String>,
}

/// Connect to a backend address. In offload mode, opens a plain TCP
/// connection. In bridge mode, opens a TLS connection with optional mTLS.
///
/// The `sni_hostname` is used for SNI in bridge mode (so the backend's
/// `sentin8-tls` can select the correct certificate).
/// Connect it.
pub async fn connect(
    backend_addr: &str,
    sni_hostname: &str,
    config: &UpstreamTlsConfig,
) -> Result<UpstreamConnection, std::io::Error> {
    match config.mode {
        BackendTlsMode::Offload => {
            // Plain TCP - no TLS to backend.
            let stream = tokio::time::timeout(
                config.connect_timeout,
                tokio::net::TcpStream::connect(backend_addr),
            )
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"))??;

            Ok(UpstreamConnection::Plain(stream))
        }
        BackendTlsMode::Bridge => {
            // TLS to backend with optional mTLS client cert.
            let tcp_stream = tokio::time::timeout(
                config.connect_timeout,
                tokio::net::TcpStream::connect(backend_addr),
            )
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"))??;

            // Build the TLS client config.
            let tls_stream = connect_tls(tcp_stream, sni_hostname, config).await?;
            Ok(UpstreamConnection::Tls(tls_stream))
        }
    }
}

/// Establish a TLS connection to the backend.
///
/// Uses the process-default CryptoProvider (installed by `sentin8-tls`).
/// When mTLS cert/key paths are configured, presents the client certificate
/// to the backend.
async fn connect_tls(
    tcp_stream: tokio::net::TcpStream,
    sni_hostname: &str,
    config: &UpstreamTlsConfig,
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, std::io::Error> {
    // Load the root certificate store from the OS trust store.
    // sentin8-tls installs the Graviola PQ provider as the process default,
    // so we use the default CryptoProvider here.
    let provider = rustls::crypto::CryptoProvider::get_default()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no crypto provider installed - sentin8-tls must be initialized first",
            )
        })?
        .clone();

    // Load native root certificates from the OS trust store.
    // This includes Sentin8:Acme's Root CA (installed via update-ca-certificates).
    let mut root_store = rustls::RootCertStore::empty();
    match rustls_native_certs::load_native_certs() {
        Ok(certs) => {
            for cert in certs {
                if let Err(e) = root_store.add(cert) {
                    tracing::warn!(error = %e, "proxy: failed to add native root cert");
                }
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "proxy: failed to load native root certs");
        }
    }

    let versions = sentin8::tls::crypto::sentin8_tls_versions();

    // Load mTLS client cert if configured.
    let client_config = if let (Some(cert_path), Some(key_path)) =
        (&config.mtls_cert_path, &config.mtls_key_path)
    {
        let cert_pem = std::fs::read(cert_path)?;
        let key_pem = std::fs::read(key_path)?;

        let cert_chain: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut &cert_pem[..])
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("failed to parse cert: {e}"),
                    )
                })?
                .into_iter()
                .map(|cert| cert.into_owned())
                .collect();

        let key_der = rustls_pemfile::private_key(&mut &key_pem[..])
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("failed to parse key: {e}"),
                )
            })?
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "no private key found in PEM",
                )
            })?
            .clone_key();

        rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&versions)
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid TLS versions: {e}"),
                )
            })?
            .with_root_certificates(root_store)
            .with_client_auth_cert(cert_chain, key_der)
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("failed to build client cert config: {e}"),
                )
            })?
    } else {
        rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&versions)
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid TLS versions: {e}"),
                )
            })?
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    let client_config = std::sync::Arc::new(client_config);
    let server_name =
        rustls::pki_types::ServerName::try_from(sni_hostname.to_string()).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid SNI: {e}"),
            )
        })?;

    let connector = tokio_rustls::TlsConnector::from(client_config);
    connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                format!("TLS handshake failed: {e}"),
            )
        })
}
