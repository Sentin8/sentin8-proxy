// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Proxy
// SPDX-License-Identifier: Apache-2.0

//! TLS termination at the edge - wraps `sentin8-tls` for the proxy's L7 mode.
//!
//! The proxy uses the same `sentin8-tls` library as backends for TLS
//! termination, Acme certificate management, and PQ crypto. The proxy
//! is just another `sentin8-tls` consumer - it obtains certificates from
//! Sentin8:Acme for all domains in the `sentin8_domains` cache.
//!
//! Design:

use std::sync::Arc;

use sentin8::tls::WildcardCertResolver;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

/// A TLS acceptor for the proxy's edge listener.
///
/// Wraps the `sentin8-tls` `WildcardCertResolver` to terminate client
/// TLS connections using Acme certificates with PQ crypto.
pub struct ProxyTlsAcceptor {
    acceptor: TlsAcceptor,
}

impl ProxyTlsAcceptor {
    /// Create a TLS acceptor from the sentin8-tls cert resolver.
    ///
    /// The cert resolver must be shared with the `sentin8-tls` sync task
    /// so certificates are kept up-to-date via LISTEN/NOTIFY.
    pub fn new(cert_resolver: Arc<WildcardCertResolver>) -> Result<Self, String> {
        let provider = sentin8::tls::crypto::sentin8_pq_provider();

        let versions = sentin8::tls::crypto::sentin8_tls_versions();
        let server_config =
            rustls::server::ServerConfig::builder_with_provider(std::sync::Arc::new(provider))
                .with_protocol_versions(&versions)
                .map_err(|e| format!("invalid protocol versions: {e}"))?
                .with_no_client_auth()
                .with_cert_resolver(cert_resolver);

        Ok(Self {
            acceptor: TlsAcceptor::from(std::sync::Arc::new(server_config)),
        })
    }

    /// Create a TLS acceptor that REQUESTS a client certificate and accepts
    /// ANY presented certificate without CA verification (DESIGN 9a.12 -
    /// the sentin8-tls `allow_self_signed` posture at the proxy edge).
    ///
    /// SECURITY: the presented cert reaches the backend as
    /// `X-Sentin8-Client-Cert`; Sentin8:Auth's RFC 8705 decision binds its
    /// RFC 8705 thumbprint against the registration row - an unregistered
    /// cert authenticates nothing. The posture only enables self-signed
    /// client handshakes (the conformance rig's `self_signed_tls_client_auth`
    /// variants) while clients presenting no certificate still connect.
    pub fn new_allow_self_signed(
        cert_resolver: Arc<WildcardCertResolver>,
    ) -> Result<Self, String> {
        use rustls::server::danger::ClientCertVerifier;

        #[derive(Debug)]
        struct AcceptAnyClientCert;

        impl ClientCertVerifier for AcceptAnyClientCert {
            fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
                &[]
            }

            // OPTIONAL client auth - handshakes without a client
            // certificate keep working (the CA posture's
            // `allow_unauthenticated` semantics; DESIGN 9a.12).
            fn client_auth_mandatory(&self) -> bool {
                false
            }

            fn verify_client_cert(
                &self,
                _end_entity: &rustls::pki_types::CertificateDer<'_>,
                _intermediates: &[rustls::pki_types::CertificateDer<'_>],
                _now: rustls::pki_types::UnixTime,
            ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
                Ok(rustls::server::danger::ClientCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &rustls::pki_types::CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }

            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &rustls::pki_types::CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }

            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                vec![
                    rustls::SignatureScheme::ED25519,
                    rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                    rustls::SignatureScheme::RSA_PKCS1_SHA256,
                    rustls::SignatureScheme::RSA_PSS_SHA256,
                    rustls::SignatureScheme::RSA_PKCS1_SHA384,
                    rustls::SignatureScheme::RSA_PKCS1_SHA512,
                    rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                ]
            }
        }

        let provider = sentin8::tls::crypto::sentin8_pq_provider();
        let versions = sentin8::tls::crypto::sentin8_tls_versions();
        let server_config =
            rustls::server::ServerConfig::builder_with_provider(std::sync::Arc::new(provider))
                .with_protocol_versions(&versions)
                .map_err(|e| format!("invalid protocol versions: {e}"))?
                .with_client_cert_verifier(std::sync::Arc::new(AcceptAnyClientCert))
                .with_cert_resolver(cert_resolver.clone());

        Ok(Self {
            acceptor: TlsAcceptor::from(std::sync::Arc::new(server_config)),
        })
    }

    /// Accept a TCP stream and perform the TLS handshake.
    ///
    /// Returns a TLS stream on success, or an error if the handshake fails
    /// (e.g. no cert for SNI, client doesn't support PQ key exchange).
    pub async fn accept(
        &self,
        tcp_stream: TcpStream,
    ) -> Result<tokio_rustls::server::TlsStream<TcpStream>, std::io::Error> {
        self.acceptor.accept(tcp_stream).await
    }
}
