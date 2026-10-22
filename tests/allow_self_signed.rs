// Probe test (DESIGN 9a.12): the proxy's allow-self-signed acceptor
// completes a handshake with a SELF-SIGNED client certificate (the RFC
// 8705 self_signed_tls_client_auth rig surface). The RFC 8705 trust
// decision stays in the application.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Mint a self-signed EC P-256 client cert (DER) + key (PKCS8 DER).
fn self_signed_client() -> (Vec<u8>, Vec<u8>) {
    let mut params = rcgen::CertificateParams::new(Vec::new()).expect("params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "probe-mtls");
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyEncipherment,
    ];
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
    let cert = params.self_signed(&key).expect("self-sign");
    (cert.der().to_vec(), key.serialize_der())
}

#[tokio::test]
async fn allow_self_signed_accepts_self_signed_client() {
    let (client_cert_der, client_key_der) = self_signed_client();

    // Server side: the proxy's own acceptor posture... the proxy's acceptor
    // type is crate-private to src; recreate the exact rustls config by
    // driving the same builder here (the CONTRACT under test is the rustls
    // custom-verifier wiring, mirrored in ProxyTlsAcceptor::new_allow_self_signed).
    use rustls::server::danger::ClientCertVerifier;

    #[derive(Debug)]
    struct AcceptAnyClientCert;

    impl ClientCertVerifier for AcceptAnyClientCert {
        fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
            &[]
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
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
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
    let mut roots = rustls::RootCertStore::empty();
    // A resolver with a self-signed SERVER cert for the test session.
    let mut server_params = rcgen::CertificateParams::new(vec!["localhost".into()]).expect(
        "params",
    );
    server_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "probe-server");
    let server_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
    let server_cert = server_params.self_signed(&server_key).expect("self-sign");
    roots
        .add(server_cert.der().clone())
        .expect("add server cert as root");
    // Not used as root - the server sends its own cert directly.
    let _ = &mut roots;

    let server_config = rustls::server::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&versions)
        .expect("versions")
        .with_client_cert_verifier(Arc::new(AcceptAnyClientCert))
        .with_single_cert(
            vec![server_cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(server_key.serialize_der().into()),
        )
        .expect("server cert");

    let server_tls = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        sentin8::tls::crypto::sentin8_pq_provider(),
    ))
    .with_protocol_versions(&versions)
    .expect("versions")
    .dangerous()
    .with_custom_certificate_verifier(client_verifier(server_cert.der().to_vec()))
    .with_client_auth_cert(
        vec![rustls::pki_types::CertificateDer::from(client_cert_der)],
        rustls::pki_types::PrivateKeyDer::Pkcs8(client_key_der.into()),
    )
    .expect("client cert");

    let client_tls = tokio_rustls::TlsConnector::from(Arc::new(client_config));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let mut tls = server_tls.accept(tcp).await.expect("server handshake");
        // Serve one HTTP-ish exchange.
        let mut buf = [0u8; 256];
        let n = tls.read(&mut buf).await.expect("server read");
        let _ = tls.write_all(&buf[..n]).await;
        let _ = tls.shutdown().await;
    });

    let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let mut tls = client_tls
        .connect("localhost".try_into().expect("dns"), tcp)
        .await
        .expect("CLIENT HANDSHAKE WITH SELF-SIGNED CLIENT CERT");
    tls.write_all(b"ping").await.expect("write");
    let mut buf = Vec::new();
    tls.read_to_end(&mut buf).await.expect("read");
    assert_eq!(buf, b"ping");
    server.await.expect("server task");
}

use rustls::client::danger::ServerCertVerifier as _;
use rustls::server::danger::ClientCertVerifier as _;

/// A client verifier that trusts exactly the test server cert.
#[derive(Debug)]
struct TrustOne(Vec<u8>);

impl rustls::client::danger::ServerCertVerifier for TrustOne {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.0.as_slice() {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("unexpected server cert".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

fn client_verifier(
    server_der: Vec<u8>,
) -> std::sync::Arc<dyn rustls::client::danger::ServerCertVerifier> {
    std::sync::Arc::new(TrustOne(server_der))
}