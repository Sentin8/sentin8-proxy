// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Proxy
// SPDX-License-Identifier: Apache-2.0

//! X-Sentin8-* header injection at the edge for L7 TLS bridging mode.
//!
//! When operating in L7 mode, the proxy resolves tenant context from the
//! `Host` header (using the `sentin8_domains` cache) and injects
//! `X-Sentin8-*` headers before forwarding to the backend. Client-supplied
//! `X-Sentin8-*` headers are stripped to prevent forgery.
//!
//! Design:

use crate::mapping_cache::DomainMapping;
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use uuid::Uuid;

/// All `X-Sentin8-*` headers that are stripped from client requests
/// before the proxy injects its own.
const SENTIN8_HEADERS: &[&str] = &[
    "x-sentin8-env-id",
    "x-sentin8-app-id",
    "x-sentin8-service",
    "x-sentin8-hostname",
    "x-sentin8-domain-type",
    "x-sentin8-correlation-id",
    "x-sentin8-caller-service",
    "x-sentin8-client-cert",
    "x-sentin8-client-cert-subject",
    "x-sentin8-client-cert-thumbprint",
    "x-sentin8-client-cert-issuer",
    "x-sentin8-client-cert-chain",
];

/// Strip all client-supplied `X-Sentin8-*` headers and inject the resolved
/// tenant context headers from the mapping.
///
/// Returns a new `HeaderMap` with:
/// - All original non-`X-Sentin8-*` headers preserved
/// - `X-Sentin8-Env-Id`, `X-Sentin8-App-Id` (if applicable),
///   `X-Sentin8-Service`, `X-Sentin8-Hostname`, `X-Sentin8-Correlation-Id`
///   injected from the mapping
pub fn inject_tenant_headers(
    original_headers: &HeaderMap,
    mapping: &DomainMapping,
    host: &str,
) -> HeaderMap {
    let mut new_headers = HeaderMap::new();

    // Preserve all non-X-Sentin8-* headers.
    for (name, value) in original_headers.iter() {
        let name_str = name.as_str().to_ascii_lowercase();
        if SENTIN8_HEADERS.contains(&name_str.as_str()) {
            continue;
        }
        new_headers.insert(name.clone(), value.clone());
    }

    // Inject resolved tenant context.
    inject(
        &mut new_headers,
        "x-sentin8-env-id",
        &mapping.env_id.to_string(),
    );
    inject(&mut new_headers, "x-sentin8-service", &mapping.service);
    inject(&mut new_headers, "x-sentin8-hostname", host);

    if let Some(app_id) = mapping.application_id {
        inject(&mut new_headers, "x-sentin8-app-id", &app_id.to_string());
    }

    // Generate or propagate correlation ID.
    let correlation_id = original_headers
        .get("x-sentin8-correlation-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("proxy-{}", Uuid::new_v4().simple()));
    inject(
        &mut new_headers,
        "x-sentin8-correlation-id",
        &correlation_id,
    );

    // Set caller-service so the backend knows this came through the proxy.
    inject(&mut new_headers, "x-sentin8-caller-service", "proxy");

    new_headers
}

/// Forward the client's mTLS certificate (PROXY-4, proxy README §7):
/// the DER leaf certificate, base64-encoded, as `X-Sentin8-Client-Cert` -
/// the backend's mTLS consumer can verify it against the platform CA
/// without holding the TLS connection. Client-supplied copies of the
/// header are already stripped (forgery guard), so this value is always
/// the certificate the proxy actually terminated TLS for. `None` (no
/// injection) when the connection presented no client certificate.
pub fn extract_client_cert_header(
    tls_stream: &tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> Option<String> {
    let (_, connection) = tls_stream.get_ref();
    let certs = connection.peer_certificates()?;
    let first = certs.first()?;
    Some(base64_encode(first.as_ref()))
}

/// Minimal standard base64 (RFC 4648) - avoids pulling the base64 crate
/// into the proxy for one call site.
fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk_get(chunk, 0),
            chunk_get(chunk, 1),
            chunk_get(chunk, 2),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(n >> 6) as usize & 63] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[n as usize & 63] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn chunk_get(chunk: &[u8], idx: usize) -> u8 {
    chunk.get(idx).copied().unwrap_or(0)
}

/// Extract the hostname from the `Host` header, stripping the port if present.
pub fn extract_host(headers: &HeaderMap) -> String {
    headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
        .unwrap_or_default()
}

fn inject(headers: &mut HeaderMap, name: &str, value: &str) {
    if let (Ok(hname), Ok(hvalue)) = (
        HeaderName::from_bytes(name.as_bytes()),
        HeaderValue::from_str(value),
    ) {
        headers.insert(hname, hvalue);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn make_mapping() -> DomainMapping {
        DomainMapping {
            hostname: "auth.qa1.org1.local.sentin8.dev".to_string(),
            service: "auth".to_string(),
            org_id: Uuid::new_v4(),
            env_id: Uuid::new_v4(),
            application_id: None,
            backend_url: None,
        }
    }

    #[test]
    fn strips_client_sentin8_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "host",
            HeaderValue::from_static("auth.qa1.org1.local.sentin8.dev"),
        );
        headers.insert(
            "x-sentin8-env-id",
            HeaderValue::from_static("forged-env-id"),
        );
        headers.insert("authorization", HeaderValue::from_static("Bearer token"));

        let mapping = make_mapping();
        let result = inject_tenant_headers(&headers, &mapping, "auth.qa1.org1.local.sentin8.dev");

        // Forged header should be replaced.
        assert_ne!(
            result.get("x-sentin8-env-id").unwrap().to_str().unwrap(),
            "forged-env-id"
        );
        // Non-Sentin8 header preserved.
        assert_eq!(
            result.get("authorization").unwrap().to_str().unwrap(),
            "Bearer token"
        );
    }

    #[test]
    fn injects_correct_tenant_context() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "host",
            HeaderValue::from_static("auth.qa1.org1.local.sentin8.dev"),
        );

        let mapping = make_mapping();
        let result = inject_tenant_headers(&headers, &mapping, "auth.qa1.org1.local.sentin8.dev");

        assert_eq!(
            result.get("x-sentin8-env-id").unwrap().to_str().unwrap(),
            mapping.env_id.to_string()
        );
        assert_eq!(
            result.get("x-sentin8-service").unwrap().to_str().unwrap(),
            "auth"
        );
        assert!(result.get("x-sentin8-correlation-id").is_some());
    }

    #[test]
    fn extract_host_strips_port() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("auth.example.com:443"));
        assert_eq!(extract_host(&headers), "auth.example.com");
    }
}
