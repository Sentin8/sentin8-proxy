// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Proxy
// SPDX-License-Identifier: Apache-2.0

//! Proxy configuration loaded from environment variables.

use std::env;

/// Backend TLS mode for L7 bridging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The backendtlsmode type.
pub enum BackendTlsMode {
    /// Re-encrypt TLS to backend with mTLS (production).
    /// The bridge variant.
    Bridge,
    /// Forward plain HTTP to backend (dev / loopback).
    /// The offload variant.
    Offload,
}

impl BackendTlsMode {
    /// Parse the configured TLS-mode keyword (case-insensitive).
    ///
    /// Not the `FromStr` trait - no `Err` variant exists (unknown values
    /// default to `Offload`), so the inherent name stands; call sites use
    /// the qualified path.
    pub fn parse_tls_mode(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "bridge" => Self::Bridge,
            _ => Self::Offload,
        }
    }
}

/// Proxy configuration.
#[derive(Debug, Clone)]
/// Configuration for prox.
pub struct ProxConfig {
    /// TCP listener port for client connections (default 443).
    /// The tcp port.
    pub tcp_port: u16,
    /// Management API port (default 3098).
    /// The mgmt port.
    pub mgmt_port: u16,
    /// Internal L4 passthrough port (default 8443, 0 = disabled).
    /// The internal port.
    pub internal_port: u16,
    /// Plain-HTTP listener port for upstream ACME HTTP-01 challenge
    /// validation (DEVDOM-2, acme DESIGN §4.3). Serves ONLY
    /// `/.well-known/acme-challenge/*` (forwarded to acme); everything
    /// else a fixed 404. 0/unset = listener not bound (external
    /// issuance disabled). Default 80 when the operator enables it.
    /// The http challenge port.
    pub http_challenge_port: u16,
    /// Valkey URL for the captain service registry.
    /// The valkey URL.
    pub valkey_url: String,
    /// PostgreSQL connection string for domain resolution (read-only).
    /// The database URL.
    pub database_url: String,
    /// NOTIFY debounce window in milliseconds (default 1000).
    /// The debounce ms.
    pub debounce_ms: u64,
    /// Safety poll interval in seconds (default 30).
    /// The safety poll s.
    pub safety_poll_s: u64,
    /// Suspect backend skip duration in seconds (default 30).
    /// The suspect ttl s.
    pub suspect_ttl_s: u64,
    /// TCP connect timeout to backends in milliseconds (default 2000).
    /// The connect timeout ms.
    pub connect_timeout_ms: u64,

    // ── L7 TLS Bridging ──
    /// Enable L7 TLS bridging for external traffic (default true).
    /// When false, all traffic gets L4 passthrough.
    /// The l7 enabled.
    pub l7_enabled: bool,
    /// Enable WAF rule evaluation (default false).
    /// The waf enabled.
    pub waf_enabled: bool,
    /// Enable rate limiting (default false).
    /// The rate limit enabled.
    pub rate_limit_enabled: bool,
    /// Default requests/second per client IP (default 100).
    /// The rate limit rps.
    pub rate_limit_rps: u32,
    /// Backend TLS mode: "bridge" (re-encrypt) or "offload" (plain HTTP).
    /// The backend tls mode.
    pub backend_tls_mode: BackendTlsMode,
    /// Proxy's mTLS client cert path for backend connections (bridging mode).
    /// The mtls cert path.
    pub mtls_cert_path: Option<String>,
    /// Proxy's mTLS client key path (bridging mode).
    /// The mtls key path.
    pub mtls_key_path: Option<String>,
    /// Root Sentin8 domain (e.g. sentin8.local).
    /// The sentin8 domain.
    pub sentin8_domain: String,
}

impl ProxConfig {
    /// Handle from env.
    pub fn from_env() -> Self {
        let valkey_url = env::var("SENTIN8_PROXY_VALKEY_URL").unwrap_or_else(|_| {
            env::var("VALKEY_URL").unwrap_or_else(|_| {
                sentin8::config::Sentin8Config::default_valkey_url().to_string()
            })
        });

        let database_url = env::var("SENTIN8_PROXY_DATABASE_URL")
            .or_else(|_| env::var("DATABASE_URL"))
            .unwrap_or_else(|_| sentin8::config::Sentin8Config::default_database_url().to_string());

        let sentin8_domain =
            env::var("SENTIN8_DOMAIN").unwrap_or_else(|_| "sentin8.local".to_string());

        Self {
            tcp_port: env::var("SENTIN8_PROXY_PORT")
                .expect("SENTIN8_PROXY_PORT must be set by captain")
                .parse()
                .expect("SENTIN8_PROXY_PORT must be a valid u16"),
            mgmt_port: env::var("SENTIN8_PROXY_MGMT_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| {
                    let svc_port: u16 = env::var("SENTIN8_PROXY_PORT")
                        .expect("SENTIN8_PROXY_PORT must be set by captain")
                        .parse()
                        .expect("SENTIN8_PROXY_PORT must be a valid u16");
                    svc_port + 10000
                }),
            internal_port: env::var("SENTIN8_PROXY_INTERNAL_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            http_challenge_port: env::var("SENTIN8_PROXY_HTTP_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            valkey_url,
            database_url,
            debounce_ms: env::var("SENTIN8_PROXY_DEBOUNCE_MS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1000),
            safety_poll_s: env::var("SENTIN8_PROXY_SAFETY_POLL_S")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30),
            suspect_ttl_s: env::var("SENTIN8_PROXY_SUSPECT_TTL_S")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30),
            connect_timeout_ms: env::var("SENTIN8_PROXY_CONNECT_TIMEOUT_MS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(2000),
            l7_enabled: env::var("SENTIN8_PROXY_L7_ENABLED")
                .ok()
                .map(|s| s == "true" || s == "1")
                .unwrap_or(true),
            waf_enabled: env::var("SENTIN8_PROXY_WAF_ENABLED")
                .ok()
                .map(|s| s == "true" || s == "1")
                .unwrap_or(false),
            rate_limit_enabled: env::var("SENTIN8_PROXY_RATE_LIMIT_ENABLED")
                .ok()
                .map(|s| s == "true" || s == "1")
                .unwrap_or(false),
            rate_limit_rps: env::var("SENTIN8_PROXY_RATE_LIMIT_RPS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(100),
            backend_tls_mode: BackendTlsMode::parse_tls_mode(
                &env::var("SENTIN8_PROXY_BACKEND_TLS_MODE")
                    .unwrap_or_else(|_| "offload".to_string()),
            ),
            mtls_cert_path: env::var("SENTIN8_PROXY_MTLS_CERT_PATH").ok(),
            mtls_key_path: env::var("SENTIN8_PROXY_MTLS_KEY_PATH").ok(),
            sentin8_domain,
        }
    }
}
