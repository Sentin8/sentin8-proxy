// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Proxy
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 Proxy — dual-mode L4/L7 ingress router for all services.
//!
//! The proxy sits on port 443 and routes traffic in two modes:
//!
//! - **L4 SNI Passthrough** (internal traffic — loopback/private IPs):
//!   Peeks the SNI hostname from the TLS ClientHello, looks it up in
//!   the `sentin8_domains` cache, and pipes the raw TLS stream to an
//!   `Active` instance of the target service. Never decrypts TLS.
//! - **L7 TLS Bridging** (external traffic — public IPs):
//!   Terminates the client's TLS using `sentin8-tls` (Acme certs, PQ
//!   crypto), inspects the HTTP request, enforces WAF/rate-limit/path-ACL
//!   policies, injects `X-Sentin8-*` tenant context headers at the edge,
//!   then re-encrypts (or offloads) to the backend.
//!
//! The traffic split is determined by source IP detection:
//!
//! - Loopback (.0/8, ::1), private (10/172.16/192.168), link-local
//!   (169.254) → L4 passthrough
//! - Everything else → L7 TLS bridging (when L7 is enabled)
//!
//! See.

mod backend_registry;
mod bootstrap_cert;
mod config;
mod domain_resolver;
mod handlers;
mod header_injector;
mod l7_metrics;
mod mapping_cache;
mod pipe;
mod policy;
mod policy_engine;
mod registration;
mod server;
mod sni;
mod sys_events;
mod tls_acceptor;
mod tls_proxy;
mod traffic_split;
mod upstream_idle_pool;
mod upstream_tls;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Self-registration probe (self-registration ): `--print-registration`
    // prints the proxy's self-description (m2m_grants) as JSON and exits.
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--print-registration") {
        let section = args
            .iter()
            .find_map(|a| a.strip_prefix("--section="))
            .map(|s| s.to_string());
        return registration::print(section);
    }

    // Install the Graviola PQ crypto provider before any reqwest HTTPS call
    // (policy admin/verify clients, TLS sync — reqwest panics "No provider
    // set" otherwise; COLD-START-1).
    let _ = sentin8::tls::crypto::sentin8_pq_provider().install_default();

    let _ = dotenvy::dotenv();
    let _ = sentin8::middleware::error_metrics::init_tracing_with_metrics(
        "sentin8:proxy",
        std::env::var("RUST_LOG").ok().as_deref().unwrap_or("info"),
    );
    sentin8::middleware::error_metrics::spawn_publisher(
        std::env::var("VALKEY_URL").unwrap_or_default(),
        "sentin8:proxy",
    );

    let config = config::ProxConfig::from_env();
    tracing::info!(
        service = "sentin8:proxy",
        version = env!("CARGO_PKG_VERSION"),
        tcp_port = config.tcp_port,
        mgmt_port = config.mgmt_port,
        internal_port = config.internal_port,
        l7_enabled = config.l7_enabled,
        backend_tls_mode = ?config.backend_tls_mode,
        "service starting"
    );

    server::serve(config).await
}
