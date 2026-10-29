// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Proxy
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 Proxy - the single ingress: L4 SNI router + L7 bridge.

#![deny(missing_docs)]

/// Backend service registry (Valkey-backed).
pub mod backend_registry;
/// Self-issued bootstrap certificate for the proxy's own hostname.
pub mod bootstrap_cert;
/// Environment configuration.
pub mod config;
/// Domain-to-backend resolution (membus → bus → owner API).
pub mod domain_resolver;
/// Management-plane HTTP handlers.
pub mod handlers;
/// TLS context header injection (X-Sentin8-*, client-supplied copies stripped).
pub mod header_injector;
/// L7 request metrics (latency, status codes).
pub mod l7_metrics;
/// Cached hostname → backend mapping.
pub mod mapping_cache;
/// Raw TCP pipe (L4 passthrough).
pub mod pipe;
/// Shield (Sentin8:Policy) integration - shared bridge re-exports.
pub mod policy;
/// Route-path policy enforcement (L7).
pub mod policy_engine;
/// Axum router and server.
pub mod server;
/// SNI parsing for the L4 router.
pub mod sni;
/// Sys event consumption (service updates).
pub mod sys_events;
/// TLS acceptor configuration (PQ key exchange, ML-DSA signatures).
pub mod tls_acceptor;
/// The TLS proxy (L4 SNI routing + L7 bridge).
pub mod tls_proxy;
/// Traffic split (IPv4/IPv6, local/private detection).
pub mod traffic_split;
/// Idle upstream-connection pool for the L7 bridge .
pub mod upstream_idle_pool;
/// Upstream TLS connections (service-to-service).
pub mod upstream_tls;

/// The L7 metrics collector.
pub use l7_metrics::L7Metrics;
/// The shared idle-upstream pool handle.
pub use upstream_idle_pool::UpstreamPool;
