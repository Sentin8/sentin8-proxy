// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Proxy
// SPDX-License-Identifier: Apache-2.0

//! Proxy server — dual-mode L4/L7 ingress router on port 443 + management API.
//!
//! Startup flow:
//!
//! 1. Connect to PostgreSQL, seed the `sentin8_domains` cache, start the
//!    LISTEN/NOTIFY sync task.
//! 2. Spawn the Valkey pub/sub backend refresh loop (per-service instance
//!    lists).
//! 3. If L7 is enabled, build the sentin8-tls cert resolver + TLS acceptor.
//! 4. Bind TCP on port 443 — accept loop spawns a task per connection.
//!    Each task: check source IP → internal: L4 passthrough, external: L7
//!    bridging.
//! 5. If internal_port > 0, bind a second listener for guaranteed L4
//!    passthrough.
//! 6. Bind management API on the mgmt port.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::routing::{get, post};
use tower_http::cors::CorsLayer;

use crate::backend_registry;
use crate::config::ProxConfig;
use crate::domain_resolver::{self, DomainResolver};
use crate::handlers::{self, AppState};
use crate::l7_metrics::L7Metrics;
use crate::mapping_cache;
use crate::policy_engine::{PolicyConfig, PolicyEngine};
use crate::sni;
use crate::tls_acceptor::ProxyTlsAcceptor;
use crate::tls_proxy::{handle_l7_connection, L7State};
use crate::traffic_split;

/// Serve it.
pub async fn serve(config: ProxConfig) -> anyhow::Result<()> {
    // ── 0. Valkey-plane workload identity ──────────────────────────────
    // The proxy's cert-CN identity (sentin8:proxy) resolves the backend
    // registry, the conn-flush metrics channel, and L7 metrics. A fresh
    // platform has no persisted pair yet — mint-or-load in a background
    // loop (the mint races Acme's own boot; retry until the pair lands,
    // then the registry refresh heals on its next cycle — group DESIGN.md
    // §3.1).
    {
        let issuer = sentin8::config::Sentin8Config::from_env().sentin8_auth_issuer();
        let ca_cert_path = sentin8::auth::m2m::platform_ca_path();
        tokio::spawn(async move {
            loop {
                match sentin8::auth::m2m::ensure_workload_certificate(
                    &issuer,
                    "sentin8:proxy",
                    &ca_cert_path,
                )
                .await
                {
                    Ok(_) => break,
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "proxy: Valkey workload identity mint pending — retrying in 10s"
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                    }
                }
            }
        });
    }

    // ── 1. Domain resolver (org/env/app tables → hostname mappings) ──
    let pool = sentin8::config::pg_pool::connect(&config.database_url).await?;
    let domain_resolver = DomainResolver::new();
    domain_resolver::spawn_sync(pool.clone(), domain_resolver.clone());

    // Keep the old mapping cache for the management API (stats only).
    let mapping_cache = mapping_cache::MappingCache::new();

    // ── 2. Backend registry (Valkey captain:svc:*) ───────────────────────
    let backends = backend_registry::spawn(
        config.valkey_url.clone(),
        config.debounce_ms,
        config.safety_poll_s,
        config.suspect_ttl_s,
    );

    // ── 3. Management API (separate port) ────────────────────────────
    let mgmt_addr = format!("0.0.0.0:{}", config.mgmt_port);

    // ── Sentin8:Policy (— boot_full): proxy is a custom-boot
    // binary (L4/L7 router, no shell serve), so it runs the ONE shared boot
    // helper itself — same four steps the shell runs for every other
    // service. No second engine may be constructed.
    let policy_engine = sentin8::shield::runtime::engine_for("sentin8:proxy");
    sentin8::shield::runtime::boot_full(
        &pool,
        &sentin8::config::Sentin8Config::from_env().sentin8_auth_issuer(),
        "sentin8:proxy",
        &policy_engine,
    )
    .await?;

    // In-flight L7 connection gauge (proxy README §7) — created here so both the
    // data plane (handle_l7_connection, via L7State) and the management
    // health payload (AppState → handlers::health) share one counter.
    let connection_gauge = std::sync::Arc::new(crate::tls_proxy::L7ConnectionGauge::new());

    // PROXY-5: the idle upstream pool is built HERE (before both AppState
    // and the L7 state) so the mgmt health payload and the L7 data path
    // share ONE pool instance.
    let upstream_pool = crate::upstream_idle_pool::UpstreamPool::new();
    crate::upstream_idle_pool::spawn_evictor(upstream_pool.clone());

    let state = AppState {
        _config: Arc::new(config.clone()),
        backends: backends.clone(),
        mappings: mapping_cache.clone(),
        admin: sentin8::shield::admin::SharedAdminState {
            service: "sentin8:proxy".to_string(),
            pool: pool.clone(),
            policy: policy_engine.clone(),
            auth_client: std::sync::Arc::new(sentin8::auth::client::Client::new(
                sentin8::auth::client::ClientOptions::default(),
            )),
        },
        policy: policy_engine,
        connection_gauge: Some(connection_gauge.clone()),
        upstream_pool: upstream_pool.clone(),
    };
    let mgmt_app = axum::Router::new()
        .route("/v1/health", get(handlers::health))
        .route("/v1/prox/backends", get(handlers::list_backends))
        .route("/v1/prox/mappings", get(handlers::list_mappings))
        // ── Sentin8:Policy admin API.
        .route(
            "/v1/admin/policy-sets",
            get(sentin8::shield::admin::list_policy_sets::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}",
            get(sentin8::shield::admin::get_policy_set::<handlers::AppState>)
                .put(sentin8::shield::admin::put_policy_set::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}/test",
            post(sentin8::shield::admin::test_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/enforce",
            post(sentin8::shield::admin::admin_enforce_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/shadow",
            post(sentin8::shield::admin::admin_shadow_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/disable",
            post(sentin8::shield::admin::admin_disable_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/relations",
            get(sentin8::shield::admin::list_relations::<handlers::AppState>)
                .put(sentin8::shield::admin::put_relation::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_relation::<handlers::AppState>),
        )
        .route(
            "/v1/admin/relations/check",
            get(sentin8::shield::admin::check_relation::<handlers::AppState>),
        )
        .route(
            "/v1/admin/attributes",
            get(sentin8::shield::admin::list_attributes::<handlers::AppState>)
                .put(sentin8::shield::admin::put_attribute::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_attribute::<handlers::AppState>),
        )
        // ── Policy Studio — RFW renderer aliases ──
        .route(
            "/v1/admin/policy-sets",
            post(sentin8::shield::admin::create_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}/save",
            post(sentin8::shield::admin::save_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}/{action}",
            post(sentin8::shield::admin::admin_flip_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-decisions",
            get(sentin8::shield::admin::list_policy_decisions::<handlers::AppState>),
        )
        .route(
            "/v1/admin/relations/{id}/delete",
            post(sentin8::shield::admin::admin_delete_relation::<handlers::AppState>),
        )
        .route(
            "/v1/admin/attributes/{id}/delete",
            post(sentin8::shield::admin::admin_delete_attribute::<handlers::AppState>),
        )
        .layer(axum::middleware::from_fn(
            sentin8::middleware::request_logging,
        ))
        .layer(axum::middleware::from_fn(
            sentin8::middleware::correlation_id,
        ))
        .layer(CorsLayer::very_permissive())
        .with_state(state);

    let mgmt_listener = tokio::net::TcpListener::bind(&mgmt_addr).await?;
    tracing::info!("prox management API listening on {mgmt_addr}");
    tokio::spawn(async move {
        let _ = axum::serve(mgmt_listener, mgmt_app)
            .with_graceful_shutdown(sentin8::middleware::shutdown_signal("prox-mgmt"))
            .await;
    });

    // ── 3b. Optional plain-HTTP challenge listener (:80, DEVDOM-2,
    // acme DESIGN §4.3). Upstream ACME CAs validate HTTP-01 by fetching
    // http://{domain}/.well-known/acme-challenge/{token} on port 80 —
    // this listener forwards those GETs to acme and 404s everything
    // else. Unset = not bound (external issuance disabled).
    if config.http_challenge_port > 0 {
        let backends = backends.clone();
        let http_addr = format!("0.0.0.0:{}", config.http_challenge_port);
        let http_listener = tokio::net::TcpListener::bind(&http_addr).await?;
        tracing::info!("proxy acme-challenge listener listening on {http_addr}");
        tokio::spawn(async move {
            loop {
                let accept = tokio::select! {
                    r = http_listener.accept() => r,
                    _ = sentin8::middleware::shutdown_signal("proxy-http80") => return,
                };
                let (mut stream, _addr) = match accept {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!(error = ?e, "http80 accept failed");
                        continue;
                    }
                };
                let backends = backends.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_acme_challenge_http(&mut stream, &backends).await {
                        tracing::warn!(error = %e, "http80 challenge request failed");
                    }
                });
            }
        });
    }

    // ── 4. Connection counter — counts routed TLS connections ─────────
    let conn_counter = ConnectionCounter::new();
    spawn_conn_flush_loop(conn_counter.clone(), config.valkey_url.clone(), 10);

    // ── 5. L7 TLS bridging state (if enabled) ──────────────────────
    let l7_state = if config.l7_enabled {
        Some(
            build_l7_state(
                &config,
                &mapping_cache,
                &backends,
                connection_gauge.clone(),
                upstream_pool.clone(),
            )
            .await,
        )
    } else {
        tracing::info!("proxy: L7 TLS bridging disabled — all traffic gets L4 passthrough");
        None
    };

    // ── 6. TCP listener on port 443 (dual-mode: L4 or L7 per connection) ─
    let tcp_addr = format!("0.0.0.0:{}", config.tcp_port);
    let listener = tokio::net::TcpListener::bind(&tcp_addr).await?;
    tracing::info!(
        "proxy dual-mode ingress listening on {tcp_addr} (L7 enabled: {})",
        config.l7_enabled
    );

    let connect_timeout = Duration::from_millis(config.connect_timeout_ms);

    loop {
        let accept_result = tokio::select! {
            r = listener.accept() => r,
            _ = sentin8::middleware::shutdown_signal("proxy") => {
                tracing::info!("proxy TCP listener shutting down");
                break;
            }
        };
        let (client_stream, client_addr) = match accept_result {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = ?e, "accept failed");
                continue;
            }
        };

        let backends = backends.clone();
        let mapping_cache = mapping_cache.clone();
        let resolver = domain_resolver.clone();
        let conn_counter = conn_counter.clone();
        let l7_state = l7_state.clone();

        tokio::spawn(async move {
            // Source IP detection: internal → L4 passthrough, external → L7 bridging.
            let is_internal = traffic_split::is_internal_ip(&client_addr.ip());

            if is_internal {
                handle_l4_passthrough(
                    client_stream,
                    client_addr,
                    &backends,
                    &mapping_cache,
                    &resolver,
                    &conn_counter,
                    connect_timeout,
                )
                .await;
            } else if let Some(ref l7) = l7_state {
                handle_l7_connection(client_stream, client_addr, l7.clone()).await;
            } else {
                // L7 disabled — fall back to L4 for external traffic too.
                handle_l4_passthrough(
                    client_stream,
                    client_addr,
                    &backends,
                    &mapping_cache,
                    &resolver,
                    &conn_counter,
                    connect_timeout,
                )
                .await;
            }
        });
    }
    Ok(())
}

/// Build the L7 TLS bridging state: TLS acceptor, policy engine, metrics.
///
/// The proxy self-issues a bootstrap leaf certificate at startup
/// to break the chicken-and-egg: the proxy needs a cert from Acme, but
/// Acme is behind the proxy. The bootstrap cert is pre-loaded into the
/// sentin8-tls cert resolver, then hot-swapped to an Acme-issued cert
/// once Acme is healthy.
async fn build_l7_state(
    config: &ProxConfig,
    mapping_cache: &mapping_cache::MappingCache,
    backends: &backend_registry::SharedServiceBackendRegistry,
    connection_gauge: std::sync::Arc<crate::tls_proxy::L7ConnectionGauge>,
    upstream_pool: crate::upstream_idle_pool::UpstreamPool,
) -> Arc<L7State> {
    // Self-issue a 24-hour leaf cert for the proxy's own hostname so
    // the TLS handshake succeeds immediately, even before Acme is up.
    let proxy_hostname = crate::bootstrap_cert::proxy_hostname(&config.sentin8_domain);
    let local_ip = std::env::var("SENTIN8_CAPTAIN_LOCAL_IP").ok();
    let bootstrap = crate::bootstrap_cert::generate_bootstrap_cert(
        &proxy_hostname,
        local_ip.as_deref(),
        24 * 3600, // 24-hour validity
    )
    .expect("proxy: failed to generate bootstrap cert");

    // Build the sentin8-tls cert resolver for edge TLS termination.
    // The proxy uses the same sentin8-tls library as backends — it's
    // just another consumer that obtains certs from Acme. The bootstrap
    // cert is pre-loaded so TLS works before Acme is reachable.
    let tls = sentin8::tls::Sentin8Tls::builder()
        .service_identity("sentin8:proxy")
        .sentin8_domain(&config.sentin8_domain)
        .bootstrap_cert(
            &bootstrap.hostname,
            bootstrap.cert_pem.clone(),
            bootstrap.key_pem.clone(),
        )
        .build()
        .await
        .expect("proxy: failed to build sentin8-tls for edge termination");

    let cert_resolver = tls.cert_resolver();
    let tls_acceptor =
        ProxyTlsAcceptor::new(cert_resolver).expect("proxy: failed to create TLS acceptor");

    // Build the policy engine.
    let policy_engine = PolicyEngine::new(PolicyConfig {
        waf_enabled: config.waf_enabled,
        rate_limit_enabled: config.rate_limit_enabled,
        rate_limit_rps: config.rate_limit_rps,
    });

    // L7 metrics.
    let metrics = L7Metrics::new();
    crate::l7_metrics::spawn_l7_metrics_flush(metrics.clone(), config.valkey_url.clone(), 10);

    tracing::info!(
        waf_enabled = config.waf_enabled,
        rate_limit_enabled = config.rate_limit_enabled,
        backend_tls_mode = ?config.backend_tls_mode,
        "proxy: L7 TLS bridging initialized (bootstrap cert loaded for {})",
        proxy_hostname
    );

    Arc::new(L7State {
        tls_acceptor,
        mapping_cache: mapping_cache.clone(),
        backends: backends.clone(),
        policy_engine,
        connect_timeout: Duration::from_millis(config.connect_timeout_ms),
        backend_tls_mode: config.backend_tls_mode,
        mtls_cert_path: config.mtls_cert_path.clone(),
        mtls_key_path: config.mtls_key_path.clone(),
        metrics,
        connection_gauge,
        upstream_pool,
    })
}

/// Handle a single TCP connection in L4 SNI passthrough mode.
///
/// This is the original L4 path: peek SNI → look up mapping → pick
/// backend → pipe raw TLS bytes bidirectionally. No decryption.
async fn handle_l4_passthrough(
    client_stream: tokio::net::TcpStream,
    client_addr: std::net::SocketAddr,
    backends: &backend_registry::SharedServiceBackendRegistry,
    mapping_cache: &mapping_cache::MappingCache,
    resolver: &DomainResolver,
    conn_counter: &ConnectionCounter,
    connect_timeout: Duration,
) {
    // 1. Peek SNI from the TLS ClientHello.
    let sni_hostname = match sni::peek_sni(&client_stream).await {
        Ok(Some(sni)) => sni,
        Ok(None) => {
            tracing::debug!(%client_addr, "no SNI in ClientHello — closing connection");
            return;
        }
        Err(e) => {
            tracing::debug!(%client_addr, error = %e, "failed to peek SNI — closing connection");
            return;
        }
    };

    // 2. Look up the SNI hostname in the mapping cache, with fallback
    // to domain-pattern deduction via the domain resolver.
    let mapping = match mapping_cache.get(&sni_hostname) {
        Some(m) => m,
        None => {
            // Deduce from domain pattern using the resolver (org/env/app tables).
            match resolver.resolve(&sni_hostname) {
                Some(m) => {
                    tracing::info!(%client_addr, sni = %sni_hostname, service = %m.service, "domain resolver: deduced mapping");
                    Arc::new(m)
                }
                None => {
                    tracing::warn!(%client_addr, sni = %sni_hostname, "no mapping for SNI (cache miss + resolver miss) — closing connection");
                    return;
                }
            }
        }
    };

    tracing::debug!(
        %client_addr,
        sni = %sni_hostname,
        service = %mapping.service,
        "routing connection"
    );

    // Count the routed connection per target service.
    conn_counter.increment(&mapping.service);

    // 3. Resolve the backend address.
    // If the mapping has a backend_url (app instance), forward directly.
    // Otherwise, pick an Active instance of the target service from Valkey.
    let backend_addr = if let Some(ref url) = mapping.backend_url {
        // App instance — direct to backend_url (strip http:// or https:// prefix).
        url.replace("http://", "").replace("https://", "")
    } else {
        // The domain resolver already resolves the subdomain label to the
        // full service_type (e.g. `auth` → `sentin8-auth`) via the
        // `subdomain_map` loaded from `sentin8_vertical_services`. So
        // `mapping.service` is always the full service_type that captain
        // registered — no `sentin8-` prefix prepending needed here.
        match backends.pick(&mapping.service) {
            Some(addr) => addr,
            None => {
                tracing::warn!(
                    %client_addr,
                    sni = %sni_hostname,
                    service = %mapping.service,
                    "no Active instances for service — closing connection"
                );
                return;
            }
        }
    };

    // 4. Connect to the backend with fail-over.
    let connect_start = Instant::now();
    let backend_stream =
        match connect_with_failover(&backend_addr, &mapping.service, backends, connect_timeout)
            .await
        {
            Some(s) => s,
            None => {
                tracing::warn!(
                    %client_addr,
                    sni = %sni_hostname,
                    service = %mapping.service,
                    backend = %backend_addr,
                    "all instances failed — closing connection"
                );
                return;
            }
        };
    let _tcp_rtt = connect_start.elapsed();

    // 5. Pipe raw bytes bidirectionally.
    crate::pipe::pipe_bidirectional(client_stream, backend_stream).await;
}

/// Serve ONE plain-HTTP request on the :80 challenge listener
/// (DEVDOM-2, acme DESIGN §4.3): `GET /.well-known/acme-challenge/{token}`
/// is forwarded to an Active acme instance over TLS (the same
/// cert-resolved HTTPS surface acme always serves — IP pinned to the
/// picked instance, SNI set to acme's platform hostname, the pattern
/// sentin8-tls's ACME client uses); every other request gets a fixed
/// 404. Requests are unauthenticated by design (RFC 8555 §8.1 — the
/// token itself is the capability).
async fn handle_acme_challenge_http(
    stream: &mut tokio::net::TcpStream,
    backends: &crate::backend_registry::ServiceBackendRegistry,
) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Read the request head (bounded — a malformed client cannot push
    // unbounded bytes into the proxy).
    let mut buf = vec![0u8; 8192];
    let mut head = Vec::new();
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Ok(()); // client closed before sending a head
        }
        head.extend_from_slice(&buf[..n]);
        if head.windows(4).any(|w| w == b"\r\n\r\n") || head.len() > 8192 {
            break;
        }
    }
    let head_text = String::from_utf8_lossy(&head);
    let mut lines = head_text.split("\r\n");
    let request_line = lines.next().unwrap_or_default().to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();

    let response = match forward_challenge_to_acme(&method, &target, backends).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "http80: challenge forward failed");
            "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: 21\r\nConnection: close\r\n\r\nbackend unavailable\n"
                .to_string()
        }
    };
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}

/// Forward a well-formed challenge GET to acme over TLS. Returns the full
/// serialized HTTP/1.1 response for the client, or `None`-mapped 404 for
/// anything that is not a challenge GET with a live acme instance.
async fn forward_challenge_to_acme(
    method: &str,
    target: &str,
    backends: &crate::backend_registry::ServiceBackendRegistry,
) -> anyhow::Result<String> {
    // Local, order-independent path check: the listener serves ONLY the
    // well-known challenge path — everything else is a fixed 404.
    let path = target.split('?').next().unwrap_or(target);
    if method != "GET" || !path.starts_with("/.well-known/acme-challenge/") {
        return Ok(
            "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 10\r\nConnection: close\r\n\r\nnot found\n"
                .to_string(),
        );
    }
    let Some(backend_addr) = backends.pick("sentin8:acme") else {
        tracing::warn!("http80: no Active sentin8:acme instance for challenge");
        return Ok(
            "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: 21\r\nConnection: close\r\n\r\nbackend unavailable\n"
                .to_string(),
        );
    };
    // The registry address is `ip:port`; the request goes to acme's TLS
    // listener with SNI = acme's platform hostname (the same hostname
    // sentin8-tls pins when fetching certs) and the OS trust store (the
    // platform Root CA is installed there).
    let (ip, port) = backend_addr
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("malformed backend address {backend_addr}"))?;
    let port: u16 = port.parse()?;
    let socket_addr: std::net::SocketAddr = format!("{ip}:{port}").parse()?;
    let sentin8_domain =
        std::env::var("SENTIN8_DOMAIN").unwrap_or_else(|_| "sentin8.local".to_string());
    let sni_host = format!("acme.ops.sys.{sentin8_domain}");
    let url = format!("https://{sni_host}:{port}{path}");
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(10))
        .resolve(sni_host.as_str(), socket_addr)
        .build()?;
    let resp = client.get(&url).send().await?;
    let status = resp.status().as_u16();
    let body = resp.bytes().await?;
    Ok(format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        http_reason(status),
        body.len(),
    ) + std::str::from_utf8(&body).unwrap_or_default())
}

/// Minimal HTTP reason phrase for the statuses this listener returns.
fn http_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        404 => "Not Found",
        502 => "Bad Gateway",
        _ => "OK",
    }
}

// ── Connection counter ──────────────────────────────────────────────────

/// Thread-safe per-service connection counter. Counts routed TCP
/// connections per target service so prox can report how many
/// connections it forwarded to each service.
#[derive(Clone)]
struct ConnectionCounter {
    inner: Arc<parking_lot::Mutex<HashMap<String, u64>>>,
}

impl ConnectionCounter {
    fn new() -> Self {
        Self {
            inner: Arc::new(parking_lot::Mutex::new(HashMap::new())),
        }
    }

    fn increment(&self, service: &str) {
        let mut map = self.inner.lock();
        *map.entry(service.to_string()).or_insert(0) += 1;
    }

    fn drain(&self) -> HashMap<String, u64> {
        let mut map = self.inner.lock();
        std::mem::take(&mut *map)
    }
}

/// Spawn a flush loop that publishes the proxy's total connection count to
/// Valkey pub/sub channel `stat:metrics:tls` every `flush_interval_s`
/// seconds. The proxy only reports its own connection count — per-service
/// API call counts are reported by each service's own `traffic_counter`
/// middleware.
fn spawn_conn_flush_loop(counter: ConnectionCounter, valkey_url: String, flush_interval_s: u64) {
    if valkey_url.is_empty() {
        tracing::info!("prox: VALKEY_URL not set, connection metrics flush disabled");
        return;
    }
    let interval = Duration::from_secs(flush_interval_s.max(1));
    tokio::spawn(async move {
        let conn = match sentin8::middleware::valkey_client(&valkey_url, "sentin8:proxy").await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "prox: failed to open Valkey client; flush disabled");
                return;
            }
        };

        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // skip first tick
        loop {
            ticker.tick().await;
            let counts = counter.drain();
            if counts.is_empty() {
                continue;
            }

            let total: u64 = counts.values().sum();
            let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
            let window = format!("{}s", flush_interval_s.max(1));

            // Only publish the proxy's own total connection count.
            // Per-service API call counts are reported by each service's
            // own traffic_counter middleware — the proxy does not
            // overwrite them.
            let payload = serde_json::json!({
                "ts": ts,
                "source": "proxy",
                "window": window,
                "org_id": null,
                "env_id": null,
                "metrics": {
                    "proxy.traffic.external→sentin8-proxy.count": total,
                },
            });
            let payload_str = serde_json::to_string(&payload).unwrap_or_default();

            use glide::AsyncCommands as _;
            let _: Result<usize, _> = conn
                .publish::<_, _, usize>("stat:metrics:tls", payload_str.as_str())
                .await;

            tracing::debug!(total, "prox: published total connection count");
        }
    });
}

/// Connect to a backend with fail-over across instances of the same service.
async fn connect_with_failover(
    first_addr: &str,
    service: &str,
    backends: &backend_registry::SharedServiceBackendRegistry,
    timeout: Duration,
) -> Option<tokio::net::TcpStream> {
    if let Ok(Ok(s)) =
        tokio::time::timeout(timeout, tokio::net::TcpStream::connect(first_addr)).await
    {
        return Some(s);
    }
    backends.mark_suspect(service, first_addr);

    // Fail-over: try other instances of the same service.
    let max_tries = backends.service_len(service);
    for _ in 0..max_tries {
        let addr = match backends.pick(service) {
            Some(a) => a,
            None => break,
        };
        if let Ok(Ok(s)) =
            tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await
        {
            return Some(s);
        }
        backends.mark_suspect(service, &addr);
    }

    None
}

/// Shared policy-admin surface accessor.
impl sentin8::shield::admin::HasPolicyAdmin for AppState {
    fn policy_admin(&self) -> &sentin8::shield::admin::SharedAdminState {
        &self.admin
    }
}
