// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Proxy
// SPDX-License-Identifier: Apache-2.0

//! L7 TLS bridging handler - terminate client TLS, inspect HTTP, enforce
//! policies, inject X-Sentin8-* headers, forward to backend, return response.
//!
//! This is the L7 path for external traffic. Internal traffic uses the
//! L4 SNI passthrough path in `server.rs` / `pipe.rs`.
//!
//! Design:

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::{HeaderName, HeaderValue, Method, StatusCode};

use crate::backend_registry::SharedServiceBackendRegistry;
use crate::config::BackendTlsMode;
use crate::header_injector;
use crate::l7_metrics::L7Metrics;
use crate::mapping_cache::MappingCache;
use crate::policy_engine::{PolicyEngine, PolicyOutcome};
use crate::tls_acceptor::ProxyTlsAcceptor;
use crate::upstream_idle_pool::{self, UpstreamPool};
use crate::upstream_tls::{self, UpstreamTlsConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// In-flight connection gauge for the L7 bridge (proxy README §7).
/// Incremented at `handle_l7_connection` entry, decremented by the
/// RAII [`L7ConnectionGuard`] on every exit path so panics and early
/// returns cannot leak the count. Relaxed ordering - the gauge is the
/// drain signal captain polls via `/v1/health`, never a fence.
/// The l7 connection gauge.
pub struct L7ConnectionGauge(AtomicUsize);

impl L7ConnectionGauge {
    /// Gauge at zero.
    pub fn new() -> Self {
        Self(AtomicUsize::new(0))
    }

    /// Enter one in-flight connection - returns a guard that decrements
    /// on drop.
    pub fn enter(self: &Arc<Self>) -> L7ConnectionGuard {
        self.0.fetch_add(1, Ordering::Relaxed);
        L7ConnectionGuard {
            gauge: self.clone(),
        }
    }

    /// Current in-flight connection count - the value reported as
    /// `active_connections` in the proxy's health payload (proxy README §7).
    pub fn active_connections(&self) -> u64 {
        self.0.load(Ordering::Relaxed) as u64
    }

    /// Saturating exit (guards against any unpaired drop).
    fn exit(&self) {
        let _ = self
            .0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1));
    }
}

impl Default for L7ConnectionGauge {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII guard for one in-flight L7 connection - the drop half of
/// [`L7ConnectionGauge::enter`].
/// The l7 connection guard.
pub struct L7ConnectionGuard {
    gauge: Arc<L7ConnectionGauge>,
}

impl Drop for L7ConnectionGuard {
    fn drop(&mut self) {
        self.gauge.exit();
    }
}

/// Shared state for L7 TLS bridging handlers.
/// l7 state.
pub struct L7State {
    /// The tls acceptor.
    pub tls_acceptor: ProxyTlsAcceptor,
    /// The mapping cache.
    pub mapping_cache: MappingCache,
    /// The backends.
    pub backends: SharedServiceBackendRegistry,
    /// The policy engine.
    pub policy_engine: PolicyEngine,
    /// The connect timeout.
    pub connect_timeout: Duration,
    /// The backend tls mode.
    pub backend_tls_mode: BackendTlsMode,
    /// The mtls cert path.
    pub mtls_cert_path: Option<String>,
    /// The mtls key path.
    pub mtls_key_path: Option<String>,
    /// The metrics.
    pub metrics: L7Metrics,
    /// In-flight connection gauge - the drain signal (proxy README §7).
    pub connection_gauge: Arc<L7ConnectionGauge>,
    /// idle upstream-connection pool - warmed TLS/TCP
    /// sessions per (backend_addr, sni), removing the per-request PQ
    /// handshake from proxied requests.
    pub upstream_pool: UpstreamPool,
}

/// Handle a single external TCP connection in L7 TLS bridging mode.
///
/// Flow:
/// 1. Enter the in-flight gauge (RAII guard - proxy README §7 drain signal)
/// 2. Terminate the client's TLS (using sentin8-tls + Acme certs)
/// 3. Read the HTTP request from the decrypted stream
/// 4. Look up the Host header in the sentin8_domains cache
/// 5. Run the policy engine (WAF, rate limiting, path ACL)
/// 6. Inject X-Sentin8-* tenant context headers
/// 7. Connect to the backend (plain TCP for offload, TLS for bridge)
/// 8. Forward the request to the backend
/// 9. Read the backend response and return it to the client
///
/// Handle l7 connection.
pub async fn handle_l7_connection(
    client_stream: TcpStream,
    client_addr: SocketAddr,
    state: Arc<L7State>,
) {
    // 0. Enter the in-flight gauge (proxy README §7) - the guard decrements
    // on every exit path (return, panic, task abort), so the drain signal
    // cannot leak.
    let _conn_guard = state.connection_gauge.enter();

    // 1. TLS handshake - terminate the client's TLS.
    let mut tls_stream = match state.tls_acceptor.accept(client_stream).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(
                %client_addr,
                error = %e,
                "proxy L7: TLS handshake failed - closing connection"
            );
            state.metrics.record_handshake_error();
            return;
        }
    };

    // 2. Read the HTTP request from the decrypted stream.
    // We read a bounded amount of data (request line + headers + limited body).
    let request_data = match read_http_request(&mut tls_stream).await {
        Ok(data) => data,
        Err(e) => {
            tracing::debug!(
                %client_addr,
                error = %e,
                "proxy L7: failed to read HTTP request"
            );
            return;
        }
    };

    let request_start = Instant::now();

    // 3. Parse the HTTP request to extract method, URI, and headers.
    let parsed = match parse_http_request(&request_data) {
        Some(p) => p,
        None => {
            let _ = write_http_error(&mut tls_stream, StatusCode::BAD_REQUEST, "bad request").await;
            return;
        }
    };

    // 4. Look up the Host header in the mapping cache.
    let host = header_injector::extract_host(&parsed.headers);
    if host.is_empty() {
        let _ = write_http_error(
            &mut tls_stream,
            StatusCode::BAD_REQUEST,
            "missing Host header",
        )
        .await;
        return;
    }

    // 4a. ACME challenge passthrough.
    //
    // Paths matching /.well-known/acme-challenge/* bypass the entire L7
    // policy engine (WAF, rate limiting, path ACLs) and are forwarded
    // directly to the backend that owns the domain. The backend's
    // sentin8-tls serves the challenge token. No tenant context headers
    // are injected - the challenge request is unauthenticated by design.
    if is_acme_challenge(&parsed.uri) {
        tracing::debug!(
            %client_addr,
            host = %host,
            uri = %parsed.uri,
            "proxy L7: ACME challenge passthrough - bypassing policy engine"
        );

        // Look up the mapping for this host (needed to find the backend).
        let mapping = match state.mapping_cache.get(&host) {
            Some(m) => m,
            None => {
                let _ = write_http_error(
                    &mut tls_stream,
                    StatusCode::MISDIRECTED_REQUEST,
                    "no mapping for host",
                )
                .await;
                state.metrics.record_status(421, &host);
                return;
            }
        };

        // Resolve the backend address (same logic as normal path, but
        // no header injection, no policy checks).
        let backend_addr = if let Some(ref url) = mapping.backend_url {
            url.replace("http://", "").replace("https://", "")
        } else {
            match state.backends.pick(&mapping.service) {
                Some(addr) => addr,
                None => {
                    let _ = write_http_error(
                        &mut tls_stream,
                        StatusCode::BAD_GATEWAY,
                        "no backend available",
                    )
                    .await;
                    state.metrics.record_status(502, &host);
                    return;
                }
            }
        };

        // Connect to the backend and forward the request as-is (no
        // injected headers - ACME challenge is unauthenticated).
        let upstream_config = UpstreamTlsConfig {
            mode: state.backend_tls_mode,
            connect_timeout: state.connect_timeout,
            mtls_cert_path: state.mtls_cert_path.clone(),
            mtls_key_path: state.mtls_key_path.clone(),
        };

        // pool-first acquisition (warm conn skips the handshake).
        let (upstream, established_fresh) = match upstream_idle_pool::acquire(
            &state.upstream_pool,
            &backend_addr,
            &host,
            &upstream_config,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    %client_addr,
                    host = %host,
                    backend = %backend_addr,
                    error = %e,
                    "proxy L7: ACME challenge - failed to connect to backend"
                );
                let _ = write_http_error(
                    &mut tls_stream,
                    StatusCode::BAD_GATEWAY,
                    "backend unavailable",
                )
                .await;
                state.metrics.record_status(502, &host);
                return;
            }
        };
        state.metrics.record_upstream_connect(established_fresh);

        // Forward the original request bytes (no header injection) and
        // pipe the response back.
        let request_bytes = build_http_request_bytes(&parsed, &parsed.headers);
        let status = forward_raw_request(
            upstream,
            &request_bytes,
            &mut tls_stream,
            &state,
            &host,
            &backend_addr,
        )
        .await;
        let latency_ms = request_start.elapsed().as_millis() as u64;
        state.metrics.record_status(status, &host);
        state.metrics.record_latency(latency_ms, &host);
        return;
    }

    // 5. Look up the mapping for non-ACME requests.
    let mapping = match state.mapping_cache.get(&host) {
        Some(m) => m,
        None => {
            tracing::debug!(
                %client_addr,
                host = %host,
                "proxy L7: no mapping for host - returning 421"
            );
            let _ = write_http_error(
                &mut tls_stream,
                StatusCode::MISDIRECTED_REQUEST,
                "no mapping for host",
            )
            .await;
            state.metrics.record_status(421, &host);
            return;
        }
    };

    // 5. Run the policy engine.
    let outcome = state.policy_engine.evaluate(
        &client_addr.ip(),
        &host,
        &parsed.method,
        &parsed.uri,
        &parsed.headers,
        &parsed.body,
    );
    match outcome {
        PolicyOutcome::Block(status, msg) => {
            let _ = write_http_error(&mut tls_stream, status, msg).await;
            state.metrics.record_status(status.as_u16(), &host);
            state.metrics.record_policy_block();
            return;
        }
        PolicyOutcome::Allow => {}
    }

    // 6. Inject X-Sentin8-* tenant context headers.
    let mut injected_headers =
        header_injector::inject_tenant_headers(&parsed.headers, &mapping, &host);
    // forward the mTLS client certificate (base64 DER) so the
    // backend's mTLS consumer can verify it - never a client-supplied value
    // (stripped by the injector), always the certificate this connection
    // terminated. Absent when no client certificate was presented.
    if let Some(cert) = header_injector::extract_client_cert_header(&tls_stream) {
        if let Ok(value) = axum::http::HeaderValue::from_str(&cert) {
            if let Ok(name) = axum::http::HeaderName::from_bytes(b"x-sentin8-client-cert") {
                injected_headers.insert(name, value);
            }
        }
    }

    // 7. Resolve the backend address.
    let backend_addr = if let Some(ref url) = mapping.backend_url {
        url.replace("http://", "").replace("https://", "")
    } else {
        match state.backends.pick(&mapping.service) {
            Some(addr) => addr,
            None => {
                tracing::warn!(
                    %client_addr,
                    host = %host,
                    service = %mapping.service,
                    "proxy L7: no Active instances - returning 502"
                );
                let _ = write_http_error(
                    &mut tls_stream,
                    StatusCode::BAD_GATEWAY,
                    "no backend available",
                )
                .await;
                state.metrics.record_status(502, &host);
                return;
            }
        }
    };

    // 8. Connect to the backend - pool-first : a warm pooled
    // connection skips the TCP + PQ TLS handshake entirely; a miss
    // connects fresh (and is refilled for the next request). A stale
    // pooled connection (backend respawned) fails transport once; the
    // retry-once below rewrites it to a fresh connect so respawns
    // surface as a single retried request, never repeated 502s.
    let upstream_config = UpstreamTlsConfig {
        mode: state.backend_tls_mode,
        connect_timeout: state.connect_timeout,
        mtls_cert_path: state.mtls_cert_path.clone(),
        mtls_key_path: state.mtls_key_path.clone(),
    };

    let upstream = match upstream_idle_pool::acquire(
        &state.upstream_pool,
        &backend_addr,
        &host,
        &upstream_config,
    )
    .await
    {
        Ok((c, established_fresh)) => {
            state.metrics.record_upstream_connect(established_fresh);
            c
        }
        Err(e) => {
            tracing::warn!(
                %client_addr,
                host = %host,
                backend = %backend_addr,
                error = %e,
                "proxy L7: failed to connect to backend"
            );
            // Try fail-over for non-app backends.
            if mapping.backend_url.is_none() {
                state.backends.mark_suspect(&mapping.service, &backend_addr);
                // Try one more instance.
                if let Some(alt_addr) = state.backends.pick(&mapping.service) {
                    if let Ok(alt_upstream) =
                        upstream_tls::connect(&alt_addr, &host, &upstream_config).await
                    {
                        state.metrics.record_upstream_connect(true);
                        // Forward to alternate backend.
                        let outcome = forward_request_once(
                            alt_upstream,
                            &parsed,
                            &injected_headers,
                            &mut tls_stream,
                            &state.metrics,
                            &host,
                            &state.upstream_pool,
                            &alt_addr,
                        )
                        .await;
                        if let ForwardOutcome::Done { status, .. } = outcome {
                            record_completion(&state.metrics, &host, status, request_start);
                        } else {
                            state.metrics.record_status(502, &host);
                        }
                        return;
                    }
                }
            }
            let _ = write_http_error(
                &mut tls_stream,
                StatusCode::BAD_GATEWAY,
                "backend unavailable",
            )
            .await;
            state.metrics.record_status(502, &host);
            return;
        }
    };

    // 9. Forward the request to the backend and pipe the response back.
    // a FIRST transport error on this (possibly pooled) upstream
    // is treated as a stale connection - discard and retry ONCE on a
    // fresh connect. The retry metric keeps stale-conn artifacts
    // observable without surfacing them as 502s.
    let outcome = forward_request_once(
        upstream,
        &parsed,
        &injected_headers,
        &mut tls_stream,
        &state.metrics,
        &host,
        &state.upstream_pool,
        &backend_addr,
    )
    .await;
    let status = match outcome {
        ForwardOutcome::Done { status, .. } => status,
        ForwardOutcome::Stale(stale_err) => {
            tracing::debug!(
                %client_addr,
                %host,
                error = %stale_err,
 "proxy L7: upstream transport error - retrying once on a fresh connection "
            );
            state.metrics.record_upstream_stale_retry();
            match upstream_tls::connect(&backend_addr, &host, &upstream_config).await {
                Ok(retry_upstream) => {
                    state.metrics.record_upstream_connect(true);
                    match forward_request_once(
                        retry_upstream,
                        &parsed,
                        &injected_headers,
                        &mut tls_stream,
                        &state.metrics,
                        &host,
                        &state.upstream_pool,
                        &backend_addr,
                    )
                    .await
                    {
                        ForwardOutcome::Done { status, .. } => status,
                        ForwardOutcome::Stale(_) => {
                            let _ = write_http_error(
                                &mut tls_stream,
                                StatusCode::BAD_GATEWAY,
                                "backend write failed",
                            )
                            .await;
                            state.metrics.record_status(502, &host);
                            502
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(%host, error = %e, "proxy L7: fresh retry connect failed");
                    let _ = write_http_error(
                        &mut tls_stream,
                        StatusCode::BAD_GATEWAY,
                        "backend unavailable",
                    )
                    .await;
                    state.metrics.record_status(502, &host);
                    502
                }
            }
        }
    };
    record_completion(&state.metrics, &host, status, request_start);
}

/// Result of one forward + pipe cycle.
enum ForwardOutcome {
    /// Response fully delivered; `status` is the backend's status. A
    /// REUSABLE upstream was already returned to the pool by
    /// [`pipe_response`] - the caller never touches the socket again.
    Done { status: u16 },
    /// Transport failed before any response byte reached the client -
    /// the caller retries once on a fresh connection .
    Stale(String),
}

/// retryable forward: a transport failure **before any response
/// byte reaches the client** (the request-write phase) returns
/// [`ForwardOutcome::Stale`] instead of writing a 502 - the caller
/// retries once on a fresh connection. Once the response pipe has
/// STARTED, the request is committed to the client: never retried (a
/// second send would double-deliver).
#[allow(clippy::too_many_arguments)]
async fn forward_request_once(
    mut upstream: upstream_tls::UpstreamConnection,
    parsed: &ParsedRequest,
    injected_headers: &axum::http::HeaderMap,
    client_tls: &mut tokio_rustls::server::TlsStream<TcpStream>,
    metrics: &L7Metrics,
    host: &str,
    pool: &UpstreamPool,
    backend_addr: &str,
) -> ForwardOutcome {
    let request_bytes = build_http_request_bytes(parsed, injected_headers);

    // Send the request (the stale-retryable phase - nothing reached the
    // client yet); then hand the WHOLE upstream to pipe_response, which
    // matches the variant to recover the concrete stream on reuse.
    match &mut upstream {
        upstream_tls::UpstreamConnection::Plain(backend) => {
            if let Err(e) = backend.write_all(&request_bytes).await {
                return ForwardOutcome::Stale(format!("upstream write failed: {e}"));
            }
        }
        upstream_tls::UpstreamConnection::Tls(backend) => {
            if let Err(e) = backend.write_all(&request_bytes).await {
                return ForwardOutcome::Stale(format!("upstream write failed: {e}"));
            }
        }
    }
    pipe_response(upstream, client_tls, metrics, host, pool, backend_addr).await
}

/// Read the HTTP response from the backend and pipe it to the client's
/// TLS stream, WITH ENVELOPE FRAMING .
///
/// Buffers until the header block (\r\n\r\n) is complete, parses the
/// status + framing header, and streams the body. When the response is
/// Content-Length- or chunked-framed AND the cycle completes healthy,
/// the upstream is returned to the pool for the NEXT request (HTTP/1.1
/// keep-alive - the PQ handshake amortizes across requests).
/// `Connection: close` or close-delimited bodies (HTTP/1.0, no length)
/// end at EOF: the connection is consumed, never pooled.
///
/// Split into a non-generic [`pipe_response`] (matches on the
/// `UpstreamConnection` enum, puts reusable streams back) and a generic
/// [`pipe_framed`] (shared framing logic for Plain/TLS streams) - the
/// pool needs the CONCRETE stream type to hand off, which a generic `R`
/// cannot name.
///
/// stale class: an EOF/read error BEFORE any response byte
/// reaches the client returns [`ForwardOutcome::Stale`] - the caller
/// retries once on a fresh connection. Once bytes reached the client
/// the request is committed: never retried (double-delivery).
async fn pipe_response(
    backend: upstream_tls::UpstreamConnection,
    client_tls: &mut tokio_rustls::server::TlsStream<TcpStream>,
    metrics: &L7Metrics,
    host: &str,
    pool: &UpstreamPool,
    backend_addr: &str,
) -> ForwardOutcome {
    match backend {
        upstream_tls::UpstreamConnection::Plain(s) => {
            let returned = pipe_framed(s, client_tls, metrics, host, backend_addr).await;
            if returned.reusable {
                // reusable ⇒ stream is recovered by the pipe's contract.
                let s = returned
                    .stream
                    .expect("reusable pipe always recovers the stream");
                pool.put(
                    backend_addr,
                    host,
                    upstream_tls::UpstreamConnection::Plain(s),
                );
            }
            returned.outcome
        }
        upstream_tls::UpstreamConnection::Tls(s) => {
            let returned = pipe_framed(s, client_tls, metrics, host, backend_addr).await;
            if returned.reusable {
                // reusable ⇒ stream recovered by the pipe's contract.
                let s = returned
                    .stream
                    .expect("reusable pipe always recovers the stream");
                pool.put(backend_addr, host, upstream_tls::UpstreamConnection::Tls(s));
            }
            returned.outcome
        }
    }
}

/// The result of the generic framed pipe: the client-facing outcome plus
/// the stream (movable only when reusable).
struct PipedStream<S> {
    outcome: ForwardOutcome,
    reusable: bool,
    /// Recovered only when `reusable` - `None` when consumed (stale /
    /// close-delimited / mid-pipe failure).
    stream: Option<S>,
}

impl<S> PipedStream<S> {
    /// The client-facing outcome (consuming view for the caller).
    #[allow(dead_code)]
    fn into_outcome(self) -> ForwardOutcome {
        self.outcome
    }
}

/// Generic framed pipe over a concrete backend stream.
async fn pipe_framed<S: AsyncReadExt + Unpin>(
    mut backend: S,
    client_tls: &mut tokio_rustls::server::TlsStream<TcpStream>,
    _metrics: &L7Metrics,
    _host: &str,
    _backend_addr: &str,
) -> PipedStream<S> {
    const HEADER_CAP: usize = 64 * 1024;
    let mut header_buf: Vec<u8> = Vec::with_capacity(8192);
    let mut status_code = 502u16;

    // 1. Read until end of the header block (bounded).
    let header_end = loop {
        let mut tmp = [0u8; 4096];
        match backend.read(&mut tmp).await {
            Ok(0) => {
                // EOF before headers - stale/crashed backend. The client
                // received NOTHING (safe retry on a fresh connection).
                return PipedStream {
                    outcome: ForwardOutcome::Stale("backend closed before response".into()),

                    stream: None,
                    reusable: false,
                };
            }
            Ok(n) => {
                header_buf.extend_from_slice(&tmp[..n]);
            }
            Err(e) => {
                // Headers not yet flushed to the client - retryable.
                return PipedStream {
                    outcome: ForwardOutcome::Stale(format!("backend read error: {e}")),

                    stream: None,
                    reusable: false,
                };
            }
        }
        if header_buf.len() > HEADER_CAP {
            return PipedStream {
                outcome: ForwardOutcome::Stale("response headers too large".into()),

                stream: None,
                reusable: false,
            };
        }
        if let Some(pos) = find_header_end(&header_buf) {
            break pos;
        }
    };

    let header_str = String::from_utf8_lossy(&header_buf[..header_end]);
    if let Some(status) = parse_http_status(&header_buf) {
        status_code = status;
    }
    let framing = detect_framing(&header_str);
    let body = header_buf[header_end + 4..].to_vec();

    // Headers + any body bytes already read → client.
    if client_tls
        .write_all(&header_buf[..header_end + 4])
        .await
        .is_err()
    {
        return PipedStream {
            outcome: ForwardOutcome::Done {
                status: status_code,
            },

            stream: None,
            reusable: false,
        };
    }

    match framing {
        // ── Content-Length framing: exact body length, poolable ──
        Ok(Some(len)) => {
            let delivered = body.len() as u64;
            if !body.is_empty() && client_tls.write_all(&body).await.is_err() {
                return PipedStream {
                    outcome: ForwardOutcome::Done {
                        status: status_code,
                    },
                    stream: None,
                    reusable: false,
                };
            }
            let mut remaining = len.saturating_sub(delivered);
            let mut buf = vec![0u8; 16384];
            while remaining > 0 {
                let want = buf.len().min(remaining as usize);
                match backend.read(&mut buf[..want]).await {
                    Ok(0) => {
                        // Truncated body - connection state is garbage.
                        let _ = client_tls.flush().await;
                        return PipedStream {
                            outcome: ForwardOutcome::Done {
                                status: status_code,
                            },

                            stream: None,
                            reusable: false,
                        };
                    }
                    Ok(n) => {
                        if client_tls.write_all(&buf[..n]).await.is_err() {
                            return PipedStream {
                                outcome: ForwardOutcome::Done {
                                    status: status_code,
                                },

                                stream: None,
                                reusable: false,
                            };
                        }
                        remaining -= n as u64;
                    }
                    Err(_) => {
                        return PipedStream {
                            outcome: ForwardOutcome::Done {
                                status: status_code,
                            },

                            stream: None,
                            reusable: false,
                        };
                    }
                }
            }
            let _ = client_tls.flush().await;
            // keep-alive: framed cycle complete - the stream is
            // RECOVERED (pipe_response moves it into the pool).
            PipedStream {
                outcome: ForwardOutcome::Done {
                    status: status_code,
                },
                reusable: true,
                stream: Some(backend),
            }
        }
        // ── Chunked transfer-encoding: stream until the 0-size
        //    terminator, then poolable (connection kept open). ──
        Ok(None) => {
            let mut src: Vec<u8> = body;
            let mut buf = vec![0u8; 16384];
            let chunked_done = loop {
                if find_chunked_terminator(&src).is_some() {
                    break true;
                }
                match backend.read(&mut buf).await {
                    Ok(0) => break false, // EOF before terminator - not poolable
                    Ok(n) => src.extend_from_slice(&buf[..n]),
                    Err(_) => break false,
                }
            };
            let _ = client_tls.write_all(&src).await;
            let _ = client_tls.flush().await;
            PipedStream {
                outcome: ForwardOutcome::Done {
                    status: status_code,
                },
                reusable: chunked_done,
                stream: chunked_done.then_some(backend),
            }
        }
        // ── Close-delimited (no framing header): pipe to EOF, never pool.
        Err(_) => {
            if !body.is_empty() {
                let _ = client_tls.write_all(&body).await;
                let _ = client_tls.flush().await;
            }
            let mut buf = vec![0u8; 16384];
            loop {
                match backend.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Err(e) = client_tls.write_all(&buf[..n]).await {
                            tracing::debug!(error = %e, "proxy L7: client write failed");
                            break;
                        }
                        let _ = client_tls.flush().await;
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "proxy L7: backend read error");
                        break;
                    }
                }
            }
            PipedStream {
                outcome: ForwardOutcome::Done {
                    status: status_code,
                },

                stream: None,
                reusable: false,
            }
        }
    }
}

/// Response framing of the header block: `Ok(Some(len))` =
/// Content-Length, `Ok(None)` = chunked, `Err(())` = close-delimited
/// (no framing header / `Connection: close`).
fn detect_framing(headers: &str) -> Result<Option<u64>, ()> {
    let mut chunked = false;
    let mut content_length: Option<u64> = None;
    let mut connection_close = false;
    for line in headers.lines().skip(1) {
        let lower = line.to_ascii_lowercase();
        if let Some(val) = lower.strip_prefix("transfer-encoding:") {
            if val.trim().contains("chunked") {
                chunked = true;
            }
        } else if let Some(val) = lower.strip_prefix("content-length:") {
            content_length = val.trim().parse().ok();
        } else if let Some(val) = lower.strip_prefix("connection:") {
            if val.trim().eq_ignore_ascii_case("close") {
                connection_close = true;
            }
        }
    }
    if connection_close {
        return Err(());
    }
    if chunked {
        return Ok(None);
    }
    Ok(content_length)
}

/// Find the 0-length chunk terminator (`0\r?\n\r?\n` end sequence) -
/// presence means the chunked body completed and the connection is
/// reusable. Bounded scan: the terminator can never appear past the
/// final CRLF CRLF.
fn find_chunked_terminator(buf: &[u8]) -> Option<usize> {
    let len = buf.len();
    if len < 5 {
        return None;
    }
    // The terminal sequence is "0\r\n\r\n" (no trailers supported -
    // platform backends do not emit trailers).
    if &buf[len - 5..] == b"0\r\n\r\n" {
        return Some(len - 5);
    }
    // Tolerate bare-LF backends: "0\n\n".
    if &buf[len - 3..] == b"0\n\n" {
        return Some(len - 3);
    }
    None
}

/// Record completion metrics for a request.
fn record_completion(metrics: &L7Metrics, host: &str, status: u16, start: Instant) {
    let latency_ms = start.elapsed().as_millis() as u64;
    metrics.record_status(status, host);
    metrics.record_latency(latency_ms, host);
}

/// Check if a URI path is an ACME HTTP-01 challenge path.
///
/// Paths matching `/.well-known/acme-challenge/*` bypass the entire L7
/// policy engine and are forwarded directly to the backend. The backend's
/// sentin8-tls serves the challenge token.
///
/// Design:
fn is_acme_challenge(uri: &str) -> bool {
    // Strip query string if present.
    let path = uri.split('?').next().unwrap_or(uri);
    path.starts_with("/.well-known/acme-challenge/")
}

/// Forward raw HTTP request bytes to the backend and pipe the response back.
///
/// This is used for ACME challenge passthrough - the original request
/// is forwarded as-is (no header injection, no policy checks). One-shot
/// cycle: the upstream is NEVER pooled (the challenge must not warm a
/// reusable session outside the request path) - the pool passed is the
/// shared one, but a close-delimited pipe discards the conn anyway; the
/// framed path putting back is harmless for the one-off backend.
async fn forward_raw_request(
    mut upstream: upstream_tls::UpstreamConnection,
    request_bytes: &[u8],
    client_tls: &mut tokio_rustls::server::TlsStream<TcpStream>,
    state: &L7State,
    host: &str,
    backend_addr: &str,
) -> u16 {
    match &mut upstream {
        upstream_tls::UpstreamConnection::Plain(backend) => {
            if let Err(e) = backend.write_all(request_bytes).await {
                tracing::warn!(error = %e, "proxy L7: ACME challenge - backend write failed");
                return 502;
            }
            let _ = backend.flush().await;
        }
        upstream_tls::UpstreamConnection::Tls(backend) => {
            if let Err(e) = backend.write_all(request_bytes).await {
                tracing::warn!(error = %e, "proxy L7: ACME challenge - backend write failed");
                return 502;
            }
            let _ = backend.flush().await;
        }
    }
    let outcome = pipe_response(
        upstream,
        client_tls,
        &state.metrics,
        host,
        &state.upstream_pool,
        backend_addr,
    )
    .await;
    match outcome {
        ForwardOutcome::Done { status, .. } => status,
        ForwardOutcome::Stale(e) => {
            tracing::debug!(error = %e, "proxy L7: ACME challenge - backend closed before response");
            502
        }
    }
}

// ── HTTP parsing helpers ─────────────────────────────────────────────────

/// A parsed HTTP request.
/// Request body for parsed.
pub struct ParsedRequest {
    /// The method.
    pub method: Method,
    /// The URI.
    pub uri: String,
    /// The headers.
    pub headers: axum::http::HeaderMap,
    /// The body.
    pub body: Vec<u8>,
    /// The raw request data (for re-sending to backend in offload mode).
    /// The raw.
    pub _raw: Vec<u8>,
}

/// Read an HTTP request from a stream. Reads headers (up to 64KB) and
/// a limited body (up to 10MB).
async fn read_http_request<R: AsyncReadExt + Unpin>(
    stream: &mut R,
) -> Result<Vec<u8>, std::io::Error> {
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];

    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            if buf.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed before headers",
                ));
            }
            break;
        }
        buf.extend_from_slice(&tmp[..n]);

        // Check for end of headers (\r\n\r\n).
        if let Some(header_end) = find_header_end(&buf) {
            // Check if we have a body to read.
            let header_str = String::from_utf8_lossy(&buf[..header_end]);
            let content_length = extract_content_length(&header_str);

            let body_start = header_end + 4;
            let current_body = buf.len() - body_start;

            if content_length > current_body {
                // Read remaining body.
                let remaining = content_length - current_body;
                let mut body_buf = vec![0u8; remaining];
                let mut read = 0;
                while read < remaining {
                    let n = stream.read(&mut body_buf[read..]).await?;
                    if n == 0 {
                        break;
                    }
                    read += n;
                }
                buf.extend_from_slice(&body_buf[..read]);
            }
            break;
        }

        // Safety limit: don't read more than 64KB of headers.
        if buf.len() > 65536 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "headers too large",
            ));
        }
    }

    Ok(buf)
}

/// Find the end of HTTP headers (\r\n\r\n).
fn find_header_end(buf: &[u8]) -> Option<usize> {
    for i in 0..buf.len().saturating_sub(3) {
        if &buf[i..i + 4] == b"\r\n\r\n" {
            return Some(i);
        }
    }
    None
}

/// Extract Content-Length from header string.
fn extract_content_length(headers: &str) -> usize {
    for line in headers.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(val) = lower.strip_prefix("content-length:") {
            return val.trim().parse().unwrap_or(0);
        }
    }
    0
}

/// Parse raw HTTP request bytes into method, URI, headers, and body.
fn parse_http_request(data: &[u8]) -> Option<ParsedRequest> {
    let header_end = find_header_end(data)?;
    let header_str = std::str::from_utf8(&data[..header_end]).ok()?;
    let body = data[header_end + 4..].to_vec();

    let mut lines = header_str.lines();
    let request_line = lines.next()?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }

    let method = Method::from_bytes(parts[0].as_bytes()).ok()?;
    let uri = parts[1].to_string();

    let mut headers = axum::http::HeaderMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(": ") {
            if let (Ok(hn), Ok(hv)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                // APPEND (never insert): repeated header lines are lawful
                // and semantically LOAD-BEARING - the DPoP proof header
                // pair (RFC 9449 §4.1) must reach the backend as TWO
                // lines so the RS can reject the two-proof request shape;
                // insert() would collapse the duplicates.
                headers.append(hn, hv);
            }
        }
    }

    // Inbound wire observability (DESIGN §4.4 header transparency): a
    // duplicated DPoP proof header means the client is attempting the
    // RFC 9449 §4.1 negative shape - log it so operator traces can tell
    // client-side collapse from forwarding defects.
    let dpop_count = headers.get_all("dpop").iter().count();
    if dpop_count > 1 {
        tracing::warn!(
            dpop_headers = dpop_count,
            uri = %uri,
            "request carries multiple DPoP proof headers - forwarding all of them"
        );
    }

    Some(ParsedRequest {
        method,
        uri,
        headers,
        body,
        _raw: data.to_vec(),
    })
}

/// Build HTTP request bytes with injected headers.
///
/// Reconstructs the request line + injected headers + body.
fn build_http_request_bytes(
    parsed: &ParsedRequest,
    injected_headers: &axum::http::HeaderMap,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8192 + parsed.body.len());

    // Request line.
    buf.extend_from_slice(parsed.method.as_str().as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(parsed.uri.as_bytes());
    buf.extend_from_slice(b" HTTP/1.1\r\n");

    // Headers.
    for (name, value) in injected_headers.iter() {
        buf.extend_from_slice(name.as_str().as_bytes());
        buf.extend_from_slice(b": ");
        buf.extend_from_slice(value.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }

    // End of headers.
    buf.extend_from_slice(b"\r\n");

    // Body.
    buf.extend_from_slice(&parsed.body);

    buf
}

/// Parse the HTTP status code from the first chunk of a response.
fn parse_http_status(data: &[u8]) -> Option<u16> {
    let str = std::str::from_utf8(data).ok()?;
    let first_line = str.lines().next()?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() >= 2 {
        parts[1].parse().ok()
    } else {
        None
    }
}

/// Write a simple HTTP error response to the client's TLS stream.
async fn write_http_error<W: AsyncWriteExt + Unpin>(
    stream: &mut W,
    status: StatusCode,
    message: &str,
) -> Result<(), std::io::Error> {
    let body = format!(
        "{{\"error\":\"{}\",\"status\":{}}}\n",
        message,
        status.as_u16()
    );
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status.as_u16(),
        status.canonical_reason().unwrap_or("Error"),
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_header_end_finds() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\nbody";
        assert_eq!(find_header_end(data), Some(33));
    }

    #[test]
    fn find_header_end_not_found() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n";
        assert_eq!(find_header_end(data), None);
    }

    #[test]
    fn parse_http_request_parses() {
        let data =
            b"GET /api/v1/users HTTP/1.1\r\nHost: example.com\r\nAccept: application/json\r\n\r\n";
        let parsed = parse_http_request(data).unwrap();
        assert_eq!(parsed.method, Method::GET);
        assert_eq!(parsed.uri, "/api/v1/users");
        assert_eq!(
            parsed.headers.get("host").unwrap().to_str().unwrap(),
            "example.com"
        );
        assert!(parsed.body.is_empty());
    }

    #[test]
    fn parse_http_request_with_body() {
        let data = b"POST /api/v1/users HTTP/1.1\r\nHost: example.com\r\nContent-Length: 13\r\n\r\n{\"name\":\"foo\"}";
        let parsed = parse_http_request(data).unwrap();
        assert_eq!(parsed.method, Method::POST);
        assert_eq!(parsed.body, b"{\"name\":\"foo\"}");
    }

    #[test]
    fn parse_http_status_parses() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}";
        assert_eq!(parse_http_status(data), Some(200));
    }

    #[test]
    fn parse_http_status_error() {
        let data = b"HTTP/1.1 502 Bad Gateway\r\n\r\n";
        assert_eq!(parse_http_status(data), Some(502));
    }

    #[test]
    fn build_http_request_bytes_roundtrip() {
        let data = b"GET /api/v1/users HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let parsed = parse_http_request(data).unwrap();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("example.com"));
        headers.insert("x-sentin8-env-id", HeaderValue::from_static("test-env"));
        let bytes = build_http_request_bytes(&parsed, &headers);
        let str = String::from_utf8(bytes).unwrap();
        assert!(str.contains("GET /api/v1/users HTTP/1.1"));
        assert!(str.contains("host: example.com"));
        assert!(str.contains("x-sentin8-env-id: test-env"));
    }

    #[test]
    fn extract_content_length_parses() {
        let headers = "GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 42\r\n";
        assert_eq!(extract_content_length(headers), 42);
    }

    #[test]
    fn extract_content_length_missing() {
        let headers = "GET / HTTP/1.1\r\nHost: example.com\r\n";
        assert_eq!(extract_content_length(headers), 0);
    }

    #[test]
    fn is_acme_challenge_match() {
        assert!(is_acme_challenge("/.well-known/acme-challenge/abc123"));
        assert!(is_acme_challenge(
            "/.well-known/acme-challenge/very-long-token-here-456"
        ));
    }

    #[test]
    fn is_acme_challenge_no_match() {
        assert!(!is_acme_challenge("/api/v1/users"));
        assert!(!is_acme_challenge("/.well-known/openid-configuration"));
        assert!(!is_acme_challenge("/health"));
        assert!(!is_acme_challenge("/"));
    }

    #[test]
    fn is_acme_challenge_strips_query() {
        // Query string should be stripped before matching.
        assert!(is_acme_challenge("/.well-known/acme-challenge/abc?foo=bar"));
        assert!(!is_acme_challenge(
            "/api/v1/users?path=/.well-known/acme-challenge/fake"
        ));
    }

    #[test]
    fn l7_gauge_pairs_entry_and_exit() {
        // The in-flight gauge pairs with the RAII guard - every
        // enter() is matched by exactly one drop.
        let gauge = std::sync::Arc::new(L7ConnectionGauge::new());
        assert_eq!(gauge.active_connections(), 0);
        let g1 = gauge.enter();
        let g2 = gauge.enter();
        assert_eq!(gauge.active_connections(), 2);
        drop(g1);
        assert_eq!(gauge.active_connections(), 1);
        drop(g2);
        assert_eq!(gauge.active_connections(), 0);
    }

    #[test]
    fn l7_gauge_saturates_at_zero() {
        // A defensive double-exit (impossible via the guard) must not wrap.
        let gauge = L7ConnectionGauge::new();
        gauge.exit();
        assert_eq!(gauge.active_connections(), 0);
    }
}
