// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Proxy
// SPDX-License-Identifier: Apache-2.0

//! L7 traffic metrics - HTTP status codes, request latency, policy blocks.
//!
//! These metrics are only available for external (L7) traffic. Internal
//! (L4) traffic uses the connection-level metrics in `server.rs`.
//!
//! Design:

use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

/// L7 metrics counters - thread-safe, in-memory.
#[derive(Clone)]
pub struct L7Metrics {
    inner: Arc<Mutex<L7MetricsInner>>,
}

struct L7MetricsInner {
    /// Per-host status code counts: (host, status_code) → count.
    status_counts: HashMap<(String, u16), u64>,
    /// Per-host latency sums: host → (total_ms, count).
    latency: HashMap<String, (u64, u64)>,
    /// Total TLS handshake errors.
    handshake_errors: u64,
    /// Total policy blocks (WAF, rate limit, path ACL).
    policy_blocks: u64,
    /// requests served on a WARM pooled upstream (no
    /// TCP+TLS setup paid).
    upstream_warm: u64,
    /// requests that paid a fresh upstream connect
    /// (pool miss - includes the PQ handshake).
    upstream_cold: u64,
    /// stale pooled connections discarded + retried fresh.
    upstream_stale_retries: u64,
}

impl L7Metrics {
    /// Create an empty collector.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(L7MetricsInner {
                status_counts: HashMap::new(),
                latency: HashMap::new(),
                handshake_errors: 0,
                policy_blocks: 0,
                upstream_warm: 0,
                upstream_cold: 0,
                upstream_stale_retries: 0,
            })),
        }
    }

    /// Record an HTTP status code for a host.
    pub fn record_status(&self, status: u16, host: &str) {
        let mut inner = self.inner.lock();
        *inner
            .status_counts
            .entry((host.to_string(), status))
            .or_insert(0) += 1;
    }

    /// Record request latency in milliseconds for a host.
    pub fn record_latency(&self, latency_ms: u64, host: &str) {
        let mut inner = self.inner.lock();
        let entry = inner.latency.entry(host.to_string()).or_insert((0, 0));
        entry.0 += latency_ms;
        entry.1 += 1;
    }

    /// Record a TLS handshake error.
    pub fn record_handshake_error(&self) {
        let mut inner = self.inner.lock();
        inner.handshake_errors += 1;
    }

    /// Record a policy block (WAF, rate limit, etc.).
    pub fn record_policy_block(&self) {
        let mut inner = self.inner.lock();
        inner.policy_blocks += 1;
    }

    /// count one upstream acquisition - warm pooled vs cold
    /// fresh connect (the cold path pays TCP + PQ TLS handshake).
    pub fn record_upstream_connect(&self, established_fresh: bool) {
        let mut inner = self.inner.lock();
        if established_fresh {
            inner.upstream_cold += 1;
        } else {
            inner.upstream_warm += 1;
        }
    }

    /// count one stale pooled upstream discarded + retried
    /// fresh (backend respawned under a pooled socket).
    pub fn record_upstream_stale_retry(&self) {
        let mut inner = self.inner.lock();
        inner.upstream_stale_retries += 1;
    }

    /// Drain and return all accumulated metrics.
    pub fn drain(&self) -> L7MetricsSnapshot {
        let mut inner = self.inner.lock();
        L7MetricsSnapshot {
            status_counts: std::mem::take(&mut inner.status_counts),
            latency: std::mem::take(&mut inner.latency),
            handshake_errors: inner.handshake_errors,
            policy_blocks: inner.policy_blocks,
            upstream_warm: inner.upstream_warm,
            upstream_cold: inner.upstream_cold,
            upstream_stale_retries: inner.upstream_stale_retries,
        }
    }
}

impl Default for L7Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// A point-in-time snapshot of L7 metrics.
pub struct L7MetricsSnapshot {
    /// Request counts per (service, status code).
    pub status_counts: HashMap<(String, u16), u64>,
    /// Latency (count, total ms) per service.
    pub latency: HashMap<String, (u64, u64)>,
    /// TLS handshake failures observed.
    pub handshake_errors: u64,
    /// Requests blocked by route policy.
    pub policy_blocks: u64,
    /// requests served on a warm pooled upstream.
    pub upstream_warm: u64,
    /// requests that paid a fresh upstream connect.
    pub upstream_cold: u64,
    /// stale pooled upstreams discarded + retried fresh.
    pub upstream_stale_retries: u64,
}

/// Spawn a flush loop that publishes L7 metrics to Valkey pub/sub
/// channel `stat:metrics:tls` every `flush_interval_s` seconds.
pub fn spawn_l7_metrics_flush(metrics: L7Metrics, valkey_url: String, flush_interval_s: u64) {
    if valkey_url.is_empty() {
        tracing::info!("proxy: VALKEY_URL not set, L7 metrics flush disabled");
        return;
    }
    let interval = std::time::Duration::from_secs(flush_interval_s.max(1));
    tokio::spawn(async move {
        let conn = match sentin8::middleware::valkey_client(&valkey_url, "sentin8:proxy").await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "proxy: failed to open Valkey client for L7 metrics");
                return;
            }
        };

        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // skip first tick
        loop {
            ticker.tick().await;
            let snapshot = metrics.drain();

            let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
            let window = format!("{}s", flush_interval_s.max(1));

            let mut http_metrics = serde_json::Map::new();

            // Status code metrics.
            for ((host, status), count) in &snapshot.status_counts {
                http_metrics.insert(
                    format!("proxy.http.external→{}.status_{}", host, status),
                    serde_json::json!(count),
                );
            }

            // Latency metrics (average over the window).
            for (host, (total_ms, count)) in &snapshot.latency {
                if *count > 0 {
                    let avg_ms = total_ms / count;
                    http_metrics.insert(
                        format!("proxy.http.external→{}.latency_ms", host),
                        serde_json::json!(avg_ms),
                    );
                }
            }

            // Handshake errors.
            if snapshot.handshake_errors > 0 {
                http_metrics.insert(
                    "proxy.http.external→proxy.handshake_errors".to_string(),
                    serde_json::json!(snapshot.handshake_errors),
                );
            }

            // Policy blocks.
            if snapshot.policy_blocks > 0 {
                http_metrics.insert(
                    "proxy.http.external→proxy.policy_blocks".to_string(),
                    serde_json::json!(snapshot.policy_blocks),
                );
            }

            // upstream pool counters (window counts).
            if snapshot.upstream_warm > 0 {
                http_metrics.insert(
                    "proxy.http.external→proxy.upstream_warm".to_string(),
                    serde_json::json!(snapshot.upstream_warm),
                );
            }
            if snapshot.upstream_cold > 0 {
                http_metrics.insert(
                    "proxy.http.external→proxy.upstream_cold".to_string(),
                    serde_json::json!(snapshot.upstream_cold),
                );
            }
            if snapshot.upstream_stale_retries > 0 {
                http_metrics.insert(
                    "proxy.http.external→proxy.upstream_stale_retries".to_string(),
                    serde_json::json!(snapshot.upstream_stale_retries),
                );
            }

            if http_metrics.is_empty() {
                continue;
            }

            let payload = serde_json::json!({
                "ts": ts,
                "source": "proxy",
                "window": window,
                "org_id": null,
                "env_id": null,
                "metrics": http_metrics,
            });
            let payload_str = serde_json::to_string(&payload).unwrap_or_default();

            use glide::AsyncCommands as _;
            let _: Result<usize, _> = conn
                .publish::<_, _, usize>("stat:metrics:tls", payload_str.as_str())
                .await;

            tracing::debug!("proxy: published L7 metrics");
        }
    });
}
