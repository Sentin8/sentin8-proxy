// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Proxy
// SPDX-License-Identifier: Apache-2.0

//! Idle-connection pool for L7 upstreams (PROXY-5, proxy DESIGN §7).
//!
//! The L7 bridge previously opened a fresh `upstream_tls::connect()` per
//! proxied request, paying a full post-quantum TLS handshake
//! (X25519MLKEM768 + ML-DSA-65, ~40 ms loopback) on EVERY external
//! request — the dashboard latency metric showed the handshake cost, not
//! request cost. The pool keeps warmed upstream connections per
//! `(backend_addr, sni_hostname)` and hands them out before a fresh
//! connect is attempted.
//!
//! ## One connection = one request (handoff-warm, no pipelining)
//!
//! The L7 pipe closes the upstream after the response completes
//! (HTTP/1.0-style connection-per-request byte piping) — a pooled
//! connection is taken, used for exactly one request/response cycle, and
//! the pool is refilled by fresh connects as requests need them. The
//! pool therefore never pipelines a second request onto a busy socket
//! and never multiplexes; freshness is handled by taking WITHOUT
//! returning: a taken connection either completes its request or is
//! discarded on error.
//!
//! ## Staleness discipline
//!
//! A backend respawn (SIGKILL + re-bind on the same port) leaves stale
//! pooled sockets that fail on first write/read. The caller handles that
//! with retry-once-on-fresh-connection semantics (mirroring the captain
//! health-probe retry, captain DESIGN §5): a stale send must not surface
//! as repeated 502s, and a failed take is discarded — never re-pooled.
//!
//! ## Eviction
//!
//! A background task evicts idle entries past [`IDLE_TIMEOUT`] and caps
//! the pool per backend at [`MAX_PER_BACKEND`] so a burst cannot
//! unboundedly hoard sockets. The pool itself holds only established,
//! healthy sockets — a connect failure never inserts.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::upstream_tls::{self, UpstreamConnection, UpstreamTlsConfig};

/// Idle duration after which an unused pooled connection is evicted.
/// Below the backend respawn cycle so evictions prune dead sockets even
/// without request traffic.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum idle connections retained per `(addr, sni)` key. The L7 path
/// is connection-per-request, so a small warm buffer (1) is sufficient —
/// additional concurrent requests open fresh connects and immediately
/// hand off.
const MAX_PER_BACKEND: usize = 1;

/// An entry in the idle pool.
struct PoolEntry {
    conn: UpstreamConnection,
    idle_since: Instant,
}

/// Shared handle to the idle pool — cheap to clone.
#[derive(Clone)]
pub struct UpstreamPool {
    inner: Arc<UpstreamPoolInner>,
}

struct UpstreamPoolInner {
    // `(backend_addr, sni)` → one idle connection per key (MAX_PER_BACKEND
    // is 1; the map value is Option so take/pPut is a single lock hold).
    entries: Mutex<HashMap<(String, String), PoolEntry>>,
}

impl UpstreamPool {
    /// Create an empty pool.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(UpstreamPoolInner {
                entries: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Take a warm connection for `(backend_addr, sni_hostname)` if one
    /// is pooled. Returns `None` when the pool is empty for the key —
    /// the caller then connects fresh.
    pub fn take(&self, backend_addr: &str, sni_hostname: &str) -> Option<UpstreamConnection> {
        let key = (backend_addr.to_string(), sni_hostname.to_string());
        self.inner
            .entries
            .lock()
            .ok()
            .and_then(|mut m| m.remove(&key).map(|e| e.conn))
    }

    /// Put a healthy upstream connection back for reuse (HTTP/1.1
    /// keep-alive cycle completed — PROXY-5). Called by the L7 pipe when
    /// the response was fully framed; a close-delimited or failed pipe
    /// discards the connection instead (stale/garbage state —
    /// never re-pooled).
    pub fn put(&self, backend_addr: &str, sni_hostname: &str, conn: UpstreamConnection) {
        let key = (backend_addr.to_string(), sni_hostname.to_string());
        if let Ok(mut m) = self.inner.entries.lock() {
            if m.len() >= MAX_PER_BACKEND || m.contains_key(&key) {
                return; // drop the surplus connection
            }
            m.insert(
                key,
                PoolEntry {
                    conn,
                    idle_since: Instant::now(),
                },
            );
        }
        // Lock poisoning or cap-full: the connection is dropped —
        // the next request connects fresh (always safe).
    }

    /// Number of pooled connections (observability — mgmt health payload).
    // Observability-only counter: emptiness is not a pool state the code
    // branches on (eviction/pruning decide), so no paired is_empty ships.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.inner.entries.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// Evict entries idle longer than [`IDLE_TIMEOUT`]. Called by the
    /// background sweep task; also prunes when the pool is consulted so
    /// an unflushed eviction cannot serve a very-long-idle socket.
    fn evict_idle(&self) {
        if let Ok(mut m) = self.inner.entries.lock() {
            m.retain(|_, e| e.idle_since.elapsed() < IDLE_TIMEOUT);
        }
    }
}

impl Default for UpstreamPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Spawn the eviction loop — prunes idle entries every [`IDLE_TIMEOUT`].
pub fn spawn_evictor(pool: UpstreamPool) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(IDLE_TIMEOUT).await;
            pool.evict_idle();
        }
    });
}

/// Acquire an upstream connection for a proxied request: pool-first
/// (`take`), fresh `upstream_tls::connect` on a miss.
///
/// Returns `(connection, established_fresh)`. `established_fresh` is
/// true when no pooled connection was available and a new TCP(+PQ TLS)
/// connection was created — the caller records it as a cold-path metric.
/// The caller is responsible for the connection's end state:
///
/// - response fully framed (Content-Length / chunked) →
///   [`UpstreamPool::put`] returns the connection for the NEXT request
///   (HTTP/1.1 keep-alive reuse — the target state);
/// - close-delimited response (no length, HTTP/1.0) or any mid-pipe
///   transport failure → the connection is dead — discard it.
pub async fn acquire(
    pool: &UpstreamPool,
    backend_addr: &str,
    sni_hostname: &str,
    config: &UpstreamTlsConfig,
) -> Result<(UpstreamConnection, bool), std::io::Error> {
    if let Some(conn) = pool.take(backend_addr, sni_hostname) {
        return Ok((conn, false));
    }
    let conn = upstream_tls::connect(backend_addr, sni_hostname, config).await?;
    Ok((conn, true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener as StdListener;

    #[test]
    fn pool_take_on_empty_is_none() {
        let pool = UpstreamPool::new();
        assert!(pool
            .take("127.0.0.1:3001", "auth.ops.sys.sentin8.local")
            .is_none());
        assert_eq!(pool.len(), 0);
    }

    #[tokio::test]
    async fn pool_put_then_take_roundtrip() {
        let listener = StdListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        // A connected socket pair pretends to be an idle backend conn;
        // the pool never touches the socket between put/take.
        let _peer = std::net::TcpStream::connect(addr.clone()).unwrap();
        let accepted = listener.accept().unwrap().0;
        accepted
            .set_nonblocking(true)
            .expect("convert to async-compatible stream");
        let conn = UpstreamConnection::Plain(tokio::net::TcpStream::from_std(accepted).unwrap());

        let pool = UpstreamPool::new();
        pool.put(&addr, "auth.ops.sys.sentin8.local", conn);
        assert_eq!(pool.len(), 1);
        assert!(pool.take(&addr, "auth.ops.sys.sentin8.local").is_some());
        assert_eq!(pool.len(), 0);
    }

    #[tokio::test]
    async fn pool_put_surplus_dropped() {
        let listener = StdListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let mut conns = Vec::new();
        for _ in 0..3 {
            let _peer = std::net::TcpStream::connect(addr.clone()).unwrap();
            let s = listener.accept().unwrap().0;
            s.set_nonblocking(true).unwrap();
            conns.push(tokio::net::TcpStream::from_std(s).unwrap());
        }
        let pool = UpstreamPool::new();
        for c in conns {
            // Repeated puts for the same key are no-ops (cap 1/key);
            // a surplus connection is dropped, never double-pooled.
            pool.put(
                &addr,
                "auth.ops.sys.sentin8.local",
                UpstreamConnection::Plain(c),
            );
        }
        assert_eq!(pool.len(), 1);
    }
}
