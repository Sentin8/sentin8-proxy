// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Proxy
// SPDX-License-Identifier: Apache-2.0

//! Per-service backend registry — Prox's in-memory map of service type →
//! Active instances, kept fresh via Valkey pub/sub on `captain:changed` +
//! safety poll.
//!
//! Scans ALL `captain:svc:*` hashes (not just `captain:svc:tls`) and builds
//! a per-service-type instance list. Round-robin selection per service
//! type with fail-over and suspect marking.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use glide::AsyncCommands;

/// A backend instance.
#[derive(Debug, Clone)]
/// The backendinstance type.
pub struct BackendInstance {
    /// The addr.
    pub addr: String, // "ip:port"
}

/// Per-service backend registry: in-memory map of service type →
/// `ServiceBackends`, kept fresh by a background Valkey pub/sub +
/// safety-poll loop.
/// The servicebackendregistry type.
pub struct ServiceBackendRegistry {
    map: RwLock<HashMap<String, ServiceBackends>>,
    suspect_ttl: Duration,
}

#[derive(Debug)]
struct ServiceBackends {
    instances: Vec<BackendInstance>,
    counter: AtomicUsize,
    suspect: RwLock<Vec<(String, Instant)>>,
    suspect_ttl: Duration,
}

impl ServiceBackends {
    fn new(suspect_ttl: Duration) -> Self {
        Self {
            instances: Vec::new(),
            counter: AtomicUsize::new(0),
            suspect: RwLock::new(Vec::new()),
            suspect_ttl,
        }
    }

    fn swap(&mut self, instances: Vec<BackendInstance>) {
        self.instances = instances;
    }

    /// Pick the next backend using round-robin, skipping suspect ones.
    fn pick(&self) -> Option<String> {
        if self.instances.is_empty() {
            return None;
        }
        // Expire stale suspect entries.
        let now = Instant::now();
        {
            let mut suspect = self.suspect.write().unwrap();
            suspect.retain(|(_, ts)| now.duration_since(*ts) < self.suspect_ttl);
        }
        let suspect = self.suspect.read().unwrap();
        let n = self.instances.len();
        for _ in 0..n {
            let idx = self.counter.fetch_add(1, Ordering::Relaxed) % n;
            let addr = &self.instances[idx].addr;
            if !suspect.iter().any(|(a, _)| a == addr) {
                return Some(addr.clone());
            }
        }
        // All suspect — fall back to round-robin pick.
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % n;
        Some(self.instances[idx].addr.clone())
    }

    fn mark_suspect(&self, addr: &str) {
        let mut suspect = self.suspect.write().unwrap();
        suspect.push((addr.to_string(), Instant::now()));
    }

    fn len(&self) -> usize {
        self.instances.len()
    }
}

impl ServiceBackendRegistry {
    /// Handle new.
    pub fn new(suspect_ttl_s: u64) -> Self {
        Self {
            map: RwLock::new(HashMap::new()),
            suspect_ttl: Duration::from_secs(suspect_ttl_s),
        }
    }

    /// Replace the instance list for a service type (called by the refresh loop).
    /// Handle swap service.
    pub fn swap_service(&self, service: &str, instances: Vec<BackendInstance>) {
        let mut map = self.map.write().unwrap();
        map.entry(service.to_string())
            .or_insert_with(|| ServiceBackends::new(self.suspect_ttl))
            .swap(instances);
    }

    /// Pick the next backend for a service type using round-robin.
    /// Handle pick.
    pub fn pick(&self, service: &str) -> Option<String> {
        let map = self.map.read().unwrap();
        map.get(service).and_then(|sb| sb.pick())
    }

    /// Mark a backend as suspect after a connect failure.
    /// Handle mark suspect.
    pub fn mark_suspect(&self, service: &str, addr: &str) {
        let map = self.map.read().unwrap();
        if let Some(sb) = map.get(service) {
            sb.mark_suspect(addr);
        }
    }

    /// Get the instance count for a service type.
    /// Handle service len.
    pub fn service_len(&self, service: &str) -> usize {
        self.map
            .read()
            .unwrap()
            .get(service)
            .map_or(0, |sb| sb.len())
    }

    /// Get a summary of all services and their instance counts.
    /// Handle service counts.
    pub fn service_counts(&self) -> Vec<(String, usize)> {
        self.map
            .read()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.len()))
            .collect()
    }
}

/// Type alias for sharedservicebackendregistry.
pub type SharedServiceBackendRegistry = Arc<ServiceBackendRegistry>;

/// Spawn the Valkey pub/sub refresh loop. Returns the registry handle.
/// Spawn it.
pub fn spawn(
    valkey_url: String,
    debounce_ms: u64,
    safety_poll_s: u64,
    suspect_ttl_s: u64,
) -> SharedServiceBackendRegistry {
    let registry = Arc::new(ServiceBackendRegistry::new(suspect_ttl_s));
    let reg = registry.clone();
    let pubsub_url = valkey_url.clone();
    tokio::spawn(async move {
        let conn = sentin8::middleware::valkey_client(&valkey_url, "sentin8:proxy")
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = ?e, "prox Valkey client create failed");
                panic!("prox Valkey client create failed: {e:?}");
            });
        // Seed.
        refresh(&conn, &reg).await;

        let debounce = Duration::from_millis(debounce_ms.max(100));
        let safety = Duration::from_secs(safety_poll_s.max(1));
        let mut last_refresh = Instant::now();

        loop {
            let pubsub_client = match sentin8::middleware::valkey_client_pubsub(
                &pubsub_url,
                "sentin8:proxy",
            )
            .await
            {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = ?e, "prox Valkey pubsub connect failed; safety poll only");
                    tokio::time::sleep(safety).await;
                    refresh(&conn, &reg).await;
                    last_refresh = Instant::now();
                    continue;
                }
            };
            use glide::PubSubCommands as _;
            if let Err(e) = pubsub_client.subscribe(&["captain:changed"]).await {
                tracing::warn!(error = %e, "prox Valkey subscribe failed; safety poll only");
                tokio::time::sleep(safety).await;
                refresh(&conn, &reg).await;
                last_refresh = Instant::now();
                continue;
            }

            loop {
                let timeout = safety.saturating_sub(last_refresh.elapsed());
                let msg = tokio::time::timeout(timeout, pubsub_client.get_pubsub_message()).await;
                match msg {
                    Ok(_) => {
                        if last_refresh.elapsed() < debounce {
                            tokio::time::sleep(debounce - last_refresh.elapsed()).await;
                        }
                        refresh(&conn, &reg).await;
                        last_refresh = Instant::now();
                    }
                    Err(_) => {
                        refresh(&conn, &reg).await;
                        last_refresh = Instant::now();
                    }
                }
            }
        }
    });
    registry
}

/// Read ALL service instances from Valkey and swap each service's list.
async fn refresh(conn: &glide::GlideClient, registry: &ServiceBackendRegistry) {
    // SCAN all captain:svc:* keys.
    let keys: Vec<String> = conn.keys("captain:svc:*").await.unwrap_or_default();

    let now = chrono::Utc::now().timestamp();
    let mut total_instances = 0usize;

    for key in &keys {
        // Extract service type from the key: "captain:svc:{service_type}"
        let service_type = key.strip_prefix("captain:svc:").unwrap_or(key);

        let entries: Vec<(String, String)> = conn.hgetall(key).await.unwrap_or_default();
        let mut backends = Vec::new();
        for (_field, json) in entries {
            let obj: serde_json::Value = match serde_json::from_str(&json) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let status = obj.get("status").and_then(|v| v.as_str()).unwrap_or("");
            if status != "Active" {
                continue;
            }
            let health_ts = obj.get("last_health_check").and_then(|v| v.as_i64());
            let fresh = health_ts.is_some_and(|ts| now - ts < 30);
            if !fresh {
                continue;
            }
            let ip = obj.get("local_ip").and_then(|v| v.as_str()).unwrap_or("");
            let port = obj.get("local_port").and_then(|v| v.as_u64()).unwrap_or(0);
            if ip.is_empty() || port == 0 {
                continue;
            }
            backends.push(BackendInstance {
                addr: format!("{ip}:{port}"),
            });
        }
        backends.sort_by(|a, b| a.addr.cmp(&b.addr));
        total_instances += backends.len();
        registry.swap_service(service_type, backends);
    }
    tracing::debug!(
        total_instances,
        service_types = keys.len(),
        "prox backend lists refreshed from Valkey"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instance(addr: &str) -> BackendInstance {
        BackendInstance {
            addr: addr.to_string(),
        }
    }

    #[test]
    fn pick_round_robin_over_configured_backends() {
        let reg = ServiceBackendRegistry::new(300);
        reg.swap_service(
            "sentin8:auth",
            vec![
                instance("10.0.0.1:8443"),
                instance("10.0.0.2:8443"),
                instance("10.0.0.3:8443"),
            ],
        );
        assert_eq!(reg.service_len("sentin8:auth"), 3);
        assert_eq!(reg.pick("sentin8:auth").as_deref(), Some("10.0.0.1:8443"));
        assert_eq!(reg.pick("sentin8:auth").as_deref(), Some("10.0.0.2:8443"));
        assert_eq!(reg.pick("sentin8:auth").as_deref(), Some("10.0.0.3:8443"));
        assert_eq!(reg.pick("sentin8:auth").as_deref(), Some("10.0.0.1:8443"));
    }

    #[test]
    fn pick_empty_registry_returns_none() {
        let reg = ServiceBackendRegistry::new(300);
        assert_eq!(reg.pick("sentin8:auth"), None);
        assert_eq!(reg.service_len("sentin8:auth"), 0);
    }

    #[test]
    fn pick_unknown_service_returns_none() {
        let reg = ServiceBackendRegistry::new(300);
        reg.swap_service("sentin8:auth", vec![instance("10.0.0.1:8443")]);
        assert_eq!(reg.pick("sentin8:bus"), None);
    }

    #[test]
    fn failover_skips_suspect_instance() {
        let reg = ServiceBackendRegistry::new(300);
        reg.swap_service(
            "sentin8:auth",
            vec![instance("10.0.0.1:8443"), instance("10.0.0.2:8443")],
        );
        // First pick is round-robin; mark it suspect as a connect failure would.
        let first = reg.pick("sentin8:auth").unwrap();
        reg.mark_suspect("sentin8:auth", &first);
        // Next pick must skip the suspect instance.
        assert_eq!(reg.pick("sentin8:auth").as_deref(), Some("10.0.0.2:8443"));
    }

    #[test]
    fn all_instances_suspect_falls_back_to_round_robin() {
        let reg = ServiceBackendRegistry::new(300);
        reg.swap_service("sentin8:auth", vec![instance("10.0.0.1:8443")]);
        reg.mark_suspect("sentin8:auth", "10.0.0.1:8443");
        // With the only instance suspect the fallback still returns a
        // round-robin pick rather than None.
        assert_eq!(reg.pick("sentin8:auth").as_deref(), Some("10.0.0.1:8443"));
    }

    #[test]
    fn suspect_entries_expire_after_ttl() {
        // TTL 0 → suspect entries are pruned on the very next pick.
        let reg = ServiceBackendRegistry::new(0);
        reg.swap_service(
            "sentin8:auth",
            vec![instance("10.0.0.1:8443"), instance("10.0.0.2:8443")],
        );
        reg.mark_suspect("sentin8:auth", "10.0.0.1:8443");
        assert_eq!(reg.pick("sentin8:auth").as_deref(), Some("10.0.0.1:8443"));
        assert_eq!(reg.pick("sentin8:auth").as_deref(), Some("10.0.0.2:8443"));
    }

    #[test]
    fn swap_service_replaces_instance_list() {
        let reg = ServiceBackendRegistry::new(300);
        reg.swap_service(
            "sentin8:auth",
            vec![instance("10.0.0.1:8443"), instance("10.0.0.2:8443")],
        );
        assert_eq!(reg.service_len("sentin8:auth"), 2);
        reg.swap_service("sentin8:auth", vec![instance("10.0.0.9:8443")]);
        assert_eq!(reg.service_len("sentin8:auth"), 1);
        for _ in 0..3 {
            assert_eq!(reg.pick("sentin8:auth").as_deref(), Some("10.0.0.9:8443"));
        }
    }

    #[test]
    fn service_counts_reports_each_service() {
        let reg = ServiceBackendRegistry::new(300);
        reg.swap_service("sentin8:auth", vec![instance("10.0.0.1:8443")]);
        reg.swap_service("sentin8:web", vec![instance("10.0.1.1:8443")]);
        let counts = reg.service_counts();
        assert_eq!(counts.len(), 2);
        assert!(counts
            .iter()
            .any(|(svc, n)| svc == "sentin8:auth" && *n == 1));
        assert!(counts
            .iter()
            .any(|(svc, n)| svc == "sentin8:web" && *n == 1));
    }
}
