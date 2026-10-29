// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Proxy
// SPDX-License-Identifier: Apache-2.0

//! Domain resolver - constructs hostname → service mappings on the fly
//! from sys's domain model (orgs, envs, app instances, vertical services).
//!
//! /2 ( - membus → bus → owner API):
//! cache invalidation rides **MemBus** (`mchan:{SYSTEM_ENV_ID}:sys-domain`
//! pub/sub notifications published by sys post-commit); the initial seed +
//! any cache-miss fallback queries ride sys's owner API
//! (`GET /v1/resolve/hostname`, M2M `sentin8:sys:instances:read`) - the
//! proxy holds **no SELECT grants** on sys's tables. The former
//! LISTEN/NOTIFY channel (`sentin8_domain_changed`) is retired together
//! with sys's notify triggers; a 30s safety poll remains as the outage
//! backstop.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use parking_lot::RwLock;
use sqlx::PgPool;
use uuid::Uuid;

/// Re-export the DomainMapping type from mapping_cache so all code uses
/// the same type.
pub use crate::mapping_cache::DomainMapping;

/// Resolve a service label to its full service name using the subdomain map
/// loaded from `sentin8_vertical_services.subdomain`. Falls back to
/// `sentin8-web` for unknown labels (app instances served by web).
fn resolve_service_name(
    label: &str,
    known_services: &HashSet<String>,
    subdomain_map: &HashMap<String, String>,
) -> String {
    // Check the subdomain map first - this is the authoritative path.
    // e.g. `auth` → `sentin8-auth`, `func` → `sentin8-func`,
    // `bank8-ledger` → `bank8-ledger`.
    if let Some(service_type) = subdomain_map.get(label) {
        return service_type.clone();
    }
    // Fall back to known_services (for labels that match service_type directly).
    if known_services.contains(label) {
        return label.to_string();
    }
    // Unknown label → app instance, route to web.
    "sentin8:web".to_string()
}

/// Resolve a PLATFORM-plane SNI hostname (`{label}.ops.sys.{domain}`) to
/// its mapping in-process - no cache, no sys call, no SQL.
///
/// Well-known system constants (sentin8-config) supply the org/env ids;
/// the label→service_type identity comes from `SENTIN8_TLS_PLATFORM_LABELS`
/// (captain propagates it from the runtime registry, covering vertical
/// subdomains) with the built-in core-platform table as the fallback.
/// Returns `None` for anything that is not exactly that shape - tenant
/// hostnames go through the Sys owner API (`GET /v1/resolve/hostname`).
/// Parity with `sentin8-tls` `static_platform_mapping`; two
/// implementations because the proxy's mapping type is its own.
fn static_platform_mapping(hostname: &str) -> Option<DomainMapping> {
    let cfg = sentin8::config::Sentin8Config::from_env();
    let expected_suffix = format!("ops.sys.{}", cfg.sentin8_domain);
    let host = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').collect();
    // Exactly `{label}.ops.sys.{domain}` - no more, no fewer (tenant
    // hostnames carry an env label and go via Sys).
    if labels.len() != 3 + cfg.sentin8_domain.split('.').count() {
        return None;
    }
    let suffix = labels[1..].join(".");
    if suffix != expected_suffix {
        return None;
    }
    let service = platform_service_for_label(labels[0])?;
    Some(DomainMapping {
        hostname: hostname.to_string(),
        service,
        org_id: sentin8::config::SYSTEM_ORG_ID,
        env_id: sentin8::config::SYSTEM_ENV_ID,
        application_id: None,
        backend_url: None,
    })
}

/// Resolve a platform subdomain label to its full service identity.
/// Order: `SENTIN8_TLS_PLATFORM_LABELS` (comma-separated `label:service`
/// pairs) → the built-in core-platform table (label == the platform leaf).
fn platform_service_for_label(label: &str) -> Option<String> {
    if label.is_empty() {
        return None;
    }
    if let Ok(pairs) = std::env::var("SENTIN8_TLS_PLATFORM_LABELS") {
        for pair in pairs.split(',').map(str::trim) {
            if let Some((lbl, svc)) = pair.split_once(':') {
                if lbl.eq_ignore_ascii_case(label) && !svc.is_empty() {
                    return Some(svc.to_string());
                }
            }
        }
    }
    // Built-in core-platform fallback: label == the service leaf name.
    const PLATFORM_LEAVES: &[(&str, &str)] = &[
        ("acme", "sentin8:acme"),
        ("auth", "sentin8:auth"),
        ("proxy", "sentin8:proxy"),
        ("bus", "sentin8:bus"),
        ("db", "sentin8:db"),
        ("storage", "sentin8:storage"),
        ("post", "sentin8:post"),
        ("stat", "sentin8:stat"),
        ("secrets", "sentin8:secrets"),
        ("sign", "sentin8:sign"),
        ("func", "sentin8:func"),
        ("cron", "sentin8:cron"),
        ("flow", "sentin8:flow"),
        ("ai", "sentin8:ai"),
        ("sys", "sentin8:sys"),
        ("app", "sentin8:app"),
        ("bff", "sentin8:bff"),
        ("web", "sentin8:web"),
    ];
    PLATFORM_LEAVES
        .iter()
        .find(|(l, _)| *l == label)
        .map(|(_, s)| s.to_string())
}

/// In-memory cache of app instances and known service types.
/// Used to resolve hostnames to mappings without DB queries on every request.
/// PLATFORM-plane hostnames never touch this (static, §3) and tenant
/// hostnames resolve via the Sys owner API on cache miss.
#[derive(Clone)]
/// The domainresolver type.
pub struct DomainResolver {
    /// hostname → app instance mapping
    apps: Arc<RwLock<HashMap<String, AppRow>>>,
    /// Known service types from sentin8_vertical_services + platform services.
    /// e.g. {"sentin8:auth", "sentin8:storage", "bank8:ledger", "bank8:fdx", ...}
    known_services: Arc<RwLock<HashSet<String>>>,
    /// Map from subdomain label → full service_type.
    /// e.g. {"auth" → "sentin8:auth", "func" → "sentin8:func",
    /// "bank8-ledger" → "bank8:ledger"}.
    /// Built from `sentin8_vertical_services.subdomain` at load time.
    /// Used to resolve the first hostname label to a service without
    /// ad-hoc `sentin8-` prefix prepending.
    subdomain_map: Arc<RwLock<HashMap<String, String>>>,
}

#[derive(Debug, Clone)]
struct AppRow {
    bff_hostname: String,
    org_id: Uuid,
    env_id: Uuid,
    app_id: Uuid,
}

impl DomainResolver {
    /// Handle new.
    pub fn new() -> Self {
        Self {
            apps: Arc::new(RwLock::new(HashMap::new())),
            known_services: Arc::new(RwLock::new(HashSet::new())),
            subdomain_map: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Resolve a hostname to a domain mapping.
    /// Resolve it.
    pub fn resolve(&self, hostname: &str) -> Option<DomainMapping> {
        // 0. Platform-plane SNIs resolve STATICALLY - no cache, no sys
        // call, no SQL (parity with every service's embedded
        // sentin8-tls resolver; proxy DESIGN §3). `auth.ops.sys.<domain>`
        // → well-known SYSTEM_ORG_ID/SYSTEM_ENV_ID + the label→service map
        // captain propagates via `SENTIN8_TLS_PLATFORM_LABELS`.
        if let Some(m) = static_platform_mapping(hostname) {
            return Some(m);
        }

        let labels: Vec<&str> = hostname.split('.').collect();
        if labels.len() < 3 {
            return None;
        }

        // 1. Check app instance domains (exact match in apps cache).
        {
            let apps = self.apps.read();
            if let Some(app) = apps.get(hostname) {
                return Some(DomainMapping {
                    hostname: hostname.to_string(),
                    service: "sentin8:web".to_string(),
                    org_id: app.org_id,
                    env_id: app.env_id,
                    application_id: Some(app.app_id),
                    backend_url: None,
                });
            }
            // Check BFF hostname.
            if let Some(app) = apps.values().find(|a| a.bff_hostname == hostname) {
                return Some(DomainMapping {
                    hostname: hostname.to_string(),
                    service: "sentin8:bff".to_string(),
                    org_id: app.org_id,
                    env_id: app.env_id,
                    application_id: Some(app.app_id),
                    backend_url: None,
                });
            }
        }

        // 2. Tenant hostname shape: {service}.{env_slug}.{org_domain}? The
        // org/env caches are GONE (D7-PXY - the RLS-blind SELECTs are retired):
        // a tenant hostname's SERVICE label still resolves locally via the
        // subdomain map; org/env IDs for the mapping ride the Sys owner API
        // via sentin8-tls's HostContextResolver when the mapping needs them.
        // In the L4 SNI path only `service` drives backend picking - the
        // system constants fill the placeholder fields.
        let known_services = self.known_services.read();
        let subdomain_map = self.subdomain_map.read();

        for suffix_len in (2..=labels.len() - 1).rev() {
            let org_domain = labels[labels.len() - suffix_len..].join(".");
            let prefix_labels = &labels[..labels.len() - suffix_len];

            if prefix_labels.is_empty() || org_domain.is_empty() {
                continue;
            }

            let service_label = prefix_labels[0];
            let env_slug = if prefix_labels.len() >= 2 {
                prefix_labels[1]
            } else {
                sentin8::config::SYSTEM_ENV_SLUG
            };
            if service_label.is_empty() || env_slug.is_empty() {
                continue;
            }
            let service = resolve_service_name(service_label, &known_services, &subdomain_map);
            let env_id = if env_slug == sentin8::config::SYSTEM_ENV_SLUG {
                sentin8::config::SYSTEM_ENV_ID
            } else {
                // Tenant envs: without the org/env caches the exact env_id
                // is resolved by the caller-side owner API path; default to
                // the system env placeholder (L4 routing ignores it).
                sentin8::config::SYSTEM_ENV_ID
            };
            return Some(DomainMapping {
                hostname: hostname.to_string(),
                service,
                org_id: sentin8::config::SYSTEM_ORG_ID,
                env_id,
                application_id: None,
                backend_url: None,
            });
        }

        None
    }

    /// Load known service types + subdomain mappings into the caches.
    /// ONLY the `sys.vertical_services` SELECT remains (the one DECLARED
    /// cross-schema read - registration.rs); the orgs/envs/app instances
    /// SQL loads are RETIRED (D7-PXY): platform SNIs resolve statically,
    /// tenant SNIs resolve via Sys's owner API.
    pub async fn reload(&self, pool: &PgPool) -> Result<(), sqlx::Error> {
        let cfg = sentin8::config::Sentin8Config::from_env();
        let subdomain_map = cfg.load_subdomain_map(pool).await;
        let known_services: HashSet<String> = subdomain_map.values().cloned().collect();

        let svc_count = known_services.len();

        *self.known_services.write() = known_services;
        *self.subdomain_map.write() = subdomain_map;

        tracing::info!(services = svc_count, "domain resolver: cache loaded");

        Ok(())
    }
}

impl Default for DomainResolver {
    fn default() -> Self {
        Self::new()
    }
}

/// Spawn the background sync task: seed the cache, then subscribe to sys's
/// MemBus domain-changed notifications on
/// `mchan:{SYSTEM_ENV_ID}:sys-domain`.
///
/// The former LISTEN/NOTIFY path (sys's `sentin8_notify_domain_changed`
/// triggers) is RETIRED - the proxy holds no sys.* grants anymore
/// . A 30s safety poll remains as the outage backstop.
/// Spawn sync.
pub fn spawn_sync(pool: PgPool, resolver: DomainResolver) {
    tokio::spawn(async move {
        // 1. Seed: retry until non-empty (up to 10 × 3s).
        for attempt in 0..10u32 {
            match resolver.reload(&pool).await {
                Ok(_) => break,
                Err(e) => {
                    tracing::error!(error = ?e, attempt, "domain resolver: seed failed");
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }

        // 2. MemBus subscription (mchan pub/sub, ephemeral class) + safety
        // poll backstop. A failed subscribe keeps the poll-only mode -
        // refresh degrades to 30s, never blocks routing.
        let safety = std::time::Duration::from_secs(30);
        let cfg = sentin8::membus::MemBusConfig::from_env("sentin8:proxy");
        match sentin8::membus::MemBus::connect(cfg).await {
            Ok(bus) => match bus.for_env(&sentin8::config::SYSTEM_ENV_ID.to_string()) {
                Ok(env_bus) => match env_bus
                    .subscribe_pubsub(crate::sys_events::DOMAIN_FAMILY)
                    .await
                {
                    Ok(mut sub) => {
                        tracing::info!(
                            family = crate::sys_events::DOMAIN_FAMILY,
                            "domain resolver: MemBus domain-changed subscription active"
                        );
                        // Reader task + safety poll.
                        loop {
                            tokio::select! {
                                                           frame = sub.next_frame() => {
                                                               match frame {
                                                                   Ok(Some(_env)) => {
                                                                       tracing::info!(
                                                                           "domain resolver: domain-changed notification - reloading cache"
                                                                       );
                                                                       if let Err(e) = resolver.reload(&pool).await {
                                                                           tracing::error!(error = ?e, "domain resolver: reload failed");
                                                                       }
                                                                   }
                                                                   Ok(None) | Err(_) => {
                                                                       tracing::warn!("domain resolver: membus subscription ended - reconnecting");
                                                                       break;
                                                                   }
                                                               }
                                                           }
                                                           _ = tokio::time::sleep(safety) => {
                            // Safety poll: also catches missed
                            // notifications while Valkey was down.
                                                               if let Err(e) = resolver.reload(&pool).await {
                                                                   tracing::error!(error = ?e, "domain resolver: safety poll failed");
                                                               }
                                                           }
                                                       }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "domain resolver: membus subscribe failed - safety poll only");
                    }
                },
                Err(e) => {
                    tracing::warn!(error = %e, "domain resolver: membus for_env failed - safety poll only")
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, "domain resolver: membus connect failed - safety poll only");
            }
        }

        // Safety polling loop (runs if the subscription is unavailable).
        loop {
            tokio::time::sleep(safety).await;
            if let Err(e) = resolver.reload(&pool).await {
                tracing::error!(error = ?e, "domain resolver: safety poll failed");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> DomainResolver {
        let resolver = DomainResolver::new();
        *resolver.known_services.write() = HashSet::from([
            "sentin8:auth".to_string(),
            "sentin8:proxy".to_string(),
            "sentin8:web".to_string(),
            "bank8:ledger".to_string(),
        ]);
        *resolver.subdomain_map.write() = HashMap::from([
            ("auth".to_string(), "sentin8:auth".to_string()),
            ("proxy".to_string(), "sentin8:proxy".to_string()),
            ("ledger".to_string(), "bank8:ledger".to_string()),
        ]);
        resolver
    }

    #[test]
    fn platform_service_host_resolves_statically() {
        // auth.ops.sys.local.sentin8.dev - the EXACT platform-plane shape:
        // static resolution; the sentin8_domain default must end with the
        // built-in default for this test to hold.
        let f = fixture();
        let m = f.resolve("auth.ops.sys.local.sentin8.dev").unwrap();
        assert_eq!(m.service, "sentin8:auth");
        assert_eq!(m.org_id, sentin8::config::SYSTEM_ORG_ID);
        assert_eq!(m.env_id, sentin8::config::SYSTEM_ENV_ID);
        assert_eq!(m.application_id, None);
        assert_eq!(m.hostname, "auth.ops.sys.local.sentin8.dev");
    }

    #[test]
    fn platform_service_host_proxy_label() {
        let f = fixture();
        let m = f.resolve("proxy.ops.sys.local.sentin8.dev").unwrap();
        assert_eq!(m.service, "sentin8:proxy");
        assert_eq!(m.env_id, sentin8::config::SYSTEM_ENV_ID);
    }

    #[test]
    fn tenant_host_shape_resolves_service_label() {
        // ledger.prod.acme.example.com - tenant shape: the service label
        // resolves via the subdomain map; org/env ids carry the system
        // placeholders (L4 path routes on `service` only).
        let f = fixture();
        let m = f.resolve("ledger.prod.acme.example.com").unwrap();
        assert_eq!(m.service, "bank8:ledger");
    }

    #[test]
    fn tenant_host_bff_label_prefers_bff_domain() {
        // bff-portal.prod.acme.example.com - hostname matching the app's
        // BFF hostname resolves to the BFF service.
        let f = fixture();
        let app_id = Uuid::new_v4();
        *f.apps.write() = HashMap::from([(
            "portal.prod.acme.example.com".to_string(),
            AppRow {
                bff_hostname: "bff-portal.prod.acme.example.com".to_string(),
                org_id: sentin8::config::SYSTEM_ORG_ID,
                env_id: sentin8::config::SYSTEM_ENV_ID,
                app_id,
            },
        )]);
        let m = f.resolve("bff-portal.prod.acme.example.com").unwrap();
        assert_eq!(m.service, "sentin8:bff");
        assert_eq!(m.application_id, Some(app_id));
    }

    #[test]
    fn app_instance_hostname_routes_to_web_with_app_id() {
        let f = fixture();
        let app_id = Uuid::new_v4();
        *f.apps.write() = HashMap::from([(
            "portal.prod.acme.example.com".to_string(),
            AppRow {
                bff_hostname: "bff-portal.prod.acme.example.com".to_string(),
                org_id: sentin8::config::SYSTEM_ORG_ID,
                env_id: sentin8::config::SYSTEM_ENV_ID,
                app_id,
            },
        )]);
        let m = f.resolve("portal.prod.acme.example.com").unwrap();
        assert_eq!(m.service, "sentin8:web");
        assert_eq!(m.application_id, Some(app_id));
    }

    #[test]
    fn unknown_service_prefix_routes_to_web() {
        // Not in the subdomain map and not a known service type → an app
        // instance served by web.
        let f = fixture();
        let m = f.resolve("portal.prod.acme.example.com").unwrap();
        assert_eq!(m.service, "sentin8:web");
        assert_eq!(m.application_id, None);
    }

    #[test]
    fn ops_org_domain_hostname_routes_to_web() {
        // ops.sys.local.sentin8.dev - 4 labels, NOT the 3+domain platform
        // shape → falls to the tenant walk → service label "ops"... the
        // subdomain map does not know it → web.
        let f = fixture();
        let m = f.resolve("ops.sys.local.sentin8.dev").unwrap();
        assert_eq!(m.service, "sentin8:web");
    }
}
