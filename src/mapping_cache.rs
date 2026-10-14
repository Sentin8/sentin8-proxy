// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Proxy
// SPDX-License-Identifier: Apache-2.0

//! Read-only in-memory cache for domain mappings.
//!
//! The cache is always empty — all domain resolution is done by the
//! `DomainResolver` which constructs mappings on the fly from
//! `sentin8_sys_organizations`, `sentin8_sys_environments`, and
//! `sentin8_sys_app_instances`.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::Serialize;
use uuid::Uuid;

/// A domain mapping row (read-only view).
#[derive(Debug, Clone, Serialize)]
/// The domainmapping type.
pub struct DomainMapping {
    /// The hostname.
    pub hostname: String,
    /// The service.
    pub service: String,
    /// org identifier.
    pub org_id: Uuid,
    /// env identifier.
    pub env_id: Uuid,
    /// application identifier.
    pub application_id: Option<Uuid>,
    /// The backend URL.
    pub backend_url: Option<String>,
}

/// In-memory hostname → mapping cache (thread-safe, read-only consumer).
#[derive(Clone)]
/// The mappingcache type.
pub struct MappingCache {
    inner: Arc<RwLock<HashMap<String, Arc<DomainMapping>>>>,
    stats: Arc<RwLock<CacheStats>>,
}

#[derive(Debug, Default, Clone, Serialize)]
/// The cachestats type.
pub struct CacheStats {
    /// The size.
    pub size: usize,
    /// The hits.
    pub hits: u64,
    /// The misses.
    pub misses: u64,
}

impl MappingCache {
    /// Handle new.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(CacheStats::default())),
        }
    }

    /// Look up a mapping by hostname.
    /// Fetch it.
    pub fn get(&self, hostname: &str) -> Option<Arc<DomainMapping>> {
        let result = self.inner.read().get(hostname).cloned();
        let mut stats = self.stats.write();
        match &result {
            Some(_) => stats.hits += 1,
            None => stats.misses += 1,
        }
        result
    }

    /// Get cache statistics.
    /// Handle stats.
    pub fn stats(&self) -> CacheStats {
        let mut stats = self.stats.write();
        stats.size = self.inner.read().len();
        stats.clone()
    }
}

impl Default for MappingCache {
    fn default() -> Self {
        Self::new()
    }
}
