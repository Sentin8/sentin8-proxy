// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Proxy
// SPDX-License-Identifier: Apache-2.0

//! Axum handlers for the Prox management API.

use std::sync::Arc;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;

use crate::backend_registry::SharedServiceBackendRegistry;
use crate::config::ProxConfig;
use crate::mapping_cache::MappingCache;

#[derive(Clone)]
/// app state.
pub struct AppState {
    /// The config.
    pub _config: Arc<ProxConfig>,
    /// The backends.
    pub backends: SharedServiceBackendRegistry,
    /// The mappings.
    pub mappings: MappingCache,
    /// Shield engine (.16 — ): step 5 gates the
    /// management API. The data plane (SNI/L7 bridge) is transport, not
    /// authorization — tenant isolation rides the X-Sentin8-* context
    /// headers the upstream services enforce.
    /// The policy.
    pub policy: std::sync::Arc<crate::policy::Engine>,
    /// Shared Sentin8:Policy admin surface.
    /// The admin.
    pub admin: sentin8::shield::admin::SharedAdminState,
    /// In-flight L7 connection gauge — the drain signal captain polls
    /// via this health payload (`active_connections`, proxy README §7). `None`
    /// when L7 is disabled (all traffic is L4 passthrough, which the
    /// proxy cannot see inside).
    /// The connection gauge.
    pub connection_gauge: Option<std::sync::Arc<crate::tls_proxy::L7ConnectionGauge>>,
    /// PROXY-5 idle upstream pool — occupancy reported in the health
    /// payload (`upstream_pool_size`).
    /// The upstream pool.
    pub upstream_pool: crate::upstream_idle_pool::UpstreamPool,
}

/// Handle health.
pub async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    let mapping_stats = state.mappings.stats();
    let service_counts = state.backends.service_counts();
    let services: Vec<serde_json::Value> = service_counts
        .iter()
        .map(|(svc, n)| serde_json::json!({"service": svc, "instances": n}))
        .collect();
    let mut payload = serde_json::json!({
        "status": "ok",
        "service": "proxy",
        "version": sentin8::build_info::id(),
        "build": sentin8::build_info::build_hash(),
        "mappings": mapping_stats.size,
        "mapping_hits": mapping_stats.hits,
        "mapping_misses": mapping_stats.misses,
        "services": services,
        "total_instances": service_counts.iter().map(|(_, n)| n).sum::<usize>(),
    });
    // In-flight L7 connection gauge (proxy README §7) — the drain signal
    // captain polls during rolling upgrades (captain README §7). Omitted when L7
    // is disabled (L4 passthrough connections are opaque TLS pipes — no
    // in-process gauge exists for them).
    if let Some(ref gauge) = state.connection_gauge {
        payload["active_connections"] = serde_json::Value::from(gauge.active_connections());
    }
    // PROXY-5 upstream pool occupancy (observability — pool health).
    payload["upstream_pool_size"] = serde_json::Value::from(state.upstream_pool.len());
    Json(payload)
}

/// List backends.
pub async fn list_backends(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (axum::http::StatusCode, String)> {
    // Step 5 — Shield decides.
    let a = sentin8::auth::client::verify_bearer_token(&state.admin.auth_client, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:proxy:backends:read"),
    )
    .await?;
    let counts = state.backends.service_counts();
    let services: Vec<serde_json::Value> = counts
        .iter()
        .map(|(svc, n)| serde_json::json!({"service": svc, "instances": n}))
        .collect();
    Ok(Json(serde_json::json!({
        "services": services,
        "total_instances": counts.iter().map(|(_, n)| n).sum::<usize>(),
    })))
}

/// List mappings.
pub async fn list_mappings(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (axum::http::StatusCode, String)> {
    // Step 5 — Shield decides.
    let a = sentin8::auth::client::verify_bearer_token(&state.admin.auth_client, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:proxy:mappings:read"),
    )
    .await?;
    let stats = state.mappings.stats();
    Ok(Json(serde_json::json!({
        "count": stats.size,
        "hits": stats.hits,
        "misses": stats.misses,
    })))
}
