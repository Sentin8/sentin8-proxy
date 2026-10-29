// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Proxy
// SPDX-License-Identifier: Apache-2.0

//! Sentin8:Proxy self-registration (self-registration ).
//!
//! The proxy describes itself to `vertical enroll` via `--print-registration`.
//! Its M2M grants declare the workload identities it registers:
//! - `sentin8:proxy` - future direct-produce workloads (bus produce scope).
//! - `sentin8:proxy-policy` - the Shield hot-reload consumer
//!   (`policy_bus_client("sentin8:proxy")` → `{service}-policy`) AND the
//!   Shield decision stat emitter (`boot_full` →
//!   `init_stat_emitter_for_service` → `{short}-policy`, scope
//!   `sentin8:stat:measure` - same workload, two consumers, hence both
//!   scopes).

use sentin8::registration::{AdminScope, CrossSchemaGrant, M2mGrant, PgRole, Registration};

const M2M_GRANTS: &[M2mGrant] = &[
    M2mGrant {
        workload: "sentin8:proxy",
        scopes: &["sentin8:bus:produce"],
    },
    M2mGrant {
        workload: "sentin8:proxy-policy",
        scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
    },
    // (design/sentin8-vertical-data-plane-contract.md §VDC.7): the database-free HostContextResolver’s resolve workload - cache miss calls Sys `GET /v1/resolve/hostname`.
    M2mGrant {
        workload: "sentin8-proxy-tls",
        scopes: &["sentin8:sys:instances:read"],
    },
];

/// The OpenAPI spec closure - the proxy carries no utoipa spec (its surface
/// is the SNI/L7 routing, not CLI-derivable commands), so the closure emits
/// `null` (the enroll path skips empty openapi output).
fn openapi_spec() -> serde_json::Value {
    serde_json::Value::Null
}

// Declared cross-schema reads (architecture-principles §6.6a - explicit,
// never blanket): `domain_resolver.rs` resolves hostnames from the platform
// org/env rows + app instances on cache-miss (crates-tls HostContextResolver
// fallback). SELECT-only; the proxy holds no cross-schema writes.
const PG_ROLES: &[PgRole] = &[PgRole {
    scope: "sentin8:proxy:admin,sentin8:proxy:backends:read,sentin8:proxy:mappings:read",
    role: "sentin8_proxy_service",
    bypass_rls: false,
    database: "sentin8",
    cross_schema_grants: &[
        // D7-PXY: the orgs/envs/app_instances SELECTs are RETIRED -
        // platform SNIs resolve statically, tenant SNIs ride Sys's owner
        // API (`GET /v1/resolve/hostname`, `sentin8-proxy-tls` workload).
        // The subdomain→service map is read on every domain-event reload +
        // 30s poll (crates/config `load_subdomain_map`) and by the embedded
        // TLS context resolver (`resolve_service_name_in_tx`) -,
        // proxy DESIGN §3.
        CrossSchemaGrant {
            schema: "sys",
            table: "vertical_services",
            privilege: "SELECT",
        },
    ],
}];

pub fn print(section: Option<String>) -> anyhow::Result<()> {
    let reg = Registration {
        service_type: "sentin8:proxy",
        subdomain: "proxy",
        health_path: "/v1/health",
        admin_scopes: &[AdminScope::Tuple(
            "sentin8:proxy:admin",
            "sentin8:proxy:admin",
        )],
        error_codes: &[],
        consent_providers: &[],
        consent_flows: &[],
        admin_ui: None,
        sql_migrations: vec![],
        pg_roles: PG_ROLES,
        policies: &[],
        relations: &[],
        event_triggers: &[],
        schedules: &[],
        audit_findings: None,
        service_actions: None,
        m2m_grants: Some(M2M_GRANTS),
        openapi_url: "/openapi.json",
        openapi: openapi_spec,
    };
    sentin8::registration::print_registration(section, &reg, openapi_spec)
}
