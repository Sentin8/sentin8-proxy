// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Proxy
// SPDX-License-Identifier: Apache-2.0

//! Sentin8:Policy integration for proxy (.16).
//!
//! Thin re-export of the shared bridge (`sentin8::shield::runtime`) — the
//! consolidated implementation every service uses. The proxy's SNI/L7 data
//! plane is transport, not authorization: tenant isolation rides the
//! `X-Sentin8-*` context headers the upstream services enforce. The Shield
//! engine gates the management API (step 5).

#[allow(unused_imports)]
pub use sentin8::shield::runtime::{
    check_policy, evaluate_full, init_shared_deps, policy_bus_client, request_ctx, require_policy,
    spawn_hot_reload,
};
pub use sentin8::shield::PolicyEngine as Engine;
