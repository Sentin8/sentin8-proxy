// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Proxy
// SPDX-License-Identifier: Apache-2.0

//! Sys event constants shared by the proxy's MemBus consumers.
//!
//! Mirrors `services/sys/src/domain_events.rs` - keep in sync. The proxy
//! cannot depend on the sys service crate (verticals ← sentin8 one-way;
//! platform services are peers), so the family name lives here.

/// The membus family (stream/channel suffix) for sys domain notifications.
pub const DOMAIN_FAMILY: &str = "sys-domain";
/// The ephemeral event type carried in the envelope (checked by future
/// surgical-refresh consumers; the proxy reloads on any frame today).
#[allow(dead_code)]
pub const DOMAIN_EVENT: &str = "sentin8:sys:domain:changed";
