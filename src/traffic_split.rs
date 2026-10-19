// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Proxy
// SPDX-License-Identifier: Apache-2.0

//! Source IP detection - determines whether a connection is internal or external.
//!
//! Internal connections (loopback, private, link-local) get L4 SNI passthrough.
//! External connections (public IPs) get L7 TLS bridging (when enabled).
//!
//! Design:

use std::net::IpAddr;

/// Returns `true` if the source IP is internal (loopback, private, or link-local).
///
/// Internal IPs get L4 SNI passthrough - no TLS termination, no HTTP inspection.
/// External IPs get L7 TLS bridging - terminate TLS, inspect HTTP, enforce policies.
pub fn is_internal_ip(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            v4.is_loopback()        // 127.0.0.0/8
            || v4.is_private()      // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            || v4.is_link_local() // 169.254.0.0/16
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() // ::1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn loopback_v4_is_internal() {
        let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        assert!(is_internal_ip(&addr));
    }

    #[test]
    fn loopback_v6_is_internal() {
        let addr = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(is_internal_ip(&addr));
    }

    #[test]
    fn private_10_is_internal() {
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(is_internal_ip(&addr));
    }

    #[test]
    fn private_172_is_internal() {
        let addr = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
        assert!(is_internal_ip(&addr));
    }

    #[test]
    fn private_192_is_internal() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(is_internal_ip(&addr));
    }

    #[test]
    fn link_local_is_internal() {
        let addr = IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1));
        assert!(is_internal_ip(&addr));
    }

    #[test]
    fn public_ip_is_external() {
        let addr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(!is_internal_ip(&addr));
    }

    #[test]
    fn public_ip_2_is_external() {
        let addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        assert!(!is_internal_ip(&addr));
    }

    #[test]
    fn v6_non_loopback_is_external() {
        let addr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert!(!is_internal_ip(&addr));
    }
}
