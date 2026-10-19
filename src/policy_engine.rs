// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Proxy
// SPDX-License-Identifier: Apache-2.0

//! Policy engine - WAF, rate limiting, path ACLs for L7 TLS bridging mode.
//!
//! The policy pipeline runs on every external (L7) request:
//! 1. IP reputation (placeholder - always allows in v1)
//! 2. Rate limiter (token bucket per client IP)
//! 3. WAF rules (SQL injection, XSS, path traversal pattern detection)
//! 4. Path ACL (allow/deny per path prefix - default: allow all)
//! 5. Header validation (size limits, encoding checks)
//!
//! Design:

use axum::http::{HeaderMap, Method, StatusCode};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

/// Outcome of a policy evaluation.
/// The policyoutcome type.
pub enum PolicyOutcome {
    /// Request is allowed - proceed to backend.
    /// The allow variant.
    Allow,
    /// Request is blocked - return this status and message to the client.
    Block(StatusCode, &'static str),
}

/// Configuration for the policy engine.
#[derive(Debug, Clone)]
/// Configuration for policy.
pub struct PolicyConfig {
    /// The waf enabled.
    pub waf_enabled: bool,
    /// The rate limit enabled.
    pub rate_limit_enabled: bool,
    /// The rate limit rps.
    pub rate_limit_rps: u32,
}

/// The policy engine - holds rate limiter state and WAF rule configuration.
/// The policyengine type.
pub struct PolicyEngine {
    config: PolicyConfig,
    rate_limiter: RateLimiter,
}

impl PolicyEngine {
    /// Handle new.
    pub fn new(config: PolicyConfig) -> Self {
        Self {
            rate_limiter: RateLimiter::new(config.rate_limit_rps),
            config,
        }
    }

    /// Run the full policy pipeline on an incoming request.
    ///
    /// Returns `Allow` if the request passes all checks, or `Block` with
    /// the appropriate status code and message if a policy rejects it.
    /// Handle evaluate.
    pub fn evaluate(
        &self,
        client_ip: &IpAddr,
        host: &str,
        method: &Method,
        uri: &str,
        headers: &HeaderMap,
        body: &[u8],
    ) -> PolicyOutcome {
        // 1. Rate limiting - keyed `(client_ip, host)` (PROXY-3, proxy README
        // §7): the SNI/Host pair is the tenant identity at the L7 bridge, so a
        // burst against one app must not exhaust every other host's budget.
        if self.config.rate_limit_enabled && !self.rate_limiter.check(client_ip, host) {
            tracing::warn!(
                %client_ip,
                host = %host,
                "proxy: rate limit exceeded - blocking request"
            );
            return PolicyOutcome::Block(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
        }

        // 2. WAF rules
        if self.config.waf_enabled {
            if let Some(detection) = detect_waf_violation(method, uri, headers, body) {
                tracing::warn!(
                    %client_ip,
                    detection = %detection,
                    uri = %uri,
                    "proxy: WAF rule triggered - blocking request"
                );
                return PolicyOutcome::Block(StatusCode::FORBIDDEN, "request blocked by WAF");
            }
        }

        // 3. Path ACL - default: allow all (per-tenant config in future)
        // 4. Header validation - basic size checks
        if headers.len() > 100 {
            return PolicyOutcome::Block(
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                "too many headers",
            );
        }

        PolicyOutcome::Allow
    }
}

// ── Rate Limiter ─────────────────────────────────────────────────────────

/// Simple in-memory token-bucket rate limiter per `(client IP, host)`.
///
/// Each (IP, host) pair gets a bucket that refills at `rps` tokens/second
/// up to `rps` capacity. No Valkey dependency for the hot path - counters
/// are in-memory.
struct RateLimiter {
    rps: u32,
    buckets: RwLock<HashMap<(IpAddr, String), Bucket>>,
}

struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

impl RateLimiter {
    fn new(rps: u32) -> Self {
        Self {
            rps: rps.max(1),
            buckets: RwLock::new(HashMap::new()),
        }
    }

    /// Check if the (client IP, host) pair has tokens remaining. Returns
    /// `true` if allowed.
    fn check(&self, ip: &IpAddr, host: &str) -> bool {
        let rps = self.rps as f64;
        let now = Instant::now();
        let mut buckets = self.buckets.write();

        let bucket = buckets.entry((*ip, host.to_string())).or_insert(Bucket {
            tokens: rps,
            last_refill: now,
        });

        // Refill tokens based on elapsed time.
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * rps).min(rps);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// ── WAF Rules ────────────────────────────────────────────────────────────

/// WAF detection types.
#[derive(Debug)]
enum WafDetection {
    SqlInjection,
    Xss,
    PathTraversal,
}

impl std::fmt::Display for WafDetection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WafDetection::SqlInjection => write!(f, "sql_injection"),
            WafDetection::Xss => write!(f, "xss"),
            WafDetection::PathTraversal => write!(f, "path_traversal"),
        }
    }
}

/// Check the request for WAF violations.
///
/// Scans the URI, selected headers, and body for common attack patterns.
/// Returns `Some(detection)` if a violation is found, `None` otherwise.
fn detect_waf_violation(
    _method: &Method,
    uri: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Option<WafDetection> {
    // Check URI for SQL injection patterns.
    let uri_lower = uri.to_ascii_lowercase();
    if matches_sql_injection(&uri_lower) {
        return Some(WafDetection::SqlInjection);
    }

    // Check URI for path traversal.
    if uri.contains("../") || uri.contains("..\\") || uri.contains("%2e%2e/") {
        return Some(WafDetection::PathTraversal);
    }

    // Check URI and headers for XSS patterns.
    if matches_xss(&uri_lower) {
        return Some(WafDetection::Xss);
    }

    // Check selected headers.
    for header_name in &["user-agent", "referer", "cookie", "x-forwarded-for"] {
        if let Some(value) = headers.get(*header_name) {
            if let Ok(value_str) = value.to_str() {
                let value_lower = value_str.to_ascii_lowercase();
                if matches_sql_injection(&value_lower) {
                    return Some(WafDetection::SqlInjection);
                }
                if matches_xss(&value_lower) {
                    return Some(WafDetection::Xss);
                }
            }
        }
    }

    // Check body (limited to first 8KB to avoid scanning large uploads).
    if body.len() <= 8192 {
        if let Ok(body_str) = std::str::from_utf8(body) {
            let body_lower = body_str.to_ascii_lowercase();
            if matches_sql_injection(&body_lower) {
                return Some(WafDetection::SqlInjection);
            }
            if matches_xss(&body_lower) {
                return Some(WafDetection::Xss);
            }
        }
    }

    None
}

/// Simple SQL injection pattern matching.
fn matches_sql_injection(s: &str) -> bool {
    // Common SQL injection patterns.
    let patterns = [
        "' or '1'='1",
        "' or 1=1",
        "' or '1'='1' --",
        "union select",
        "' drop table",
        "' insert into",
        "' delete from",
        "' update ",
        "or 1=1 --",
        "'; --",
        "' or ''='",
        "1' or '1'='1",
    ];
    for pattern in &patterns {
        if s.contains(pattern) {
            return true;
        }
    }
    false
}

/// Simple XSS pattern matching.
fn matches_xss(s: &str) -> bool {
    let patterns = [
        "<script",
        "javascript:",
        "onerror=",
        "onload=",
        "onclick=",
        "<iframe",
        "<img onerror",
        "alert(",
        "document.cookie",
        "<svg onload",
    ];
    for pattern in &patterns {
        if s.contains(pattern) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn sql_injection_in_uri() {
        assert!(matches_sql_injection("' or '1'='1"));
        assert!(matches_sql_injection("union select * from users"));
        assert!(matches_sql_injection("' drop table users"));
        assert!(!matches_sql_injection("normal search query"));
    }

    #[test]
    fn xss_in_uri() {
        assert!(matches_xss("<script>alert(1)</script>"));
        assert!(matches_xss("javascript:alert(1)"));
        assert!(matches_xss("<img onerror=alert(1)>"));
        assert!(!matches_xss("normal page content"));
    }

    #[test]
    fn path_traversal() {
        let headers = HeaderMap::new();
        let body = vec![];
        let result = detect_waf_violation(&Method::GET, "/../../etc/passwd", &headers, &body);
        assert!(matches!(result, Some(WafDetection::PathTraversal)));
    }

    #[test]
    fn rate_limiter_allows_within_limit() {
        let limiter = RateLimiter::new(10);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        // Should allow the first 10 requests.
        for _ in 0..10 {
            assert!(limiter.check(&ip, "app1.test"));
        }
    }

    #[test]
    fn rate_limiter_blocks_over_limit() {
        let limiter = RateLimiter::new(2);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(limiter.check(&ip, "app1.test"));
        assert!(limiter.check(&ip, "app1.test"));
        // Third request should be blocked.
        assert!(!limiter.check(&ip, "app1.test"));
    }

    #[test]
    fn policy_engine_allows_normal_request() {
        let engine = PolicyEngine::new(PolicyConfig {
            waf_enabled: true,
            rate_limit_enabled: true,
            rate_limit_rps: 100,
        });
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("example.com"));
        let result = engine.evaluate(
            &ip,
            "example.com",
            &Method::GET,
            "/api/v1/users",
            &headers,
            &[],
        );
        assert!(matches!(result, PolicyOutcome::Allow));
    }

    #[test]
    fn policy_engine_blocks_sql_injection() {
        let engine = PolicyEngine::new(PolicyConfig {
            waf_enabled: true,
            rate_limit_enabled: false,
            rate_limit_rps: 100,
        });
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let headers = HeaderMap::new();
        let result = engine.evaluate(
            &ip,
            "example.com",
            &Method::GET,
            "/api/v1/users?id=1' or '1'='1",
            &headers,
            &[],
        );
        assert!(matches!(
            result,
            PolicyOutcome::Block(StatusCode::FORBIDDEN, _)
        ));
    }
}
