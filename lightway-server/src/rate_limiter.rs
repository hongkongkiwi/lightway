#![allow(dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::RwLock;

/// Rate limiter configuration
#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    /// Maximum requests per window
    pub max_requests: u32,
    /// Window duration
    pub window_duration: Duration,
    /// Cleanup interval for expired entries
    pub cleanup_interval: Duration,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            max_requests: 10,          // 10 attempts per window
            window_duration: Duration::from_secs(60),  // 1 minute window
            cleanup_interval: Duration::from_secs(300), // Cleanup every 5 minutes
        }
    }
}

/// Rate limiter entry for a single client
#[derive(Debug, Clone)]
struct RateLimitEntry {
    requests: u32,
    window_start: Instant,
}

impl RateLimitEntry {
    fn is_rate_limited(&mut self, config: &RateLimiterConfig) -> bool {
        let now = Instant::now();

        // Reset window if expired
        if now.duration_since(self.window_start) > config.window_duration {
            self.window_start = now;
            self.requests = 0;
        }

        self.requests += 1;
        self.requests > config.max_requests
    }
}

/// Thread-safe rate limiter for authentication endpoints
#[derive(Clone)]
pub struct AuthRateLimiter {
    inner: Arc<InnerRateLimiter>,
}

struct InnerRateLimiter {
    config: RateLimiterConfig,
    /// Map of client IP to rate limit state
    clients: RwLock<HashMap<SocketAddr, RateLimitEntry>>,
}

impl AuthRateLimiter {
    /// Create a new rate limiter with default config
    pub fn new() -> Self {
        Self::with_config(RateLimiterConfig::default())
    }

    /// Create a rate limiter with custom config
    pub fn with_config(config: RateLimiterConfig) -> Self {
        Self {
            inner: Arc::new(InnerRateLimiter {
                config,
                clients: RwLock::new(HashMap::new()),
            }),
        }
    }

    /// Check if an IP is rate limited
    /// Returns true if the request should be denied
    pub fn is_rate_limited(&self, addr: &SocketAddr) -> bool {
        let mut clients = self.inner.clients.write();
        let entry = clients.entry(*addr).or_insert_with(|| RateLimitEntry {
            requests: 0,
            window_start: Instant::now(),
        });
        entry.is_rate_limited(&self.inner.config)
    }

    /// Get remaining requests for an IP in current window
    pub fn remaining_requests(&self, addr: &SocketAddr) -> u32 {
        let clients = self.inner.clients.read();
        if let Some(entry) = clients.get(addr) {
            let now = Instant::now();
            let elapsed = now.duration_since(entry.window_start);
            if elapsed > self.inner.config.window_duration {
                return self.inner.config.max_requests;
            }
            let remaining = self.inner.config.max_requests.saturating_sub(entry.requests);
            remaining.saturating_sub(1) // Account for current request
        } else {
            self.inner.config.max_requests
        }
    }

    /// Clean up expired entries (call periodically to prevent memory leaks)
    pub fn cleanup(&self) {
        let mut clients = self.inner.clients.write();
        let now = Instant::now();
        clients.retain(|_, entry| {
            now.duration_since(entry.window_start) < self.inner.config.window_duration * 2
        });
    }

    /// Reset rate limit for a specific IP (e.g., after successful auth)
    pub fn reset(&self, addr: &SocketAddr) {
        let mut clients = self.inner.clients.write();
        clients.remove(addr);
    }
}

impl Default for AuthRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_rate_limiter_allows_requests() {
        let limiter = AuthRateLimiter::new();
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        // First 10 requests should be allowed
        for i in 0..10 {
            assert!(!limiter.is_rate_limited(&addr), "Request {} should be allowed", i);
        }
    }

    #[test]
    fn test_rate_limiter_blocks_excess() {
        let limiter = AuthRateLimiter::new();
        let addr: SocketAddr = "127.0.0.1:12346".parse().unwrap();

        // Make max_requests requests
        for _ in 0..10 {
            limiter.is_rate_limited(&addr);
        }

        // Next one should be blocked
        assert!(limiter.is_rate_limited(&addr));
    }

    #[test]
    fn test_rate_limiter_reset() {
        let limiter = AuthRateLimiter::new();
        let addr: SocketAddr = "127.0.0.1:12347".parse().unwrap();

        // Exhaust rate limit
        for _ in 0..11 {
            limiter.is_rate_limited(&addr);
        }

        // Reset
        limiter.reset(&addr);

        // Should be allowed again
        assert!(!limiter.is_rate_limited(&addr));
    }

    #[test]
    fn test_rate_limiter_window_reset() {
        let config = RateLimiterConfig {
            max_requests: 3,
            window_duration: Duration::from_millis(100),
            cleanup_interval: Duration::from_secs(1),
        };
        let limiter = AuthRateLimiter::with_config(config);
        let addr: SocketAddr = "127.0.0.1:12348".parse().unwrap();

        // Exhaust rate limit
        for _ in 0..4 {
            limiter.is_rate_limited(&addr);
        }
        assert!(limiter.is_rate_limited(&addr));

        // Wait for window to expire
        thread::sleep(Duration::from_millis(150));

        // Should be allowed again
        assert!(!limiter.is_rate_limited(&addr));
    }

    #[test]
    fn test_rate_limiter_different_ips() {
        let limiter = AuthRateLimiter::new();
        let addr1: SocketAddr = "127.0.0.1:12349".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:12350".parse().unwrap();

        // Exhaust rate limit for addr1
        for _ in 0..11 {
            limiter.is_rate_limited(&addr1);
        }

        // addr1 should be blocked
        assert!(limiter.is_rate_limited(&addr1));

        // addr2 should still be allowed
        assert!(!limiter.is_rate_limited(&addr2));
    }
}
