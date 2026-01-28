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
            max_requests: 10,
            window_duration: Duration::from_secs(60),
            cleanup_interval: Duration::from_secs(30),
        }
    }
}

struct RateLimitBucket {
    count: u32,
    window_start: Instant,
}

impl RateLimitBucket {
    fn new() -> Self {
        Self {
            count: 0,
            window_start: Instant::now(),
        }
    }

    fn is_expired(&self, window_duration: Duration) -> bool {
        self.window_start.elapsed() > window_duration
    }

    fn record_request(&mut self, window_duration: Duration, max_requests: u32) -> bool {
        let elapsed = self.window_start.elapsed();

        if elapsed > window_duration {
            // Reset window
            self.count = 1;
            self.window_start = Instant::now();
            return true;
        }

        self.count += 1;
        self.count <= max_requests
    }
}

/// Thread-safe rate limiter using a sliding window counter algorithm
#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<RwLock<HashMap<SocketAddr, RateLimitBucket>>>,
    config: RateLimiterConfig,
}

impl RateLimiter {
    /// Create a new rate limiter with default configuration
    pub fn new() -> Self {
        Self::with_config(RateLimiterConfig::default())
    }

    /// Create a rate limiter with custom configuration
    pub fn with_config(config: RateLimiterConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Check if rate limiting is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.max_requests > 0
    }

    /// Check if an address is rate limited
    pub fn is_rate_limited(&self, addr: &SocketAddr) -> bool {
        // Rate limiting is disabled if max_requests is 0
        if self.config.max_requests == 0 {
            return false;
        }

        let mut buckets = self.inner.write();

        if let Some(bucket) = buckets.get(addr) {
            if bucket.is_expired(self.config.window_duration) {
                // Remove expired bucket
                buckets.remove(addr);
                return false;
            }

            // Check if over limit
            return bucket.count >= self.config.max_requests;
        }

        false
    }

    /// Record a request and return true if allowed
    pub fn record_request(&self, addr: &SocketAddr) -> bool {
        // Rate limiting is disabled if max_requests is 0
        if self.config.max_requests == 0 {
            return true;
        }

        let mut buckets = self.inner.write();

        let bucket = buckets.entry(*addr).or_insert_with(RateLimitBucket::new);
        bucket.record_request(self.config.window_duration, self.config.max_requests)
    }

    /// Clean up expired entries
    pub fn cleanup(&self) {
        let mut buckets = self.inner.write();
        let window_duration = self.config.window_duration;

        buckets.retain(|_, bucket| !bucket.is_expired(window_duration));
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Authentication rate limiter for connection attempts
///
/// This provides rate limiting per-peer to prevent brute force attacks
/// on authentication. By default, allows 10 attempts per 60 seconds.
#[derive(Clone)]
pub struct AuthRateLimiter {
    rate_limiter: RateLimiter,
}

impl AuthRateLimiter {
    /// Create a new authentication rate limiter with default settings
    pub fn new() -> Self {
        Self::with_config(RateLimiterConfig::default())
    }

    /// Create an authentication rate limiter with custom configuration
    pub fn with_config(config: RateLimiterConfig) -> Self {
        Self {
            rate_limiter: RateLimiter::with_config(config),
        }
    }

    /// Check if rate limiting is enabled
    pub fn is_enabled(&self) -> bool {
        self.rate_limiter.is_enabled()
    }

    /// Check if the given peer address is currently rate limited
    pub fn is_rate_limited(&self, addr: &SocketAddr) -> bool {
        self.rate_limiter.is_rate_limited(addr)
    }

    /// Record an authentication attempt for the given peer
    /// Returns true if the attempt is allowed, false if rate limited
    pub fn record_attempt(&self, addr: &SocketAddr) -> bool {
        self.rate_limiter.record_request(addr)
    }

    /// Reset rate limit for a specific peer address (e.g., after successful auth)
    pub fn reset(&self, addr: &SocketAddr) {
        let mut buckets = self.rate_limiter.inner.write();
        buckets.remove(addr);
    }

    /// Clean up expired entries to prevent memory growth
    pub fn cleanup(&self) {
        self.rate_limiter.cleanup();
    }
}

impl Default for AuthRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}
