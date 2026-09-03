//! Rate limiting middleware for the central proxy.
//!
//! A simple in-memory token-bucket rate limiter, keyed by client IP address.
//! This prevents a single relay (or attacker who has compromised the mTLS
//! channel) from flooding the backend with requests.
//!
//! # Security
//!
//! - Limits requests per IP per window (default: 60 requests / 60 seconds).
//! - Returns `429 Too Many Requests` with a `Retry-After` header when the
//!   limit is exceeded.
//! - In `dev_mode`, rate limiting is disabled (the dev stack uses a single
//!   relay with no rate concerns).
//! - The bucket state is held in a `Mutex<HashMap<IpAddr, BucketState>>` —
//!   simple and sufficient for a single-process central proxy. For a
//!   horizontally-scaled deployment, a shared store (Redis) would be needed.
//!
//! # Algorithm
//!
//! Token bucket: each IP gets a bucket with a capacity and a refill rate.
//! On each request, we try to take one token. If the bucket is empty, the
//! request is rejected with 429. Tokens refill at a fixed rate up to the
//! capacity.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use super::AppState;

/// The default rate limit: 60 requests per 60 seconds per IP.
pub const DEFAULT_RATE_LIMIT: u32 = 60;

/// The default rate limit window: 60 seconds.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(60);

/// The token-bucket state for a single IP.
#[derive(Debug, Clone)]
struct BucketState {
    /// Remaining tokens in the bucket.
    tokens: f64,
    /// Last time the bucket was updated.
    last_update: Instant,
}

/// The rate limiter state, shared across all requests.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    /// The maximum number of tokens (burst capacity).
    capacity: f64,
    /// The refill rate in tokens per second.
    refill_per_second: f64,
    /// The per-IP bucket states.
    buckets: Arc<Mutex<HashMap<IpAddr, BucketState>>>,
    /// The window duration, used to compute the eviction threshold.
    window: Duration,
    /// Monotonic call counter for amortized eviction.
    call_count: Arc<Mutex<u64>>,
}

/// Evict buckets that have been idle for at least this many window periods.
const EVICT_AFTER_WINDOWS: u64 = 10;
/// Evict on every Nth call to try_take to amortize the cost.
const EVICT_EVERY_N_CALLS: u64 = 128;

impl RateLimiter {
    /// Creates a new `RateLimiter` with the given capacity and window.
    ///
    /// # Arguments
    ///
    /// * `capacity` — The maximum number of requests allowed in the window
    ///   (burst capacity).
    /// * `window` — The time window over which `capacity` requests are
    ///   allowed.
    #[must_use]
    pub fn new(capacity: u32, window: Duration) -> Self {
        let refill_per_second = f64::from(capacity) / window.as_secs_f64();
        Self {
            capacity: f64::from(capacity),
            refill_per_second,
            buckets: Arc::new(Mutex::new(HashMap::new())),
            window,
            call_count: Arc::new(Mutex::new(0)),
        }
    }

    /// Tries to take a token from the bucket for the given IP.
    ///
    /// Returns `Ok(())` if the request is allowed, or `Err(retry_after_secs)`
    /// with the number of seconds to wait before retrying.
    ///
    /// # Errors
    ///
    /// Returns `Err` with the retry-after duration in seconds if the rate
    /// limit has been exceeded.
    pub fn try_take(&self, ip: IpAddr) -> Result<(), u64> {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().map_err(|_| 1u64)?;

        // Amortized eviction: every EVICT_EVERY_N_CALLS, remove buckets that
        // have been idle for at least EVICT_AFTER_WINDOWS window periods.
        // This bounds memory growth from unique IPs without sweeping on
        // every request.
        if let Ok(mut count) = self.call_count.lock() {
            *count = count.wrapping_add(1);
            if *count % EVICT_EVERY_N_CALLS == 0 {
                self.evict_stale_locked(&mut buckets, now);
            }
        }

        let entry = buckets.entry(ip).or_insert(BucketState {
            tokens: self.capacity,
            last_update: now,
        });

        // Refill tokens based on elapsed time.
        let elapsed = now.duration_since(entry.last_update).as_secs_f64();
        entry.tokens = (entry.tokens + elapsed * self.refill_per_second).min(self.capacity);
        entry.last_update = now;

        if entry.tokens >= 1.0 {
            entry.tokens -= 1.0;
            Ok(())
        } else {
            // Calculate retry-after: time until one token refills.
            let tokens_needed = 1.0 - entry.tokens;
            let retry_after_secs = (tokens_needed / self.refill_per_second).ceil() as u64;
            Err(retry_after_secs.max(1))
        }
    }

    /// Removes buckets whose `last_update` is older than
    /// `EVICT_AFTER_WINDOWS * window`. The caller must hold the bucket lock.
    fn evict_stale_locked(&self, buckets: &mut HashMap<IpAddr, BucketState>, now: Instant) {
        let threshold = self.window * EVICT_AFTER_WINDOWS as u32;
        buckets.retain(|_, state| now.duration_since(state.last_update) < threshold);
    }

    /// Returns the number of tracked IP buckets. Primarily for testing and
    /// observability.
    #[cfg(test)]
    fn bucket_count(&self) -> usize {
        self.buckets.lock().map(|b| b.len()).unwrap_or(0)
    }
}

/// The rate-limiting middleware.
///
/// Extracts the client IP from the connection info, checks the rate limiter,
/// and returns `429 Too Many Requests` if the limit is exceeded. In dev mode,
/// the middleware is a no-op.
pub async fn rate_limit_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    // Skip rate limiting for health check and in dev mode.
    if request.uri().path() == "/healthz" || state.config.dev_mode {
        return next.run(request).await;
    }

    let limiter = match &state.rate_limiter {
        Some(l) => l,
        None => return next.run(request).await,
    };

    // Extract the client IP from the connection info. The server is started
    // with `.into_make_service_with_connect_info()` so every request carries
    // `ConnectInfo<SocketAddr>` in its extensions. The fallback to
    // `0.0.0.0` only triggers if a future code path forgets to inject it.
    let ip = request
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));

    match limiter.try_take(ip) {
        Ok(()) => next.run(request).await,
        Err(retry_after) => {
            tracing::warn!(
                ip = %ip,
                retry_after_secs = retry_after,
                "rate limit exceeded"
            );
            // A bare 429 leaves agents guessing when to retry. Return the
            // standard Retry-After header plus a JSON body so well-behaved
            // clients back off for exactly as long as the bucket needs.
            too_many_requests_response(retry_after)
        }
    }
}

/// Builds a 429 response carrying a `Retry-After` header (in seconds) and
/// a JSON body with the same value, so agents can back off for exactly as
/// long as the token bucket needs to refill one token.
#[must_use]
pub fn too_many_requests_response(retry_after: u64) -> Response {
    let body = serde_json::json!({
        "error": {
            "message": "rate limit exceeded",
            "type": "rate_limit_error",
            "retry_after_secs": retry_after,
        }
    });
    (
        StatusCode::TOO_MANY_REQUESTS,
        [
            ("content-type", "application/json"),
            ("retry-after", retry_after.to_string().as_str()),
        ],
        body.to_string(),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::net::Ipv4Addr;

    fn test_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    #[test]
    fn allows_requests_up_to_capacity() {
        let limiter = RateLimiter::new(5, Duration::from_secs(60));
        for _ in 0..5 {
            assert!(
                limiter.try_take(test_ip()).is_ok(),
                "should allow up to capacity"
            );
        }
        // The 6th request should be rejected.
        assert!(
            limiter.try_take(test_ip()).is_err(),
            "should reject after capacity"
        );
    }

    #[test]
    fn returns_retry_after_when_exceeded() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60));
        assert!(limiter.try_take(test_ip()).is_ok());
        let err = limiter.try_take(test_ip()).unwrap_err();
        // retry_after should be at least 1 second.
        assert!(err >= 1, "retry_after should be >= 1, got {err}");
    }

    #[test]
    fn different_ips_have_independent_buckets() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60));
        let ip1 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        assert!(limiter.try_take(ip1).is_ok());
        assert!(
            limiter.try_take(ip2).is_ok(),
            "different IP should have its own bucket"
        );
        // Both should now be exhausted.
        assert!(limiter.try_take(ip1).is_err());
        assert!(limiter.try_take(ip2).is_err());
    }

    #[test]
    fn refills_over_time() {
        // 1 request per 10ms window for fast testing.
        let limiter = RateLimiter::new(1, Duration::from_millis(10));
        assert!(limiter.try_take(test_ip()).is_ok());
        assert!(
            limiter.try_take(test_ip()).is_err(),
            "should be empty immediately"
        );
        // Wait for refill.
        std::thread::sleep(Duration::from_millis(15));
        assert!(
            limiter.try_take(test_ip()).is_ok(),
            "should refill after window"
        );
    }

    #[test]
    fn evicts_stale_buckets() {
        // Use a 10ms window so the eviction threshold (10x = 100ms) is
        // reachable quickly. Capacity is large so we don't exhaust the
        // bucket while triggering eviction.
        let limiter = RateLimiter::new(1000, Duration::from_millis(10));

        // Create buckets for several IPs.
        for i in 0..5_u8 {
            let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, i));
            assert!(limiter.try_take(ip).is_ok());
        }
        assert_eq!(limiter.bucket_count(), 5, "five buckets created");

        // Wait longer than the eviction threshold (10 * 10ms = 100ms).
        std::thread::sleep(Duration::from_millis(150));

        // Trigger eviction by making EVICT_EVERY_N_CALLS calls. The stale
        // buckets should be evicted; only the IP we just used remains.
        for _ in 0..EVICT_EVERY_N_CALLS {
            assert!(limiter.try_take(test_ip()).is_ok());
        }
        assert_eq!(
            limiter.bucket_count(),
            1,
            "stale buckets must be evicted, only the active IP should remain"
        );
    }

    #[test]
    fn eviction_preserves_recently_used_buckets() {
        let limiter = RateLimiter::new(1000, Duration::from_millis(10));

        let recent_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let stale_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));

        // Eviction threshold: EVICT_AFTER_WINDOWS (10) * 10ms = 100ms idle.
        // Sleeps only ever overshoot (never undershoot), so design the
        // margins asymmetrically to stay robust on loaded CI runners:
        // - stale_ip must be *guaranteed* past the threshold: it is at
        //   least 150ms idle by eviction time (50ms margin), and any
        //   scheduling overshoot only makes it staler.
        // - recent_ip must stay *safely under* the threshold: only 20ms
        //   elapse after its creation before eviction runs, leaving an
        //   80ms overshoot budget before it could be evicted in error.
        // Create both buckets.
        assert!(limiter.try_take(stale_ip).is_ok());
        // Wait so stale_ip is already well past the eviction threshold.
        std::thread::sleep(Duration::from_millis(150));
        assert!(limiter.try_take(recent_ip).is_ok());
        // Brief wait: recent_ip stays far below the threshold.
        std::thread::sleep(Duration::from_millis(20));

        // Trigger eviction.
        for _ in 0..EVICT_EVERY_N_CALLS {
            assert!(limiter.try_take(test_ip()).is_ok());
        }
        assert_eq!(
            limiter.bucket_count(),
            2,
            "recent_ip and test_ip must survive; only stale_ip should be evicted"
        );
        // Verify recent_ip still has a working bucket (not exhausted).
        assert!(limiter.try_take(recent_ip).is_ok());
    }
}
