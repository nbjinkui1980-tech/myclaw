//! Soft per-connection pacing and reconnect backoff.
use std::time::Duration;

use tokio::time::Instant;

/// Token bucket that makes the reader wait instead of dropping frames: an
/// authenticated peer going fast is slowed through TCP back-pressure, not
/// disconnected or cut off from its own messages.
pub(super) struct TokenBucket {
    capacity: f64,
    tokens: f64,
    per_second: f64,
    refilled_at: Instant,
}

impl TokenBucket {
    pub fn new(frames_per_second: u32) -> Self {
        let rate = f64::from(frames_per_second.max(1));
        Self {
            capacity: rate,
            tokens: rate,
            per_second: rate,
            refilled_at: Instant::now(),
        }
    }

    pub async fn acquire(&mut self) {
        loop {
            let now = Instant::now();
            let elapsed = now.duration_since(self.refilled_at).as_secs_f64();
            self.tokens = (self.tokens + elapsed * self.per_second).min(self.capacity);
            self.refilled_at = now;
            if self.tokens >= 1.0 {
                self.tokens -= 1.0;
                return;
            }
            let wait = (1.0 - self.tokens) / self.per_second;
            tokio::time::sleep(Duration::from_secs_f64(wait)).await;
        }
    }
}
/// Exponential reconnect delay with jitter. `reset` is called only after a
/// frame the stream control accepted, so a peer that accepts the connection
/// and drops it never earns a short retry.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BackoffPolicy {
    pub initial: Duration,
    pub max: Duration,
    /// Extra delay of up to this fraction of the base delay (0.0 disables).
    pub jitter_fraction: f64,
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(60),
            jitter_fraction: 0.25,
        }
    }
}

pub(super) struct Backoff {
    policy: BackoffPolicy,
    attempt: u32,
}

impl Backoff {
    pub fn new(policy: BackoffPolicy) -> Self {
        Self { policy, attempt: 0 }
    }

    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    pub fn next_delay(&mut self) -> Duration {
        let factor = 1u32.checked_shl(self.attempt.min(16)).unwrap_or(u32::MAX);
        let base = self
            .policy
            .initial
            .saturating_mul(factor)
            .min(self.policy.max);
        self.attempt = self.attempt.saturating_add(1);
        if self.policy.jitter_fraction <= 0.0 {
            return base;
        }
        use rand::RngExt;
        let jitter = rand::rng().random_range(0.0..=self.policy.jitter_fraction);
        base.mul_f64(1.0 + jitter).min(self.policy.max)
    }
}
