//! A token bucket per source for the unauthenticated endpoints.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};

/// One source's allowance.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: u32,
    /// When `tokens` was last brought up to date, in unix seconds.
    at: i64,
}

impl Bucket {
    /// The tokens it holds at `now`. A clock stepped backwards gives nothing,
    /// and takes nothing away.
    fn refilled(self, now: i64, rate_per_second: u32, burst: u32) -> u32 {
        let elapsed = now.saturating_sub(self.at).max(0);
        let earned = u32::try_from(elapsed)
            .unwrap_or(u32::MAX)
            .saturating_mul(rate_per_second);
        self.tokens.saturating_add(earned).min(burst)
    }
}

/// What a source is limited as. Someone with one IPv6 address usually has a
/// whole /64 to send from, so that is what counts as one source. An IPv4 address
/// on an IPv6 socket counts as the IPv4 address.
pub(crate) fn source_key(source: IpAddr) -> IpAddr {
    match source.to_canonical() {
        IpAddr::V6(address) => {
            let bits = address.to_bits() & !u128::from(u64::MAX);
            IpAddr::V6(Ipv6Addr::from_bits(bits))
        }
        v4 @ IpAddr::V4(_) => v4,
    }
}

/// Token buckets, bounded in the number of sources they remember.
#[derive(Debug)]
pub(super) struct RateLimiter {
    rate_per_second: u32,
    burst: u32,
    max_sources: usize,
    buckets: HashMap<IpAddr, Bucket>,
}

impl RateLimiter {
    pub(super) fn new(rate_per_second: u32, burst: u32, max_sources: usize) -> Self {
        Self {
            rate_per_second,
            burst,
            max_sources,
            buckets: HashMap::new(),
        }
    }

    /// Whether `source` may make a request now, taking a token if it may.
    pub(super) fn allow(&mut self, source: IpAddr, now: i64) -> bool {
        let key = source_key(source);
        let tokens = if let Some(bucket) = self.buckets.get(&key) {
            bucket.refilled(now, self.rate_per_second, self.burst)
        } else {
            if self.buckets.len() >= self.max_sources {
                self.forget_full_buckets(now);
                if self.buckets.len() >= self.max_sources {
                    return false;
                }
            }
            self.burst
        };
        let Some(left) = tokens.checked_sub(1) else {
            self.buckets.insert(key, Bucket { tokens, at: now });
            return false;
        };
        self.buckets.insert(
            key,
            Bucket {
                tokens: left,
                at: now,
            },
        );
        true
    }

    /// A full bucket says nothing a new one would not, so forgetting it costs
    /// its source nothing.
    fn forget_full_buckets(&mut self, now: i64) {
        let (rate, burst) = (self.rate_per_second, self.burst);
        self.buckets
            .retain(|_, bucket| bucket.refilled(now, rate, burst) < burst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn a_source_gets_its_burst_then_its_rate() {
        let mut limiter = RateLimiter::new(2, 3, 16);
        let source = ip("192.0.2.1");
        assert!((0..3).all(|_| limiter.allow(source, 100)));
        assert!(!limiter.allow(source, 100));
        // Refused requests do not push the next token further away.
        assert!(!limiter.allow(source, 100));
        assert!(limiter.allow(source, 101));
        assert!(limiter.allow(source, 101));
        assert!(!limiter.allow(source, 101));
        // Never more than the burst, however long it has been.
        assert!((0..3).all(|_| limiter.allow(source, 1_000_000)));
        assert!(!limiter.allow(source, 1_000_000));
    }

    #[test]
    fn sources_do_not_share_an_allowance() {
        let mut limiter = RateLimiter::new(1, 1, 16);
        assert!(limiter.allow(ip("192.0.2.1"), 100));
        assert!(!limiter.allow(ip("192.0.2.1"), 100));
        assert!(limiter.allow(ip("192.0.2.2"), 100));
    }

    #[test]
    fn a_v6_prefix_is_one_source_and_a_mapped_v4_address_is_the_v4_address() {
        let mut limiter = RateLimiter::new(1, 1, 16);
        assert!(limiter.allow(ip("2001:db8:0:1::1"), 100));
        assert!(!limiter.allow(ip("2001:db8:0:1::2"), 100));
        assert!(limiter.allow(ip("2001:db8:0:2::1"), 100));

        assert!(limiter.allow(ip("192.0.2.1"), 100));
        assert!(!limiter.allow(ip("::ffff:192.0.2.1"), 100));
    }

    #[test]
    fn the_table_is_bounded_and_refuses_new_sources_when_full() {
        let mut limiter = RateLimiter::new(1, 5, 2);
        assert!(limiter.allow(ip("192.0.2.1"), 100));
        assert!(limiter.allow(ip("192.0.2.2"), 100));
        assert!(!limiter.allow(ip("192.0.2.3"), 100));
        assert_eq!(limiter.buckets.len(), 2);
        // A source already known keeps its allowance.
        assert!(limiter.allow(ip("192.0.2.1"), 100));
        // Once buckets have refilled they can be forgotten, and a new source
        // gets in.
        assert!(limiter.allow(ip("192.0.2.3"), 200));
        assert!(limiter.buckets.len() <= 2);
    }

    #[test]
    fn a_clock_stepped_backwards_gives_no_tokens() {
        let mut limiter = RateLimiter::new(1, 1, 16);
        let source = ip("192.0.2.1");
        assert!(limiter.allow(source, 100));
        assert!(!limiter.allow(source, 50));
        assert!(limiter.allow(source, 51));
    }
}
