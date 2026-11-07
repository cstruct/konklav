use konklav_relying::rate_limit::{
    Attempt, RateLimitConfig, RateLimitError, RateLimitWindow, RateLimited, RateLimiter,
    STORE_BACKOFF_MAX_MS, StoreSecret,
};

const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

fn window(size: u32, period_ms: u64) -> RateLimitWindow {
    RateLimitWindow { size, period_ms }
}

fn local(windows: Vec<RateLimitWindow>) -> RateLimiter {
    RateLimiter::new(RateLimitConfig::new("test", windows), None).unwrap()
}

fn add(limiter: &mut RateLimiter, key: &str, now: u64) -> Result<(), RateLimited> {
    match limiter.begin(key.as_bytes(), now) {
        Attempt::Decided(result) => result,
        Attempt::Store { local, .. } => local,
    }
}

fn refused(retry_after_ms: u64) -> Result<(), RateLimited> {
    Err(RateLimited { retry_after_ms })
}

// r[verify relying.rate-limit.windows]
// r[verify relying.rate-limit.retry-after]
#[test]
fn a_window_admits_a_burst_then_one_per_interval() {
    let mut limiter = local(vec![window(3, 3000)]);
    for _ in 0..3 {
        assert_eq!(add(&mut limiter, "k", 0), Ok(()));
    }
    assert_eq!(add(&mut limiter, "k", 0), refused(1000));
    assert_eq!(add(&mut limiter, "k", 999), refused(1));
    assert_eq!(add(&mut limiter, "k", 1000), Ok(()));
    assert_eq!(add(&mut limiter, "k", 1000), refused(1000));
    // Fully drained after the period: a whole burst again.
    for _ in 0..3 {
        assert_eq!(add(&mut limiter, "k", 10_000), Ok(()));
    }
}

// r[verify relying.rate-limit.windows]
#[test]
fn keys_are_limited_separately() {
    let mut limiter = local(vec![window(1, 1000)]);
    assert_eq!(add(&mut limiter, "a", 0), Ok(()));
    assert_eq!(add(&mut limiter, "b", 0), Ok(()));
    assert_eq!(add(&mut limiter, "a", 0), refused(1000));
}

// r[verify relying.rate-limit.windows]
// r[verify relying.rate-limit.retry-after]
#[test]
fn every_window_must_admit_and_the_longest_wait_is_reported() {
    // 2 per second, 3 per minute.
    let mut limiter = local(vec![window(2, 1000), window(3, 60_000)]);
    assert_eq!(add(&mut limiter, "k", 0), Ok(()));
    assert_eq!(add(&mut limiter, "k", 0), Ok(()));
    assert_eq!(add(&mut limiter, "k", 0), refused(500));
    assert_eq!(add(&mut limiter, "k", 500), Ok(()));
    // The minute window is now full: one more every 20 s from the start.
    assert_eq!(add(&mut limiter, "k", 2000), refused(18_000));
    assert_eq!(add(&mut limiter, "k", 20_000), Ok(()));
}

// r[verify relying.rate-limit.windows]
#[test]
fn refused_events_count_toward_no_window() {
    let mut limiter = local(vec![window(1, 1000), window(10, 60_000)]);
    assert_eq!(add(&mut limiter, "k", 0), Ok(()));
    // Refused by the first window; must not use up the second.
    for _ in 0..100 {
        assert!(add(&mut limiter, "k", 10).is_err());
    }
    for second in 1..10 {
        assert_eq!(add(&mut limiter, "k", second * 1000), Ok(()), "{second}");
    }
}

// r[verify relying.rate-limit.local-divisor]
#[test]
fn the_local_divisor_divides_window_sizes() {
    let mut config = RateLimitConfig::new("test", vec![window(10, 1000), window(3, 1000)]);
    config.local_divisor = 4;
    let mut limiter = RateLimiter::new(config, None).unwrap();
    // 10 / 4 is 2 per second, 3 / 4 is at least 1 per second.
    assert_eq!(add(&mut limiter, "k", 0), Ok(()));
    assert_eq!(add(&mut limiter, "k", 0), refused(1000));
    assert_eq!(add(&mut limiter, "k", 1000), Ok(()));
    assert_eq!(add(&mut limiter, "j", 0), Ok(()));
    assert_eq!(add(&mut limiter, "j", 500), refused(500));
}

// r[verify relying.rate-limit.local]
#[test]
fn local_state_keeps_a_bounded_number_of_keys() {
    let mut config = RateLimitConfig::new("test", vec![window(1, 60_000)]);
    config.max_local_keys = 2;
    let mut limiter = RateLimiter::new(config, None).unwrap();
    assert_eq!(add(&mut limiter, "a", 0), Ok(()));
    assert_eq!(add(&mut limiter, "b", 0), Ok(()));
    // Using `a` makes `b` the least recently used.
    assert!(add(&mut limiter, "a", 1).is_err());
    assert_eq!(add(&mut limiter, "c", 2), Ok(()));
    assert_eq!(limiter.local_keys(), 2);
    assert!(add(&mut limiter, "a", 3).is_err(), "a is kept");
    assert_eq!(add(&mut limiter, "b", 4), Ok(()), "b was evicted");
}

// r[verify relying.rate-limit.expiry]
#[test]
fn drained_keys_are_dropped_from_memory() {
    let mut limiter = local(vec![window(2, 1000)]);
    for key in ["a", "b", "c"] {
        assert_eq!(add(&mut limiter, key, 0), Ok(()));
    }
    assert_eq!(limiter.local_keys(), 3);
    // One event drains after 500 ms. Each later event drops up to two
    // drained keys, the least recently used first.
    assert_eq!(add(&mut limiter, "d", 400), Ok(()));
    assert_eq!(limiter.local_keys(), 4, "nothing has drained at 400 ms");
    assert_eq!(add(&mut limiter, "d", 5000), Ok(()));
    assert_eq!(limiter.local_keys(), 2);
    assert_eq!(add(&mut limiter, "d", 5000), Ok(()));
    assert_eq!(limiter.local_keys(), 1);
}

#[test]
fn configs_are_validated() {
    let new = |config: RateLimitConfig| RateLimiter::new(config, None).map(|_| ());
    assert!(matches!(
        new(RateLimitConfig::new("Login", vec![window(1, 1)])),
        Err(RateLimitError::InvalidName(_))
    ));
    assert!(matches!(
        new(RateLimitConfig::new("a{b}", vec![window(1, 1)])),
        Err(RateLimitError::InvalidName(_))
    ));
    assert_eq!(
        new(RateLimitConfig::new("login", vec![])),
        Err(RateLimitError::NoWindows)
    );
    assert_eq!(
        new(RateLimitConfig::new("login", vec![window(0, 1000)])),
        Err(RateLimitError::EmptyWindow)
    );
    let mut config = RateLimitConfig::new("login", vec![window(1, 1000)]);
    config.local_divisor = 0;
    assert_eq!(new(config), Err(RateLimitError::ZeroDivisor));
    assert_eq!(
        new(RateLimitConfig::new("login.v2_a-b", vec![window(1, 1)])),
        Ok(())
    );
}

// r[verify relying.rate-limit.key-privacy]
#[test]
fn store_secrets_must_be_long_enough() {
    assert!(matches!(
        StoreSecret::new(&SECRET[..31]),
        Err(RateLimitError::ShortSecret)
    ));
    assert!(StoreSecret::new(SECRET).is_ok());
}

fn with_store(windows: Vec<RateLimitWindow>) -> RateLimiter {
    RateLimiter::new(
        RateLimitConfig::new("login", windows),
        Some(StoreSecret::new(SECRET).unwrap()),
    )
    .unwrap()
}

// r[verify item.relying.rate-limit]
// r[verify relying.rate-limit.key-privacy]
// r[verify relying.rate-limit.shared]
#[test]
fn store_calls_name_hashed_keys_per_window() {
    let mut limiter = with_store(vec![window(2, 1000), window(3, 60_000)]);
    let Attempt::Store { call, local } = limiter.begin(b"a@example.com", 0) else {
        panic!("expected a store call");
    };
    assert_eq!(local, Ok(()));
    assert_eq!(call.keys.len(), 2);
    for key in &call.keys {
        assert!(key.starts_with("konklav:rl:{login:"), "{key}");
        assert!(!key.contains("example"), "{key}");
    }
    assert!(call.keys[0].ends_with("}:2/1000"));
    assert!(call.keys[1].ends_with("}:3/60000"));
    // Emission interval and tolerance in microseconds, per window.
    assert_eq!(call.args, ["500000", "500000", "20000000", "40000000"]);

    // The same key hashes the same in every process; other keys don't.
    let mut other = with_store(vec![window(2, 1000), window(3, 60_000)]);
    let Attempt::Store { call: again, .. } = other.begin(b"a@example.com", 0) else {
        panic!("expected a store call");
    };
    assert_eq!(again.keys, call.keys);
    let Attempt::Store { call: b, .. } = other.begin(b"b@example.com", 0) else {
        panic!("expected a store call");
    };
    assert_ne!(b.keys, call.keys);
}

#[test]
fn the_store_answers_when_it_can() {
    let mut limiter = with_store(vec![window(1, 1000)]);
    assert!(matches!(limiter.begin(b"k", 0), Attempt::Store { .. }));
    assert_eq!(limiter.on_store_answer(0), Ok(()));
    // Locally refused, but the store's answer is the one that counts.
    let Attempt::Store { local, .. } = limiter.begin(b"k", 0) else {
        panic!("expected a store call");
    };
    assert!(local.is_err());
    assert_eq!(limiter.on_store_answer(0), Ok(()));
    assert_eq!(limiter.on_store_answer(250), refused(250));
}

// r[verify item.relying.rate-limit]
// r[verify relying.rate-limit.fallback]
#[test]
fn a_failing_store_is_backed_off_and_local_state_answers() {
    let mut limiter = with_store(vec![window(1, 100)]);
    let mut now = 0;
    let mut backoffs = Vec::new();
    for _ in 0..8 {
        assert!(matches!(limiter.begin(b"k", now), Attempt::Store { .. }));
        limiter.on_store_failed(now);
        // A call that was already under way doesn't extend the backoff.
        limiter.on_store_failed(now + 1);
        let start = now;
        while limiter.store_backed_off(now) {
            assert!(matches!(limiter.begin(b"k", now), Attempt::Decided(_)));
            now += 100;
        }
        backoffs.push(now - start);
    }
    assert_eq!(
        backoffs,
        [1000, 2000, 4000, 8000, 16_000, 30_000, 30_000, 30_000]
    );
    assert_eq!(STORE_BACKOFF_MAX_MS, 30_000);

    // One answer resets the backoff.
    assert!(matches!(limiter.begin(b"k", now), Attempt::Store { .. }));
    assert_eq!(limiter.on_store_answer(0), Ok(()));
    limiter.on_store_failed(now);
    assert!(limiter.store_backed_off(now + 999));
    assert!(!limiter.store_backed_off(now + 1000));
}

// r[verify relying.rate-limit.local]
#[test]
fn local_state_is_kept_while_the_store_answers() {
    let mut limiter = with_store(vec![window(1, 60_000)]);
    assert!(matches!(limiter.begin(b"k", 0), Attempt::Store { .. }));
    assert_eq!(limiter.on_store_answer(0), Ok(()));
    limiter.on_store_failed(1);
    // Backed off: local state already counts the first event.
    assert_eq!(
        limiter.begin(b"k", 2),
        Attempt::Decided(Err(RateLimited {
            retry_after_ms: 59_998
        }))
    );
}
