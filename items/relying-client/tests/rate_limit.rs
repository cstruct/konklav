//! Rate limits against a real Redis (`mise run db:up`), directly and through
//! a proxy that can cut the connection.

#![cfg(feature = "redis")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use konklav_relying_client::rate_limit::{
    RateLimit, RateLimitConfig, RateLimitWindow, RateLimited, StoreSecret,
};
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::AbortHandle;

const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

fn unique_name() -> String {
    format!("test-{}", uuid::Uuid::now_v7().simple())
}

async fn connect(url: &str) -> ConnectionManager {
    let client = redis::Client::open(url).expect("redis url");
    let config = redis::aio::ConnectionManagerConfig::new()
        .set_connection_timeout(Some(Duration::from_millis(200)))
        .set_response_timeout(Some(Duration::from_millis(200)))
        .set_number_of_retries(0);
    ConnectionManager::new_with_config(client, config)
        .await
        .expect("connect to the test Redis (is `mise run db:up` running?)")
}

async fn limit(url: &str, name: &str, windows: Vec<RateLimitWindow>) -> RateLimit {
    RateLimit::with_redis(
        RateLimitConfig::new(name, windows),
        connect(url).await,
        StoreSecret::new(SECRET).unwrap(),
        RateLimit::DEFAULT_TIMEOUT,
    )
    .unwrap()
}

fn window(size: u32, period_ms: u64) -> RateLimitWindow {
    RateLimitWindow { size, period_ms }
}

// r[verify relying.rate-limit.shared]
#[tokio::test]
async fn processes_sharing_a_store_enforce_one_limit() {
    let url = konklav_test_support::redis_url();
    let name = unique_name();
    let a = limit(&url, &name, vec![window(3, 60_000)]).await;
    let b = limit(&url, &name, vec![window(3, 60_000)]).await;

    assert_eq!(a.add("k").await, Ok(()));
    assert_eq!(b.add("k").await, Ok(()));
    assert_eq!(a.add("k").await, Ok(()));
    let Err(RateLimited { retry_after_ms }) = b.add("k").await else {
        panic!("the shared limit should refuse the fourth event");
    };
    assert!(
        (19_000..=20_000).contains(&retry_after_ms),
        "{retry_after_ms}"
    );
    // Other keys are limited separately.
    assert_eq!(b.add("other").await, Ok(()));
}

// r[verify relying.rate-limit.windows]
#[tokio::test]
async fn the_store_counts_only_admitted_events() {
    let url = konklav_test_support::redis_url();
    // 1 per 300 ms, and 3 per minute.
    let a = limit(
        &url,
        &unique_name(),
        vec![window(1, 300), window(3, 60_000)],
    )
    .await;
    for round in 0..3 {
        assert_eq!(a.add("k").await, Ok(()), "round {round}");
        // Refused by the first window; must not use up the second.
        for _ in 0..10 {
            assert!(a.add("k").await.is_err());
        }
        tokio::time::sleep(Duration::from_millis(320)).await;
    }
    let Err(RateLimited { retry_after_ms }) = a.add("k").await else {
        panic!("the minute window should be full");
    };
    assert!(retry_after_ms > 1000, "{retry_after_ms}");
}

// r[verify relying.rate-limit.key-privacy]
// r[verify relying.rate-limit.expiry]
#[tokio::test]
async fn store_keys_are_hashed_and_expire() {
    let url = konklav_test_support::redis_url();
    let name = unique_name();
    // One event drains a window in one emission interval: 300 ms and 900 ms.
    let a = limit(&url, &name, vec![window(1, 300), window(2, 1800)]).await;
    assert_eq!(a.add("a@example.com").await, Ok(()));

    let mut redis = connect(&url).await;
    let pattern = format!("konklav:rl:{{{name}:*");
    let mut keys: Vec<String> = redis.keys(&pattern).await.unwrap();
    keys.sort();
    assert_eq!(keys.len(), 2, "{keys:?}");
    for key in &keys {
        assert!(!key.contains("example"), "{key}");
        let ttl: i64 = redis.pttl(key).await.unwrap();
        assert!((0..=900).contains(&ttl), "{key}: {ttl}");
    }
    tokio::time::sleep(Duration::from_millis(450)).await;
    let left: Vec<String> = redis.keys(&pattern).await.unwrap();
    assert_eq!(left.len(), 1, "the 1 per 300 ms window drained: {left:?}");
    tokio::time::sleep(Duration::from_millis(550)).await;
    let left: Vec<String> = redis.keys(&pattern).await.unwrap();
    assert!(left.is_empty(), "{left:?}");
}

/// A TCP proxy to Redis that can be cut and restored.
struct Proxy {
    url: String,
    up: Arc<AtomicBool>,
    connections: Arc<Mutex<Vec<AbortHandle>>>,
}

impl Proxy {
    async fn start(target: &str) -> Self {
        let target = target
            .strip_prefix("redis://")
            .expect("a redis:// url")
            .trim_end_matches('/')
            .to_owned();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("redis://{}", listener.local_addr().unwrap());
        let up = Arc::new(AtomicBool::new(true));
        let connections = Arc::new(Mutex::new(Vec::new()));
        let (up_, connections_) = (up.clone(), connections.clone());
        tokio::spawn(async move {
            loop {
                let Ok((mut inbound, _)) = listener.accept().await else {
                    return;
                };
                if !up_.load(Ordering::SeqCst) {
                    continue;
                }
                let target = target.clone();
                let task = tokio::spawn(async move {
                    if let Ok(mut outbound) = TcpStream::connect(&target).await {
                        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                    }
                });
                connections_.lock().unwrap().push(task.abort_handle());
            }
        });
        Self {
            url,
            up,
            connections,
        }
    }

    fn cut(&self) {
        self.up.store(false, Ordering::SeqCst);
        for connection in self.connections.lock().unwrap().drain(..) {
            connection.abort();
        }
    }

    fn restore(&self) {
        self.up.store(true, Ordering::SeqCst);
    }
}

// r[verify relying.rate-limit.fallback]
// r[verify relying.rate-limit.local]
#[tokio::test]
async fn a_lost_store_falls_back_to_memory_and_recovers() {
    let url = konklav_test_support::redis_url();
    let proxy = Proxy::start(&url).await;
    let name = unique_name();
    let proxied = limit(&proxy.url, &name, vec![window(2, 60_000)]).await;
    let direct = limit(&url, &name, vec![window(2, 60_000)]).await;

    // Counted in the store and in memory.
    assert_eq!(proxied.add("k").await, Ok(()));

    proxy.cut();
    let started = Instant::now();
    assert_eq!(proxied.add("k").await, Ok(()), "memory admits a second");
    assert!(proxied.add("k").await.is_err(), "memory refuses a third");
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "answered within the timeout: {:?}",
        started.elapsed()
    );

    // The store only saw one event.
    proxy.restore();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(
        proxied.add("k").await,
        Ok(()),
        "the store answers again after the backoff, though memory is full"
    );
    assert!(
        direct.add("k").await.is_err(),
        "and the limit is shared again"
    );
}
