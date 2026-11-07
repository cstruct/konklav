//! Rate limits, enforced through a Redis rate-limit store when one is
//! configured (feature `redis`) and in memory always.
//!
//! The rules live in `konklav_relying::rate_limit`; [`RateLimit`] only runs
//! the store's script under a timeout and reports what happened.
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use konklav_relying_client::rate_limit::{RateLimit, RateLimitConfig, RateLimitWindow};
//!
//! let login = RateLimit::new(RateLimitConfig::new(
//!     "login",
//!     vec![
//!         RateLimitWindow { size: 5, period_ms: 60_000 },
//!         RateLimitWindow { size: 20, period_ms: 3_600_000 },
//!     ],
//! ))?;
//! if let Err(limited) = login.add("a@example.com").await {
//!     println!("retry in {} ms", limited.retry_after_ms);
//! }
//! # Ok(())
//! # }
//! ```

use std::sync::{Arc, Mutex};
#[cfg(feature = "redis")]
use std::time::Duration;

use konklav_relying::rate_limit::{Attempt, RateLimiter};
pub use konklav_relying::rate_limit::{
    RateLimitConfig, RateLimitError, RateLimitWindow, RateLimited, StoreSecret,
};

use crate::now;

/// A rate limit. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct RateLimit {
    inner: Arc<Inner>,
}

struct Inner {
    limiter: Mutex<RateLimiter>,
    #[cfg(feature = "redis")]
    store: Option<RedisStore>,
}

#[cfg(feature = "redis")]
struct RedisStore {
    connection: redis::aio::ConnectionManager,
    script: redis::Script,
    timeout: Duration,
}

impl RateLimit {
    /// The default time to wait for the store before answering from memory.
    #[cfg(feature = "redis")]
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(100);

    /// A limit enforced in memory only, in this process.
    pub fn new(config: RateLimitConfig) -> Result<Self, RateLimitError> {
        Ok(Self {
            inner: Arc::new(Inner {
                limiter: Mutex::new(RateLimiter::new(config, None)?),
                #[cfg(feature = "redis")]
                store: None,
            }),
        })
    }

    /// A limit enforced through Redis, shared by every process using it,
    /// and in memory while Redis fails or takes longer than `timeout`.
    /// Keys are hashed under `secret`, which every process must share.
    #[cfg(feature = "redis")]
    pub fn with_redis(
        config: RateLimitConfig,
        connection: redis::aio::ConnectionManager,
        secret: StoreSecret,
        timeout: Duration,
    ) -> Result<Self, RateLimitError> {
        Ok(Self {
            inner: Arc::new(Inner {
                limiter: Mutex::new(RateLimiter::new(config, Some(secret))?),
                store: Some(RedisStore {
                    connection,
                    script: redis::Script::new(konklav_relying::rate_limit::STORE_SCRIPT),
                    timeout,
                }),
            }),
        })
    }

    /// Counts one event for `key`, or refuses it.
    // Async with or without the `redis` feature, so enabling it changes no
    // callers.
    #[cfg_attr(
        not(feature = "redis"),
        allow(clippy::unused_async, clippy::unused_async_trait_impl)
    )]
    pub async fn add(&self, key: impl AsRef<[u8]>) -> Result<(), RateLimited> {
        let attempt = self.limiter().begin(key.as_ref(), now());
        match attempt {
            Attempt::Decided(result) => result,
            #[cfg(feature = "redis")]
            Attempt::Store { call, local } => {
                let Some(store) = &self.inner.store else {
                    return local;
                };
                let mut connection = store.connection.clone();
                let mut invocation = store.script.key(call.keys);
                invocation.arg(call.args);
                let answer = tokio::time::timeout(
                    store.timeout,
                    invocation.invoke_async::<u64>(&mut connection),
                )
                .await;
                match answer {
                    Ok(Ok(answer)) => self.limiter().on_store_answer(answer),
                    failure => {
                        let name = self.limiter().config().name.clone();
                        match failure {
                            Ok(Err(error)) => tracing::warn!(
                                rate_limit = %name, %error,
                                "rate-limit store failed; answering from memory"
                            ),
                            _ => tracing::warn!(
                                rate_limit = %name,
                                "rate-limit store timed out; answering from memory"
                            ),
                        }
                        self.limiter().on_store_failed(now());
                        local
                    }
                }
            }
            #[cfg(not(feature = "redis"))]
            Attempt::Store { local, .. } => local,
        }
    }

    /// The limit's name, as configured.
    #[must_use]
    pub fn name(&self) -> String {
        self.limiter().config().name.clone()
    }

    /// Forgets every key's state in memory. State in the store expires on
    /// its own.
    pub fn clear(&self) {
        self.limiter().clear();
    }

    fn limiter(&self) -> std::sync::MutexGuard<'_, RateLimiter> {
        self.inner
            .limiter
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
