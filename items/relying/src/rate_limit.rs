//! Rate limits: named bounds on how often events may happen per key.
//!
//! Each [`RateLimitWindow`] is enforced with the generic cell rate algorithm
//! (GCRA): per key and window, one theoretical arrival time (TAT). A window
//! of `size` events per `period` has an emission interval `T = period /
//! size` and a burst tolerance `τ = period - T`. An event at `now` is
//! admitted when `max(tat, now) - now <= τ`, and moves the TAT to
//! `max(tat, now) + T`. A key whose TATs have all passed is as good as new,
//! so its state can be dropped.
//!
//! [`RateLimiter`] keeps that state in memory for a bounded number of keys
//! and, when a rate-limit store (Redis) is configured, says what to ask the
//! store: [`STORE_SCRIPT`] with the keys and arguments in a [`StoreCall`].
//! The host runs the call and reports its answer or failure; while the
//! store is failing, the limiter answers from memory and backs off.
//!
//! ```
//! # use konklav_relying::rate_limit::*;
//! let config = RateLimitConfig::new("login", vec![RateLimitWindow { size: 2, period_ms: 1000 }]);
//! let mut limiter = RateLimiter::new(config, None).unwrap();
//! let add = |limiter: &mut RateLimiter, now| match limiter.begin(b"a@example.com", now) {
//!     Attempt::Decided(result) => result,
//!     Attempt::Store { .. } => unreachable!("no store configured"),
//! };
//! assert!(add(&mut limiter, 0).is_ok());
//! assert!(add(&mut limiter, 0).is_ok());
//! assert_eq!(add(&mut limiter, 0), Err(RateLimited { retry_after_ms: 500 }));
//! assert!(add(&mut limiter, 500).is_ok());
//! ```

use std::collections::{BTreeMap, HashMap};
use std::fmt::{self, Write as _};

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// The script a store runs for one event: it checks every window of a key
/// against the store's clock and, only if all admit the event, moves their
/// TATs and sets each to expire when it passes. `KEYS` has one key per
/// window, `ARGV` the emission interval and burst tolerance (microseconds)
/// of each in turn. Answers `0` when admitted, otherwise the retry-after
/// time in milliseconds.
// r[impl relying.rate-limit.shared]
// r[impl relying.rate-limit.expiry]
pub const STORE_SCRIPT: &str = r"
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000000 + tonumber(t[2])
local wait = 0
local tats = {}
for i = 1, #KEYS do
  local emission = tonumber(ARGV[2 * i - 1])
  local tolerance = tonumber(ARGV[2 * i])
  local tat = tonumber(redis.call('GET', KEYS[i])) or now
  if tat < now then tat = now end
  local over = tat - now - tolerance
  if over > wait then wait = over end
  tats[i] = tat + emission
end
if wait > 0 then return math.ceil(wait / 1000) end
for i = 1, #KEYS do
  local expiry = string.format('%.0f', math.ceil(tats[i] / 1000))
  redis.call('SET', KEYS[i], string.format('%.0f', tats[i]), 'PXAT', expiry)
end
return 0
";

/// The shortest secret accepted for hashing keys in the store.
pub const MIN_SECRET_LEN: usize = 32;

/// How long the store is left alone after its first failure.
pub const STORE_BACKOFF_MIN_MS: u64 = 1000;
/// The longest the store is left alone.
pub const STORE_BACKOFF_MAX_MS: u64 = 30_000;

/// A number of events and a period: `size` events at once, and after that
/// one more each time `period_ms / size` has passed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitWindow {
    pub size: u32,
    pub period_ms: u64,
}

impl RateLimitWindow {
    /// The emission interval and burst tolerance, in microseconds, of this
    /// window with `size` events.
    fn gcra(self, size: u32) -> (u64, u64) {
        let period = self.period_ms.saturating_mul(1000);
        let emission = (period / u64::from(size)).max(1);
        (emission, period.saturating_sub(emission))
    }
}

/// A rate limit's name, windows and tuning.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Identifies the limit's state in the store: limits with the same name
    /// and windows share it. Lowercase ASCII letters, digits, `_`, `.` and
    /// `-`, at most 64 of them.
    pub name: String,
    pub windows: Vec<RateLimitWindow>,
    /// Divides each window's size in local state (rounded down, at least 1),
    /// for processes answering from memory together.
    #[serde(default = "RateLimitConfig::default_local_divisor")]
    pub local_divisor: u32,
    /// The most keys kept in memory; the least recently used go first.
    #[serde(default = "RateLimitConfig::default_max_local_keys")]
    pub max_local_keys: usize,
}

impl RateLimitConfig {
    pub const DEFAULT_MAX_LOCAL_KEYS: usize = 100_000;

    #[must_use]
    pub fn new(name: impl Into<String>, windows: Vec<RateLimitWindow>) -> Self {
        Self {
            name: name.into(),
            windows,
            local_divisor: 1,
            max_local_keys: Self::DEFAULT_MAX_LOCAL_KEYS,
        }
    }

    fn default_local_divisor() -> u32 {
        1
    }

    fn default_max_local_keys() -> usize {
        Self::DEFAULT_MAX_LOCAL_KEYS
    }

    fn validate(&self) -> Result<(), RateLimitError> {
        let name_ok = !self.name.is_empty()
            && self.name.len() <= 64
            && self.name.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-')
            });
        if !name_ok {
            return Err(RateLimitError::InvalidName(self.name.clone()));
        }
        if self.windows.is_empty() {
            return Err(RateLimitError::NoWindows);
        }
        if self.windows.iter().any(|w| w.size == 0 || w.period_ms == 0) {
            return Err(RateLimitError::EmptyWindow);
        }
        if self.local_divisor == 0 {
            return Err(RateLimitError::ZeroDivisor);
        }
        if self.max_local_keys == 0 {
            return Err(RateLimitError::NoLocalKeys);
        }
        Ok(())
    }

    /// A window's size in local state.
    // r[impl relying.rate-limit.local-divisor]
    fn local_size(&self, window: RateLimitWindow) -> u32 {
        (window.size / self.local_divisor).max(1)
    }
}

/// A rate limit that can't be used as configured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RateLimitError {
    InvalidName(String),
    NoWindows,
    EmptyWindow,
    ZeroDivisor,
    NoLocalKeys,
    ShortSecret,
}

impl fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName(name) => write!(
                f,
                "rate limit name {name:?} must be 1 to 64 of a-z, 0-9, '_', '.' and '-'"
            ),
            Self::NoWindows => f.write_str("a rate limit needs at least one window"),
            Self::EmptyWindow => f.write_str("a rate-limit window needs a size and a period"),
            Self::ZeroDivisor => f.write_str("a rate limit's local divisor must be at least 1"),
            Self::NoLocalKeys => f.write_str("a rate limit must keep at least one key in memory"),
            Self::ShortSecret => write!(
                f,
                "a rate-limit store needs a secret of at least {MIN_SECRET_LEN} bytes"
            ),
        }
    }
}

impl std::error::Error for RateLimitError {}

/// The secret keys are hashed under before they reach the store.
#[derive(Clone)]
pub struct StoreSecret(Vec<u8>);

impl StoreSecret {
    // r[impl relying.rate-limit.key-privacy]
    pub fn new(secret: impl Into<Vec<u8>>) -> Result<Self, RateLimitError> {
        let secret = secret.into();
        if secret.len() < MIN_SECRET_LEN {
            return Err(RateLimitError::ShortSecret);
        }
        Ok(Self(secret))
    }
}

impl fmt::Debug for StoreSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StoreSecret(..)")
    }
}

/// A refused event, and how long until its key would be admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimited {
    pub retry_after_ms: u64,
}

/// What to ask the store: run [`STORE_SCRIPT`] with these keys and
/// arguments.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreCall {
    pub keys: Vec<String>,
    pub args: Vec<String>,
}

/// What [`RateLimiter::begin`] decided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Attempt {
    /// The answer, from local state: no store is configured, or it is
    /// backed off.
    Decided(Result<(), RateLimited>),
    /// Ask the store, and answer with [`RateLimiter::on_store_answer`]. If
    /// it fails or is too slow, report [`RateLimiter::on_store_failed`] and
    /// answer with `local`.
    Store {
        call: StoreCall,
        local: Result<(), RateLimited>,
    },
}

#[derive(Debug)]
struct Entry {
    /// One TAT per window, in microseconds.
    tats: Vec<u64>,
    used: u64,
}

#[derive(Debug)]
struct Backoff {
    until_ms: u64,
    next_ms: u64,
}

/// One rate limit's local state and store backoff. Times are Unix
/// milliseconds.
// r[impl item.relying.rate-limit]
#[derive(Debug)]
pub struct RateLimiter {
    config: RateLimitConfig,
    secret: Option<StoreSecret>,
    /// Emission interval and tolerance per window, locally and in the store.
    local_gcra: Vec<(u64, u64)>,
    store_args: Vec<String>,
    store_suffixes: Vec<String>,
    entries: HashMap<Vec<u8>, Entry>,
    /// Keys by when they were last used, the least recent first.
    order: BTreeMap<u64, Vec<u8>>,
    clock: u64,
    backoff: Backoff,
}

impl RateLimiter {
    /// A limiter for `config`, using a store when `secret` is given.
    pub fn new(
        config: RateLimitConfig,
        secret: Option<StoreSecret>,
    ) -> Result<Self, RateLimitError> {
        config.validate()?;
        let local_gcra = config
            .windows
            .iter()
            .map(|&w| w.gcra(config.local_size(w)))
            .collect();
        let store_args = config
            .windows
            .iter()
            .flat_map(|&w| {
                let (emission, tolerance) = w.gcra(w.size);
                [emission.to_string(), tolerance.to_string()]
            })
            .collect();
        let store_suffixes = config
            .windows
            .iter()
            .map(|w| format!("{}/{}", w.size, w.period_ms))
            .collect();
        Ok(Self {
            config,
            secret,
            local_gcra,
            store_args,
            store_suffixes,
            entries: HashMap::new(),
            order: BTreeMap::new(),
            clock: 0,
            backoff: Backoff {
                until_ms: 0,
                next_ms: STORE_BACKOFF_MIN_MS,
            },
        })
    }

    #[must_use]
    pub fn config(&self) -> &RateLimitConfig {
        &self.config
    }

    /// Whether a store is configured.
    #[must_use]
    pub fn has_store(&self) -> bool {
        self.secret.is_some()
    }

    /// Counts one event for `key` in local state, and says whether to ask
    /// the store.
    // r[impl relying.rate-limit.local]
    pub fn begin(&mut self, key: &[u8], now_ms: u64) -> Attempt {
        let local = self.apply_local(key, now_ms);
        match &self.secret {
            Some(secret) if now_ms >= self.backoff.until_ms => Attempt::Store {
                call: self.store_call(secret, key),
                local,
            },
            _ => Attempt::Decided(local),
        }
    }

    /// The store's answer to a [`StoreCall`]: `0` when admitted, otherwise
    /// the retry-after time in milliseconds.
    pub fn on_store_answer(&mut self, answer_ms: u64) -> Result<(), RateLimited> {
        self.backoff = Backoff {
            until_ms: 0,
            next_ms: STORE_BACKOFF_MIN_MS,
        };
        if answer_ms == 0 {
            Ok(())
        } else {
            Err(RateLimited {
                retry_after_ms: answer_ms,
            })
        }
    }

    /// The store failed or was too slow. Calls that were already under way
    /// when the backoff began don't extend it.
    // r[impl relying.rate-limit.fallback]
    pub fn on_store_failed(&mut self, now_ms: u64) {
        if now_ms >= self.backoff.until_ms {
            self.backoff.until_ms = now_ms.saturating_add(self.backoff.next_ms);
            self.backoff.next_ms = (self.backoff.next_ms * 2).min(STORE_BACKOFF_MAX_MS);
        }
    }

    /// Whether the store is backed off at `now_ms`.
    #[must_use]
    pub fn store_backed_off(&self, now_ms: u64) -> bool {
        self.secret.is_some() && now_ms < self.backoff.until_ms
    }

    /// Forgets every key's local state.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }

    /// How many keys local state holds.
    #[must_use]
    pub fn local_keys(&self) -> usize {
        self.entries.len()
    }

    // r[impl relying.rate-limit.windows]
    // r[impl relying.rate-limit.retry-after]
    fn apply_local(&mut self, key: &[u8], now_ms: u64) -> Result<(), RateLimited> {
        let now = now_ms.saturating_mul(1000);
        self.drop_expired(now);
        self.clock += 1;
        let used = self.clock;
        let entry = if let Some(entry) = self.entries.get_mut(key) {
            self.order.remove(&entry.used);
            entry.used = used;
            entry
        } else {
            if self.entries.len() >= self.config.max_local_keys
                && let Some((_, oldest)) = self.order.pop_first()
            {
                self.entries.remove(&oldest);
            }
            self.entries.entry(key.to_vec()).or_insert(Entry {
                tats: vec![0; self.local_gcra.len()],
                used,
            })
        };
        self.order.insert(used, key.to_vec());

        let over = entry
            .tats
            .iter()
            .zip(&self.local_gcra)
            .map(|(&tat, &(_, tolerance))| (tat.max(now) - now).saturating_sub(tolerance))
            .max()
            .unwrap_or(0);
        if over > 0 {
            return Err(RateLimited {
                retry_after_ms: over.div_ceil(1000),
            });
        }
        for (tat, &(emission, _)) in entry.tats.iter_mut().zip(&self.local_gcra) {
            *tat = (*tat).max(now) + emission;
        }
        Ok(())
    }

    /// Drops the least recently used keys whose TATs have all passed. Keys
    /// are dropped in use order, so this looks at only a few per call.
    // r[impl relying.rate-limit.expiry]
    fn drop_expired(&mut self, now: u64) {
        for _ in 0..2 {
            let Some((&used, key)) = self.order.first_key_value() else {
                return;
            };
            let expired = self
                .entries
                .get(key)
                .is_none_or(|entry| entry.tats.iter().all(|&tat| tat <= now));
            if !expired {
                return;
            }
            let key = self.order.remove(&used).expect("present");
            self.entries.remove(&key);
        }
    }

    fn store_call(&self, secret: &StoreSecret, key: &[u8]) -> StoreCall {
        let mut mac = Hmac::<Sha256>::new_from_slice(&secret.0).expect("HMAC accepts any key");
        mac.update(self.config.name.as_bytes());
        mac.update(&[0]);
        mac.update(key);
        let digest = mac.finalize().into_bytes();
        let digest = digest[..16].iter().fold(String::new(), |mut hex, b| {
            let _ = write!(hex, "{b:02x}");
            hex
        });
        // The braces put every window of a key in one Redis Cluster slot.
        let keys = self
            .store_suffixes
            .iter()
            .map(|suffix| format!("konklav:rl:{{{}:{digest}}}:{suffix}", self.config.name))
            .collect();
        StoreCall {
            keys,
            args: self.store_args.clone(),
        }
    }
}
