use serde::{Deserialize, Serialize};

/// Tuning for the relying core. Durations are milliseconds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// The `iss` tokens must carry.
    pub issuer: String,
    /// The `aud` tokens must carry.
    pub audience: String,
    /// Tolerated clock skew when checking token times, in seconds.
    pub leeway_seconds: i64,
    /// How long an entitlement set may be used without being refreshed.
    // r[impl relying.cache.ttl]
    pub entitlement_ttl_ms: u64,
    /// How long an invalidated entry may still be used while its refresh is
    /// debounced.
    // r[impl relying.cache.debounce-bound]
    pub debounce_ms: u64,
    /// Refresh entries this long before they expire, if they are in use.
    pub refresh_margin_ms: u64,
    /// The feed's heartbeat interval.
    pub heartbeat_ms: u64,
    /// How many heartbeat intervals of silence make the feed untrusted.
    pub missed_heartbeats: u64,
    /// The minimum time between JWKS refreshes caused by unknown key ids.
    // r[impl relying.verify.jwks-refresh]
    pub jwks_min_refresh_ms: u64,
    /// How many entries one call to `poll_work` hands out, so a wildcard
    /// invalidation becomes a rate-limited sweep.
    // r[impl relying.cache.wildcard-sweep]
    pub sweep_batch: usize,
    /// The most registered scope records kept; the least recently used go
    /// first.
    // r[impl relying.cache.registered]
    pub registered_capacity: usize,
    /// How long a registered scope Konklav doesn't know is remembered as
    /// unknown.
    // r[impl relying.cache.registered-unknown]
    pub unknown_scope_ttl_ms: u64,
    /// How old a DPoP proof may be, in seconds.
    pub dpop_max_age_seconds: i64,
    /// The most DPoP proofs remembered at once, to refuse replays. When it
    /// is full of proofs that are still fresh, new proofs are refused.
    pub dpop_replay_capacity: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            audience: String::new(),
            leeway_seconds: 30,
            entitlement_ttl_ms: 15 * 60 * 1000,
            debounce_ms: 500,
            refresh_margin_ms: 60 * 1000,
            heartbeat_ms: 10 * 1000,
            missed_heartbeats: 3,
            jwks_min_refresh_ms: 30 * 1000,
            sweep_batch: 50,
            registered_capacity: 100_000,
            unknown_scope_ttl_ms: 5 * 1000,
            dpop_max_age_seconds: 60,
            dpop_replay_capacity: 100_000,
        }
    }
}
