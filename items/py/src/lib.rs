//! Python bindings for the relying core.
//!
//! The binding is deliberately thin: values cross the boundary as JSON, and
//! every rule stays in `konklav-relying`. The Python package
//! `konklav_relying` adds the I/O (httpx, asyncio) around it.

use konklav_authz::{Decision, EntitlementSet, Requirements};
use konklav_core::Cursor;
use konklav_core::feed::{FeedEvent, SessionChanged};
use konklav_relying::rate_limit::{
    Attempt, RateLimitConfig, RateLimited, RateLimiter, STORE_SCRIPT, StoreSecret,
};
use konklav_relying::{Config, Key, Need, PresentationId, Presented, Relying, ScopeRecord};
use konklav_token::JwkSet;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

fn parse<T: serde::de::DeserializeOwned>(json: &str, what: &str) -> PyResult<T> {
    serde_json::from_str(json).map_err(|e| PyValueError::new_err(format!("invalid {what}: {e}")))
}

fn dump<T: serde::Serialize>(value: &T) -> PyResult<String> {
    serde_json::to_string(value).map_err(|e| PyValueError::new_err(e.to_string()))
}

/// The relying core. Times are Unix milliseconds; values are JSON strings.
#[pyclass(module = "konklav_relying._core")]
struct Core {
    inner: Relying,
}

#[pymethods]
impl Core {
    #[new]
    fn new(config: &str) -> PyResult<Self> {
        Ok(Self {
            inner: Relying::new(parse::<Config>(config, "config")?),
        })
    }

    /// Returns an outcome: `{"outcome": "decided", "decision": ...}` or
    /// `{"outcome": "need", "needs": [...]}`.
    fn decide(&mut self, token: &str, requirements: &str, now: u64) -> PyResult<String> {
        let requirements: Requirements = parse(requirements, "requirements")?;
        dump(&self.inner.decide(token, &requirements, None, now))
    }

    /// [`Core::decide`] for a request's raw headers: `presented` is
    /// `{"authorization": ..., "dpop": ..., "request": {"method": ...,
    /// "url": ...}}`, so sender-constrained tokens work too.
    fn decide_presented(
        &mut self,
        presented: &str,
        requirements: &str,
        now: u64,
    ) -> PyResult<String> {
        let presented: Presented = parse(presented, "presented token")?;
        let requirements: Requirements = parse(requirements, "requirements")?;
        dump(&self.inner.decide_presented(&presented, &requirements, now))
    }

    /// Returns `{"outcome": "verified", "claims": ...}`, `{"outcome":
    /// "invalid"}`, `{"outcome": "invalid_proof"}` or `{"outcome": "need",
    /// "needs": [...]}`.
    fn verify(&mut self, token: &str, now: u64) -> PyResult<String> {
        dump(&self.inner.verify(token, now))
    }

    /// [`Core::verify`] for a request's raw headers, like
    /// [`Core::decide_presented`].
    fn verify_presented(&mut self, presented: &str, now: u64) -> PyResult<String> {
        let presented: Presented = parse(presented, "presented token")?;
        dump(&self.inner.verify_presented(&presented, now))
    }

    /// Accepts a request's presentation once, for the decisions of its
    /// request with [`Core::decide_accepted`]: `{"outcome": "accepted", "claims": ...,
    /// "presentation": ...}`, `{"outcome": "check", "presentation": ...}`, `{"outcome": "invalid"}`, `{"outcome": "invalid_proof"}` or
    /// `{"outcome": "need", "needs": [...]}`.
    fn accept_presented(&mut self, presented: &str, now: u64) -> PyResult<String> {
        let presented: Presented = parse(presented, "presented token")?;
        dump(&self.inner.accept_presented(&presented, now))
    }

    /// Decides `requirements` for an accepted presentation (its
    /// `presentation` JSON, as accepting returned it), without checking its
    /// proof again; an outcome as [`Core::decide`] returns. `route` marks
    /// the route decision.
    #[pyo3(signature = (presentation, requirements, now, *, route = false))]
    fn decide_accepted(
        &mut self,
        presentation: &str,
        requirements: &str,
        now: u64,
        route: bool,
    ) -> PyResult<String> {
        let presentation: PresentationId = parse(presentation, "presentation")?;
        let requirements: Requirements = parse(requirements, "requirements")?;
        dump(
            &self
                .inner
                .decide_accepted(presentation, &requirements, route, now),
        )
    }

    /// The route authority JSON to send to the check API for a decision
    /// [`Core::decide_accepted`] handed off, or `null` for the route
    /// decision.
    #[pyo3(signature = (presentation, now, *, route = false))]
    fn route_authority(&self, presentation: &str, now: u64, route: bool) -> PyResult<String> {
        let presentation: PresentationId = parse(presentation, "presentation")?;
        dump(&self.inner.route_authority(presentation, route, now))
    }

    /// Records a check-API decision (its JSON) made for a decision
    /// [`Core::decide_accepted`] handed off: an outcome as [`Core::decide`]
    /// returns.
    #[pyo3(signature = (presentation, decision, now, *, route = false))]
    fn on_check_accepted(
        &mut self,
        presentation: &str,
        decision: &str,
        now: u64,
        route: bool,
    ) -> PyResult<String> {
        let presentation: PresentationId = parse(presentation, "presentation")?;
        let decision: Decision = parse(decision, "decision")?;
        dump(
            &self
                .inner
                .on_check_accepted(presentation, route, decision, now),
        )
    }

    /// Releases an accepted presentation (its `presentation` JSON) once its
    /// request is answered: it decides nothing more.
    fn release_accepted(&mut self, presentation: &str) -> PyResult<()> {
        let presentation: PresentationId = parse(presentation, "presentation")?;
        self.inner.release_accepted(presentation);
        Ok(())
    }

    /// Returns `{"outcome": "ready", "set": ...}` or `{"outcome": "need",
    /// "needs": [...]}`.
    #[pyo3(signature = (subject, tenant, now))]
    fn entitlements(&mut self, subject: &str, tenant: Option<&str>, now: u64) -> PyResult<String> {
        let invalid = |_| PyValueError::new_err("invalid id");
        let key = Key {
            subject: subject.parse().map_err(invalid)?,
            tenant: tenant.map(str::parse).transpose().map_err(invalid)?,
        };
        match self.inner.entitlements(key, now) {
            Ok(set) => dump(&serde_json::json!({"outcome": "ready", "set": set})),
            Err(needs) => dump(&serde_json::json!({"outcome": "need", "needs": needs})),
        }
    }

    fn is_trusted(&self, now: u64) -> bool {
        self.inner.is_trusted(now)
    }

    fn feed_cursor(&self) -> Option<i64> {
        self.inner.feed_cursor().map(Cursor::get)
    }

    fn on_jwks(&mut self, jwks: &str, now: u64) -> PyResult<()> {
        self.inner.on_jwks(parse::<JwkSet>(jwks, "JWKS")?, now);
        Ok(())
    }

    fn on_session(&mut self, state: &str) -> PyResult<()> {
        self.inner
            .on_session(parse::<SessionChanged>(state, "session state")?);
        Ok(())
    }

    fn on_session_unknown(&mut self, session: &str) -> PyResult<()> {
        let session = session
            .parse()
            .map_err(|_| PyValueError::new_err("invalid session id"))?;
        self.inner.on_session_unknown(session);
        Ok(())
    }

    fn on_entitlements(&mut self, set: &str, now: u64) -> PyResult<()> {
        self.inner
            .on_entitlements(parse::<EntitlementSet>(set, "entitlement set")?, now);
        Ok(())
    }

    /// Applies a registered scope's record (the JSON body of
    /// `/v1/registered-scopes/{kind}/{id}`).
    fn on_registered_scope(&mut self, record: &str, now: u64) -> PyResult<()> {
        self.inner
            .on_registered_scope(parse::<ScopeRecord>(record, "registered scope")?, now);
        Ok(())
    }

    /// Konklav answered `404` for the registered scope.
    fn on_registered_scope_unknown(&mut self, kind: &str, id: &str, now: u64) {
        self.inner.on_registered_scope_unknown(kind, id, now);
    }

    fn on_fetch_failed(&mut self, need: &str) -> PyResult<()> {
        self.inner.on_fetch_failed(&parse::<Need>(need, "need")?);
        Ok(())
    }

    fn on_feed_connected(&mut self, now: u64) {
        self.inner.on_feed_connected(now);
    }

    fn on_feed_activity(&mut self, now: u64) {
        self.inner.on_feed_activity(now);
    }

    fn on_feed_lost(&mut self) {
        self.inner.on_feed_lost();
    }

    /// Applies a feed event (the JSON `data` of an SSE event). Raises
    /// `ValueError` for malformed events; reconnect rather than skip them.
    ///
    /// Returns an erasure notice for the relying system, or `None`:
    /// `{"notice": "erased", "subject": ..., "erased_at": ...}` or
    /// `{"notice": "missed", "since": ...}`.
    fn on_feed_event(&mut self, event: &str, now: u64) -> PyResult<Option<String>> {
        let event: FeedEvent = parse(event, "feed event")?;
        self.inner
            .on_feed_event(&event, now)
            .map_err(|e| PyValueError::new_err(format!("malformed feed event: {e}")))?
            .as_ref()
            .map(dump)
            .transpose()
    }

    fn await_cursor(&mut self, cursor: i64) -> bool {
        self.inner.await_cursor(Cursor::new(cursor))
    }

    /// Returns `{"fetch": [...needs], "next_poll_at": ms}`.
    fn poll_work(&mut self, now: u64) -> PyResult<String> {
        dump(&self.inner.poll_work(now))
    }
}

/// The retry-after time of a refused event, `None` when admitted.
fn retry_after(result: Result<(), RateLimited>) -> Option<u64> {
    result.err().map(|limited| limited.retry_after_ms)
}

/// One rate limit's local state and store backoff, from
/// `konklav_relying::rate_limit`. Times are Unix milliseconds; a verdict is
/// `None` when admitted, otherwise the retry-after time in milliseconds.
#[pyclass(module = "konklav_relying._core")]
struct RateLimiterCore {
    inner: RateLimiter,
}

#[pymethods]
impl RateLimiterCore {
    /// `config` is `{"name": ..., "windows": [{"size": ..., "period_ms":
    /// ...}], "local_divisor": ..., "max_local_keys": ...}`; with `secret`,
    /// the limit uses a store.
    #[new]
    #[pyo3(signature = (config, secret=None))]
    fn new(config: &str, secret: Option<Vec<u8>>) -> PyResult<Self> {
        let config: RateLimitConfig = parse(config, "rate-limit config")?;
        let secret = secret
            .map(StoreSecret::new)
            .transpose()
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        let inner =
            RateLimiter::new(config, secret).map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Counts one event in local state: `(local verdict, None)`, or
    /// `(local verdict, (keys, args))` to run `STORE_SCRIPT` with.
    #[allow(clippy::type_complexity)]
    fn begin(&mut self, key: &[u8], now: u64) -> (Option<u64>, Option<(Vec<String>, Vec<String>)>) {
        match self.inner.begin(key, now) {
            Attempt::Decided(result) => (retry_after(result), None),
            Attempt::Store { call, local } => (retry_after(local), Some((call.keys, call.args))),
        }
    }

    /// The store's answer: `0`, or the retry-after time in milliseconds.
    fn on_store_answer(&mut self, answer: u64) -> Option<u64> {
        retry_after(self.inner.on_store_answer(answer))
    }

    fn on_store_failed(&mut self, now: u64) {
        self.inner.on_store_failed(now);
    }

    fn store_backed_off(&self, now: u64) -> bool {
        self.inner.store_backed_off(now)
    }

    fn clear(&mut self) {
        self.inner.clear();
    }

    fn local_keys(&self) -> usize {
        self.inner.local_keys()
    }
}

#[pymodule]
fn _core(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<Core>()?;
    module.add_class::<RateLimiterCore>()?;
    module.add("STORE_SCRIPT", STORE_SCRIPT)
}
