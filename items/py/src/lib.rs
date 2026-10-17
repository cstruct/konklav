//! Python bindings for the relying core.
//!
//! The binding is deliberately thin: values cross the boundary as JSON, and
//! every rule stays in `conclave-relying`. The Python package
//! `conclave_relying` adds the I/O (httpx, asyncio) around it.

use conclave_authz::{EntitlementSet, Requirements};
use conclave_core::Cursor;
use conclave_core::feed::{FeedEvent, SessionChanged};
use conclave_relying::{Config, Need, Relying};
use conclave_token::JwkSet;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

fn parse<T: serde::de::DeserializeOwned>(json: &str, what: &str) -> PyResult<T> {
    serde_json::from_str(json).map_err(|e| PyValueError::new_err(format!("invalid {what}: {e}")))
}

fn dump<T: serde::Serialize>(value: &T) -> PyResult<String> {
    serde_json::to_string(value).map_err(|e| PyValueError::new_err(e.to_string()))
}

/// The relying core. Times are Unix milliseconds; values are JSON strings.
#[pyclass(module = "conclave_relying._core")]
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
    fn on_feed_event(&mut self, event: &str, now: u64) -> PyResult<()> {
        let event: FeedEvent = parse(event, "feed event")?;
        self.inner
            .on_feed_event(&event, now)
            .map_err(|e| PyValueError::new_err(format!("malformed feed event: {e}")))
    }

    fn await_cursor(&mut self, cursor: i64) -> bool {
        self.inner.await_cursor(Cursor::new(cursor))
    }

    /// Returns `{"fetch": [...needs], "next_poll_at": ms}`.
    fn poll_work(&mut self, now: u64) -> PyResult<String> {
        dump(&self.inner.poll_work(now))
    }
}

#[pymodule]
fn _core(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<Core>()
}
