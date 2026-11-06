//! The relying core: everything a relying system needs to decide locally,
//! with no I/O.
//!
//! The core never makes network calls, reads clocks, spawns tasks or sleeps.
//! A host binding feeds it the current time (in milliseconds), JWKS
//! documents, session states, entitlement sets and change-feed events, and
//! asks it for decisions and for the work it wants done:
//!
//! - [`Relying::decide`] answers from the caches, or says what is missing
//!   (`Need`), including [`Need::Check`] when the caches can't be trusted and
//!   the host must ask Konklav's check API instead.
//! - [`Relying::poll_work`] lists background fetches that are due, and when
//!   to poll next, so busy entries are refreshed before they expire.
//! - The `on_*` methods apply what the host fetched or received.
//!
//! Every decision rule lives here, so all host bindings behave identically.

// r[impl item.relying.sans-io]
// r[impl item.relying.single-implementation]
mod cache;
mod config;
mod presented;

pub use cache::{Key, Need, Outcome, Relying, RequestDescriptor, ScopeRecord, Verification, Work};
pub use config::Config;
pub use presented::Presented;
