//! Authorization without I/O: compiling role assignments into entitlement
//! sets, and evaluating an operation's requirements against them.
//!
//! The server compiles; the relying core (M4) evaluates. Both stay pure so
//! the rules can be pinned by golden tests and evaluated identically
//! everywhere.

// r[impl item.authz.sans-io]
mod compile;
mod evaluate;
mod model;

pub use compile::{Contribution, Explanation, compile, explain};
pub use evaluate::{Decision, DenyReason, Requirements, ScopeRequirement, StepUp, evaluate};
pub use model::{
    Assignment, Catalog, Effect, EntitlementSet, Entitlements, Group, Level, Policy, Scope,
};
