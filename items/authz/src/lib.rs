//! Authorization without I/O: compiling role assignments into entitlement
//! sets, and evaluating an operation's requirements against them.
//!
//! The server compiles; the relying core (M4) evaluates. Both stay pure so
//! the rules can be pinned by golden tests and evaluated identically
//! everywhere.

// r[impl item.authz.sans-io]
mod compile;
mod evaluate;
mod explain;
mod model;
mod route_authority;

pub use compile::{compile, shared};
pub use evaluate::{
    Decision, DenyReason, Obligation, Requirements, ScopeRequirement, StepUp, evaluate,
    evaluate_with_route_authority,
};
pub use explain::{
    ActionExplanation, Check, Contribution, DecisionExplanation, ExplainInput, Explanation, Reason,
    RouteExplanation, SessionContext, explain, explain_decision,
};
pub use model::{
    Assignment, Catalog, Confinement, Confinements, Effect, EntitlementSet, Entitlements, Group,
    Level, Policy, RegisteredScopes, Registration, Scope, Share, Shared, describe_predicates,
    failing_predicate,
};
pub use route_authority::{RouteAuthority, VouchedScope};
