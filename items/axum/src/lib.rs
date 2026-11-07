//! Route policies and rate limits for axum, decided by the Konklav relying
//! core through [`konklav_relying_client`].
//!
//! A relying system declares a route policy on each route and installs one
//! [`Konklav`] on its router:
//!
//! ```no_run
//! use axum::{Router, routing::get};
//! use konklav_axum::{Konklav, RouterPolicy, TenantToken};
//! use konklav_relying::policy::Policy;
//! use konklav_relying_client::RelyingClient;
//!
//! async fn read_document(token: TenantToken) -> String {
//!     token.sub.to_string()
//! }
//!
//! fn app(client: RelyingClient) -> Result<Router, Box<dyn std::error::Error>> {
//!     let projects = RouterPolicy::new(Policy::new().tenant_actions(["project:read"]));
//!     let konklav = Konklav::builder(client).build()?;
//!     Ok(Router::new()
//!         .route(
//!             "/projects/{project}/documents/{document}",
//!             get(read_document).route_layer(projects.route(
//!                 &Policy::new()
//!                     .scope_actions("document", ["document:read"])
//!                     .admit_flags(["personal_only"]),
//!             )?),
//!         )
//!         .layer(konklav.layer()))
//! }
//! ```
//!
//! Per request, the route's [`RoutePolicy`] (merged, outermost first, when
//! it was built) is evaluated once: the token is taken from the request and
//! accepted once ([`RelyingHost::accept_request`]), the hooks run, a route
//! tenant other than the token's is denied, the scopes are resolved, and one
//! decision is made. Anything but an allow answers with a [`Denied`].
//!
//! [`RoutePacing`] paces a route's answers, so that how long they take
//! doesn't show whether a record exists.
//!
//! Every decision is the relying core's; this crate only translates.

// Published with the other crates, requiring konklav-relying and
// konklav-relying-client at exactly its version (Cargo.toml).
// r[impl item.axum.published]

// Rejections are responses, as axum's extractors and middleware return them.
#![allow(clippy::result_large_err)]

mod client_address;
mod config;
mod evaluate;
mod host;
mod outcome;
mod pacing;
mod policy;
pub mod rate_limit;
mod token;

pub use client_address::{ClientAddress, InvalidProxy};
pub use config::{Konklav, KonklavBuilder};
pub use evaluate::{PathParams, path_param};
pub use host::{Accepted, BoxFuture, RelyingHost};
pub use outcome::{
    Denied, Forbidden, RoutePolicyError, Scheme, Unauthenticated, retry_after_seconds,
};
pub use pacing::{RoutePacing, RoutePacingService};
pub use policy::{RoutePolicy, RoutePolicyService, RouterPolicy};
pub use rate_limit::RouteRateLimit;
pub use token::{CurrentToken, IdentityToken, OptionalToken, TenantToken};

/// Pacing, for [`RoutePacing`] and for pacing work inside a handler.
pub use konklav_relying_client::pacing::{Pacing, paced};

/// The route-policy model the policies are built from.
pub use konklav_relying::policy::{FactValue, Policy, PolicyError, ResolvedScope};

/// The README's examples, compiled as doctests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
