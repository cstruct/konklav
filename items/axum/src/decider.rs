//! Deciding further requirements for an allowed request, with the
//! presentation its route policy accepted.

use std::fmt;
use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use konklav_authz::{Decision, Requirements};
use konklav_relying_client::Error;
use konklav_token::AccessClaims;

use crate::RoutePolicyError;
use crate::host::{Accepted, RelyingHost};

struct Inner {
    host: Arc<dyn RelyingHost>,
    accepted: Accepted,
}

/// Decides further requirements for an allowed request, such as a GraphQL
/// server's per field, with the presentation its route policy accepted,
/// without checking the request's DPoP proof again. Its route policy
/// releases the presentation once the handler has answered, after which it
/// decides nothing. Extract it in a handler behind a [`crate::RoutePolicy`]
/// that isn't public.
// r[impl item.axum.request-decider]
#[derive(Clone)]
pub struct RequestDecider {
    inner: Arc<Inner>,
}

impl RequestDecider {
    pub(crate) fn new(host: Arc<dyn RelyingHost>, accepted: Accepted) -> Self {
        Self {
            inner: Arc::new(Inner { host, accepted }),
        }
    }

    /// The verified token's claims.
    #[must_use]
    pub fn claims(&self) -> &AccessClaims {
        self.inner.accepted.claims()
    }

    /// Decides `requirements` for the request. Fails closed: an error means
    /// deny.
    pub async fn decide(&self, requirements: &Requirements) -> Result<Decision, Error> {
        self.inner
            .host
            .decide_accepted(&self.inner.accepted, requirements)
            .await
    }

    /// The route decision, made for the route's own requirements.
    pub(crate) fn accepted(&self) -> &Accepted {
        &self.inner.accepted
    }

    /// Releases the presentation: it decides nothing more.
    pub(crate) fn release(&self) {
        self.inner.host.release_accepted(&self.inner.accepted);
    }
}

impl fmt::Debug for RequestDecider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestDecider")
            .field("claims", self.claims())
            .finish_non_exhaustive()
    }
}

impl<S: Send + Sync> FromRequestParts<S> for RequestDecider {
    type Rejection = Response;

    fn from_request_parts(
        parts: &mut Parts,
        _: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let decider = parts.extensions.get::<Self>().cloned().ok_or_else(|| {
            RoutePolicyError::Extractor {
                extractor: "RequestDecider",
                problem: "on a route without a policy that isn't public".to_owned(),
            }
            .into_response()
        });
        std::future::ready(decider)
    }
}
