//! [`RoutePacing`]: pacing (`konklav_relying_client::pacing`) as a layer.

use std::convert::Infallible;
use std::task::{Context, Poll};

use axum::extract::Request;
use axum::response::{IntoResponse, Response};
use konklav_relying_client::pacing::{Pacing, paced};
use tower::{Layer, Service};

use crate::evaluate::{Evaluation, is_websocket};
use crate::host::BoxFuture;
use crate::outcome::RoutePolicyError;

/// Paces the requests it wraps: each answers once both the inner service
/// and a wait drawn from its [`Pacing`] are done.
///
/// A route's layers wrap its whole answer, so a `RoutePacing` paces
/// everything inside it: allows, every [`Denied`](crate::Denied), rate
/// limits, the handler's errors and extractor rejections (an unparsable
/// body's 400 or 422). On a route, apply it with `route_layer` after the
/// route's [`RoutePolicy`](crate::RoutePolicy), so that it wraps the policy:
///
/// ```
/// # use std::time::Duration;
/// # use axum::{Router, routing::post};
/// # use konklav_axum::{Pacing, RoutePacing, RoutePolicy};
/// # fn app(policy: RoutePolicy) -> Router {
/// let pacing = Pacing::new(Duration::from_millis(1500), Duration::from_millis(250));
/// Router::new().route(
///     "/invites",
///     post(|| async { "..." })
///         .route_layer(policy)
///         .route_layer(RoutePacing::new(pacing)),
/// )
/// # }
/// ```
///
/// A `RoutePacing` inside a route's policy would start after the decision,
/// so a denial would answer sooner than an allow; it answers 500 instead
/// ([`RoutePolicyError::PacingAfterPolicy`]). Applied to a `Router` with
/// `layer`, it also paces the router's 404 and 405 answers. A panic isn't
/// paced; with a panic-catching layer inside it, the 500 it answers is.
/// Websocket upgrade requests aren't paced.
///
/// Each `RoutePacing` waits on its own, so a route under several waits for
/// the longest of them.
#[derive(Clone, Copy, Debug)]
pub struct RoutePacing {
    pacing: Pacing,
}

impl RoutePacing {
    /// Paces the requests it wraps with `pacing`.
    #[must_use]
    pub const fn new(pacing: Pacing) -> Self {
        Self { pacing }
    }

    /// Its pacing.
    #[must_use]
    pub const fn pacing(&self) -> Pacing {
        self.pacing
    }
}

impl<S> Layer<S> for RoutePacing {
    type Service = RoutePacingService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RoutePacingService {
            pacing: self.pacing,
            inner,
        }
    }
}

/// The service [`RoutePacing`] wraps a route in.
#[derive(Clone)]
pub struct RoutePacingService<S> {
    pacing: Pacing,
    inner: S,
}

impl<S> Service<Request> for RoutePacingService<S>
where
    S: Service<Request, Error = Infallible> + Clone + Send + 'static,
    S::Response: IntoResponse,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = BoxFuture<'static, Result<Response, Infallible>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    // r[impl item.axum.route-pacing]
    // r[impl item.axum.route-pacing.nested]
    // r[impl item.axum.route-pacing.order]
    fn call(&mut self, request: Request) -> Self::Future {
        // The clone that was polled ready serves this request.
        let ready = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, ready);
        let pacing = self.pacing;
        Box::pin(async move {
            if request.extensions().get::<Evaluation>().is_some() {
                return Ok(RoutePolicyError::PacingAfterPolicy.into_response());
            }
            let (parts, body) = request.into_parts();
            let websocket = is_websocket(&parts);
            let call = inner.call(Request::from_parts(parts, body));
            // Turned into a Response inside the paced work, which keeps it Send.
            let answer = async move { call.await.map(IntoResponse::into_response) };
            if websocket {
                answer.await
            } else {
                paced(pacing, answer).await
            }
        })
    }
}
