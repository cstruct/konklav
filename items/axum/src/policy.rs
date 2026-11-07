//! Route policies on axum routes: [`RouterPolicy`] for the routers around a
//! route, and the [`RoutePolicy`] layer each route carries.

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::extract::Request;
use axum::response::{IntoResponse, Response};
use konklav_relying::policy::{Policy, ResolvedScope};
use konklav_token::TokenKind;
use serde_json::{Value, json};
use tower::{Layer, Service};

use crate::evaluate::{Evaluation, read_path_params};
use crate::host::BoxFuture;
use crate::{Konklav, RoutePolicyError, RouteRateLimit};

/// The route policies of the routers around a route, outermost first. A
/// value, not a layer: each route finishes it with its own route policy
/// ([`RouterPolicy::route`]) into the one [`RoutePolicy`] it carries.
///
/// ```
/// use konklav_axum::RouterPolicy;
/// use konklav_relying::policy::Policy;
///
/// let api = RouterPolicy::new(Policy::new().tenant_actions(["project:read"]));
/// let documents = api.nest(Policy::new().scope_actions("project", ["document:read"]));
/// let read = documents.route(&Policy::new().admit_flags(["personal_only"])).unwrap();
/// assert_eq!(read.describe()["tenant"], serde_json::json!(["project:read"]));
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RouterPolicy {
    layers: Vec<Policy>,
}

impl RouterPolicy {
    /// The outermost router's route policy.
    #[must_use]
    pub fn new(policy: Policy) -> Self {
        Self {
            layers: vec![policy],
        }
    }

    /// The route policies of a router nested inside this one.
    #[must_use]
    pub fn nest(&self, policy: Policy) -> Self {
        let mut nested = self.clone();
        nested.layers.push(policy);
        nested
    }

    /// The [`RoutePolicy`] of a route inside these routers, with `own`, its
    /// own route policy: all of them merged, outermost first. Refuses what
    /// its route policies alone show can't be evaluated.
    // r[impl item.axum.route-policy]
    // r[impl item.axum.admit-flags-operation]
    // r[impl item.axum.validation]
    pub fn route(&self, own: &Policy) -> Result<RoutePolicy, RoutePolicyError> {
        if self
            .layers
            .iter()
            .any(|policy| policy.admitted_flags().is_some())
        {
            return Err(RoutePolicyError::AdmitFlagsOutsideRoute);
        }
        let policy = Policy::merge(self.layers.iter().chain([own]))?;
        policy.check()?;
        Ok(RoutePolicy {
            inner: Arc::new(RouteInner {
                policy,
                rate_limits: Vec::new(),
            }),
        })
    }
}

struct RouteInner {
    policy: Policy,
    rate_limits: Vec<RouteRateLimit>,
}

/// The layer a route carries: its complete route policy, evaluated once per
/// request before the handler runs. Apply it to the route's
/// `MethodRouter`, with `route_layer` or `layer`.
///
/// ```no_run
/// # async fn read() {}
/// use axum::{Router, routing::get};
/// use konklav_axum::RoutePolicy;
/// use konklav_relying::policy::Policy;
///
/// let app: Router = Router::new()
///     .route("/projects/{project}", get(read).route_layer(
///         RoutePolicy::new(&Policy::new().scope_actions("project", ["project:read"]))?,
///     ))
///     .route("/health", get(|| async { "ok" }).route_layer(RoutePolicy::public()));
/// # Ok::<_, konklav_axum::RoutePolicyError>(())
/// ```
#[derive(Clone)]
pub struct RoutePolicy {
    inner: Arc<RouteInner>,
}

impl RoutePolicy {
    /// The route policy of a route with no router policy around it.
    pub fn new(own: &Policy) -> Result<Self, RoutePolicyError> {
        RouterPolicy::default().route(own)
    }

    /// A route anyone may use, without a token.
    #[must_use]
    pub fn public() -> Self {
        Self {
            inner: Arc::new(RouteInner {
                policy: Policy::public(),
                rate_limits: Vec::new(),
            }),
        }
    }

    /// The merged route policy.
    #[must_use]
    pub fn policy(&self) -> &Policy {
        &self.inner.policy
    }

    /// Adds one event to `limit` for each request this policy allows, after
    /// the decision, with the token it verified. Refuses a template this
    /// policy can't render.
    // r[impl item.axum.rate-limit-template-validation]
    pub fn rate_limit(self, limit: RouteRateLimit) -> Result<Self, RoutePolicyError> {
        let admitted = self.inner.policy.admitted_token_kinds();
        if let Some(problem) = limit.problem(admitted.as_ref()) {
            return Err(RoutePolicyError::RateLimit {
                name: limit.name(),
                problem,
            });
        }
        let mut rate_limits = self.inner.rate_limits.clone();
        rate_limits.push(limit);
        Ok(Self {
            inner: Arc::new(RouteInner {
                policy: self.inner.policy.clone(),
                rate_limits,
            }),
        })
    }

    /// The merged route policy as `konklav-fastapi` publishes it in `OpenAPI`
    /// (`x-konklav-policy`): `{"public": true}`, or `{"public": false}` with
    /// the requirements, each scope given by its kind and actions alone.
    // r[impl item.axum.describe]
    #[must_use]
    pub fn describe(&self) -> Value {
        let policy = &self.inner.policy;
        if policy.is_public() {
            return json!({"public": true});
        }
        let placeholders: BTreeMap<String, ResolvedScope> = policy
            .scope_kinds()
            .map(|kind| (kind.to_owned(), ResolvedScope::new("")))
            .collect();
        let Ok(requirements) = policy.requirements(&placeholders) else {
            return json!({"public": false});
        };
        let mut described = serde_json::to_value(&requirements).unwrap_or_else(|_| json!({}));
        if let Some(scopes) = described.get_mut("scopes").and_then(Value::as_array_mut) {
            for scope in scopes {
                if let Some(scope) = scope.as_object_mut() {
                    scope.retain(|key, _| key == "kind" || key == "actions");
                }
            }
        }
        if let Some(described) = described.as_object_mut() {
            described.insert("public".to_owned(), Value::Bool(false));
        }
        described
    }

    /// Evaluates the request, keeping what it found in its extensions.
    async fn evaluate(&self, parts: &mut axum::http::request::Parts) -> Result<(), Response> {
        let konklav = Konklav::of(parts).map_err(IntoResponse::into_response)?;
        if parts.extensions.get::<Evaluation>().is_some() {
            return Err(RoutePolicyError::Twice.into_response());
        }
        read_path_params(parts).await;
        let evaluation = konklav.evaluate(&self.inner.policy, parts).await?;
        let token = evaluation.token().cloned();
        parts.extensions.insert(evaluation);
        for limit in &self.inner.rate_limits {
            limit.add(&konklav, parts, token.as_ref()).await?;
        }
        Ok(())
    }

    /// The token kinds the policy admits, `None` when public.
    #[must_use]
    pub fn admitted_token_kinds(&self) -> Option<BTreeSet<TokenKind>> {
        self.inner.policy.admitted_token_kinds()
    }
}

impl<S> Layer<S> for RoutePolicy {
    type Service = RoutePolicyService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RoutePolicyService {
            policy: self.clone(),
            inner,
        }
    }
}

/// The service [`RoutePolicy`] wraps a route in.
#[derive(Clone)]
pub struct RoutePolicyService<S> {
    policy: RoutePolicy,
    inner: S,
}

impl<S> Service<Request> for RoutePolicyService<S>
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

    // Before the handler, so before any websocket upgrade: a refused
    // upgrade is answered with its status.
    // r[impl item.axum.websockets]
    fn call(&mut self, request: Request) -> Self::Future {
        // The clone that was polled ready serves this request.
        let ready = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, ready);
        let policy = self.policy.clone();
        Box::pin(async move {
            let (mut parts, body) = request.into_parts();
            if let Err(response) = policy.evaluate(&mut parts).await {
                return Ok(response);
            }
            let response = inner.call(Request::from_parts(parts, body)).await?;
            Ok(response.into_response())
        })
    }
}
