//! Evaluating a route's policy for one request.

use std::collections::{BTreeMap, BTreeSet};

use axum::extract::{FromRequestParts, Query, RawPathParams};
use axum::http::request::Parts;
use axum::http::{Method, header};
use axum::response::{IntoResponse, Response};
use konklav_authz::{Decision, DenyReason};
use konklav_relying::policy::{Policy, ResolvedScope};
use konklav_relying_client::{Presented, RequestDescriptor, Verified};
use konklav_token::{AccessClaims, TokenKind};

use crate::decider::{HeldPresentation, RequestDecider};
use crate::outcome::{Forbidden, Scheme, Unauthenticated};
use crate::{Denied, Konklav, RoutePolicyError};

/// What a route's policy found for a request, kept in its extensions for
/// the extractors and rate limits.
#[derive(Clone, Debug)]
pub(crate) enum Evaluation {
    /// A public route, with `token` once `OptionalToken` has verified any
    /// presented token (`verified`).
    Public {
        verified: bool,
        token: Option<AccessClaims>,
    },
    /// Allowed, for `token`, by a policy admitting `admitted`, with what
    /// decides the request's further requirements.
    Allowed {
        token: AccessClaims,
        admitted: BTreeSet<TokenKind>,
        decider: RequestDecider,
    },
}

impl Evaluation {
    /// The verified token, if any.
    pub(crate) fn token(&self) -> Option<&AccessClaims> {
        match self {
            Self::Allowed { token, .. } => Some(token),
            Self::Public { token, .. } => token.as_ref(),
        }
    }
}

/// A request's path parameters, percent-decoded, as route policies read
/// them. Route policies insert them into the request's extensions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PathParams(pub BTreeMap<String, String>);

/// The path parameter `name` of the request, once a route policy has read
/// the path parameters, as for scope resolvers and hooks.
#[must_use]
pub fn path_param<'a>(parts: &'a Parts, name: &str) -> Option<&'a str> {
    parts
        .extensions
        .get::<PathParams>()
        .and_then(|params| params.0.get(name))
        .map(String::as_str)
}

/// Reads the matched route's path parameters into the extensions.
pub(crate) async fn read_path_params(parts: &mut Parts) {
    if parts.extensions.get::<PathParams>().is_some() {
        return;
    }
    let params = RawPathParams::from_request_parts(parts, &())
        .await
        .map(|params| {
            params
                .iter()
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect()
        })
        .unwrap_or_default();
    parts.extensions.insert(PathParams(params));
}

/// A presented token, as the core takes it.
pub(crate) struct PresentedToken {
    pub(crate) presented: Presented,
    pub(crate) scheme: Scheme,
}

/// Whether `name`'s values, as comma-separated lists, include `token`.
fn lists(parts: &Parts, name: header::HeaderName, token: &str) -> bool {
    parts
        .headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|listed| listed.trim().eq_ignore_ascii_case(token))
}

/// Whether the request asks to open a websocket: an HTTP/1.1 upgrade (a
/// `GET` with `Connection: upgrade` and `Upgrade: websocket`, RFC 6455), or
/// HTTP/2's extended CONNECT with the `websocket` protocol (RFC 8441). The
/// `Upgrade` header alone, on any other request, makes no websocket.
// r[impl item.axum.websocket-requests]
pub(crate) fn is_websocket(parts: &Parts) -> bool {
    if parts.method == Method::CONNECT {
        return parts
            .extensions
            .get::<hyper::ext::Protocol>()
            .is_some_and(|protocol| protocol.as_str().eq_ignore_ascii_case("websocket"));
    }
    parts.method == Method::GET
        && lists(parts, header::CONNECTION, "upgrade")
        && lists(parts, header::UPGRADE, "websocket")
}

/// The path and query the client addressed.
fn addressed_path(parts: &Parts) -> &str {
    parts.uri.path_and_query().map_or("/", |path| path.as_str())
}

/// The authority the request names for itself: its target's, else its
/// `Host` header. The client chooses it.
fn named_authority(parts: &Parts) -> Option<&str> {
    parts
        .uri
        .authority()
        .map(axum::http::uri::Authority::as_str)
        .or_else(|| {
            parts
                .headers
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
        })
}

/// The URL the request names for itself, for `trust_host_header`.
fn own_url(parts: &Parts) -> String {
    let path = addressed_path(parts);
    let scheme = match parts.uri.scheme_str() {
        Some("https" | "wss") if parts.uri.authority().is_some() => "https",
        _ => "http",
    };
    let authority = named_authority(parts).unwrap_or_default();
    format!("{scheme}://{authority}{path}")
}

/// An evaluation, with what holds its accepted presentation, if any, until
/// the request is answered.
pub(crate) type Evaluated = (Evaluation, Option<HeldPresentation>);

impl Konklav {
    /// The URL a DPoP proof must name, from configuration: the public-URL
    /// hook's, else a public origin with the request's path. `None` when
    /// neither is configured, unless the application trusts the `Host`
    /// header.
    // r[impl item.axum.proof-url]
    fn proof_url(&self, parts: &Parts) -> Option<String> {
        if let Some(url) = &self.inner.public_url {
            return Some(url(parts));
        }
        let origins = &self.inner.public_origins;
        let Some(first) = origins.first() else {
            return self.inner.trust_host_header.then(|| own_url(parts));
        };
        // The request only chooses among the configured origins.
        let named = named_authority(parts);
        let origin = origins
            .iter()
            .find(|origin| {
                let authority = origin
                    .split_once("://")
                    .map_or("", |(_, authority)| authority);
                named.is_some_and(|named| named.eq_ignore_ascii_case(authority))
            })
            .unwrap_or(first);
        Some(format!("{origin}{}", addressed_path(parts)))
    }

    /// The request's token: from `Authorization`, the cookie hook or, for
    /// websockets, the `token` query parameter.
    // r[impl item.axum.token-extraction]
    pub(crate) fn presented(&self, parts: &Parts) -> Option<PresentedToken> {
        let header = |name| {
            parts
                .headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        let dpop = header(header::HeaderName::from_static("dpop"));
        let websocket = is_websocket(parts);
        let url = self.proof_url(parts);
        if url.is_none() && dpop.is_some() {
            tracing::error!(
                "a DPoP proof was presented but no public origin is configured \
                 (KonklavBuilder::public_origin); refusing it"
            );
        }
        // Without a URL the core refuses any proof.
        let request = url.map(|url| RequestDescriptor {
            // A websocket opens with a GET.
            method: if websocket {
                "GET".to_owned()
            } else {
                parts.method.as_str().to_owned()
            },
            url,
        });
        if let Some(authorization) = header(header::AUTHORIZATION).filter(|value| !value.is_empty())
        {
            return Some(PresentedToken {
                scheme: Scheme::of(&authorization),
                presented: Presented {
                    authorization,
                    dpop,
                    request,
                },
            });
        }
        let mut token = self.inner.cookie.as_ref().and_then(|cookie| cookie(parts));
        if token.as_deref().is_none_or(str::is_empty) && websocket {
            token = Query::<BTreeMap<String, String>>::try_from_uri(&parts.uri)
                .ok()
                .and_then(|Query(mut query)| query.remove("token"));
        }
        let token = token.filter(|token| !token.is_empty())?;
        let scheme = if dpop.is_some() {
            Scheme::DPoP
        } else {
            Scheme::Bearer
        };
        let authorization = match scheme {
            Scheme::DPoP => format!("DPoP {token}"),
            Scheme::Bearer => format!("Bearer {token}"),
        };
        Some(PresentedToken {
            presented: Presented {
                authorization,
                dpop,
                request,
            },
            scheme,
        })
    }

    /// Runs the hooks on a verified token, in order.
    // r[impl item.axum.hooks]
    pub(crate) async fn run_hooks(
        &self,
        parts: &Parts,
        token: &AccessClaims,
    ) -> Result<(), Response> {
        for hook in &self.inner.hooks {
            hook(parts, token).await?;
        }
        Ok(())
    }

    /// For public routes, which make no decision: a presented token,
    /// verified, with the hooks run.
    pub(crate) async fn verify(&self, parts: &Parts) -> Result<Option<AccessClaims>, Response> {
        let Some(presented) = self.presented(parts) else {
            return Ok(None);
        };
        let token = match self.host().verify_request(&presented.presented).await {
            Ok(Verified::Valid(token)) => token,
            Ok(Verified::Invalid) => {
                return Err(self.respond(Denied::Unauthenticated {
                    reason: Unauthenticated::InvalidToken,
                    scheme: Some(presented.scheme),
                }));
            }
            Ok(Verified::InvalidProof) => {
                return Err(self.respond(Denied::Unauthenticated {
                    reason: Unauthenticated::InvalidDpopProof,
                    scheme: None,
                }));
            }
            Err(_) => return Err(self.respond(Denied::Unavailable)),
        };
        self.run_hooks(parts, &token).await?;
        Ok(Some(token))
    }

    /// Evaluates `policy` for the request: nothing for a public one, else
    /// one acceptance and one decision. The accepted presentation is
    /// released when what holds it is dropped, here for a refused request.
    pub(crate) async fn evaluate(
        &self,
        policy: &Policy,
        parts: &mut Parts,
    ) -> Result<Evaluated, Response> {
        // r[impl item.axum.public]
        let Some(admitted) = policy.admitted_token_kinds() else {
            let public = Evaluation::Public {
                verified: false,
                token: None,
            };
            return Ok((public, None));
        };
        // Where each scope comes from, checked before reading any token.
        for kind in policy.scope_kinds() {
            if !self.inner.scope_resolvers.contains_key(kind) && path_param(parts, kind).is_none() {
                return Err(RoutePolicyError::MissingScope {
                    kind: kind.to_owned(),
                }
                .into_response());
            }
        }
        let Some(presented) = self.presented(parts) else {
            return Err(self.respond(Denied::Unauthenticated {
                reason: Unauthenticated::MissingToken,
                scheme: None,
            }));
        };
        let scheme = presented.scheme;

        // r[impl item.axum.verify-then-decide]
        let accepted = match self.host().accept_request(&presented.presented).await {
            Ok(Verified::Valid(accepted)) => accepted,
            Ok(Verified::Invalid) => {
                return Err(self.respond(Denied::Unauthenticated {
                    reason: Unauthenticated::InvalidToken,
                    scheme: Some(scheme),
                }));
            }
            Ok(Verified::InvalidProof) => {
                return Err(self.respond(Denied::Unauthenticated {
                    reason: Unauthenticated::InvalidDpopProof,
                    scheme: None,
                }));
            }
            Err(_) => return Err(self.respond(Denied::Unavailable)),
        };
        // r[impl item.axum.request-decider]
        let decider = RequestDecider::new(self.inner.host.clone(), accepted);
        let held = HeldPresentation::new(decider.clone());
        let token = decider.claims();
        self.run_hooks(parts, token).await?;

        // r[impl item.axum.token-tenant]
        // r[depends item.py.policy.token-tenant]
        if let Some(route_tenant) = &self.inner.route_tenant
            && let Some(tenant) = route_tenant(parts, token).await?
            && Some(tenant) != token.tid
        {
            return Err(self.respond(Denied::Forbidden(Forbidden::TokenTenant)));
        }

        // r[impl item.axum.scope-resolvers]
        let mut scopes = BTreeMap::new();
        for kind in policy.scope_kinds() {
            let scope = match self.inner.scope_resolvers.get(kind) {
                Some(resolve) => resolve(parts, token).await?,
                None => ResolvedScope::new(path_param(parts, kind).unwrap_or_default()),
            };
            scopes.insert(kind.to_owned(), scope);
        }
        let requirements = policy
            .requirements(&scopes)
            .map_err(|error| RoutePolicyError::Policy(error).into_response())?;

        // r[impl item.axum.single-decision]
        let token = token.clone();
        let Ok(decision) = self
            .host()
            .decide_accepted(decider.accepted(), &requirements, true)
            .await
        else {
            return Err(self.respond(Denied::Unavailable));
        };
        let denied = match decision {
            Decision::Allow { .. } => {
                let allowed = Evaluation::Allowed {
                    token,
                    admitted,
                    decider,
                };
                return Ok((allowed, Some(held)));
            }
            Decision::StepUp { requirement } => Denied::StepUpRequired {
                requirement,
                scheme,
            },
            Decision::Deny {
                reason: DenyReason::InvalidToken,
            } => Denied::Unauthenticated {
                reason: Unauthenticated::InvalidToken,
                scheme: Some(scheme),
            },
            Decision::Deny {
                reason: DenyReason::InvalidDpopProof,
            } => Denied::Unauthenticated {
                reason: Unauthenticated::InvalidDpopProof,
                scheme: Some(scheme),
            },
            Decision::Deny { reason } => Denied::Forbidden(Forbidden::Decision(reason)),
        };
        Err(self.respond(denied))
    }
}
