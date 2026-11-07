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
    /// Allowed, for `token`, by a policy admitting `admitted`.
    Allowed {
        token: AccessClaims,
        admitted: BTreeSet<TokenKind>,
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

pub(crate) fn is_websocket(parts: &Parts) -> bool {
    // HTTP/1.1 upgrades, and HTTP/2's extended CONNECT (RFC 8441).
    parts.method == Method::CONNECT
        || parts
            .headers
            .get(header::UPGRADE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
}

/// The URL the client addressed, without the public-URL hook.
fn own_url(parts: &Parts) -> String {
    let path = parts.uri.path_and_query().map_or("/", |path| path.as_str());
    if let (Some(scheme), Some(authority)) = (parts.uri.scheme_str(), parts.uri.authority()) {
        let scheme = match scheme {
            "ws" => "http",
            "wss" => "https",
            scheme => scheme,
        };
        return format!("{scheme}://{authority}{path}");
    }
    let host = parts
        .headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    format!("http://{host}{path}")
}

impl Konklav {
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
        let request = Some(RequestDescriptor {
            // A websocket opens with a GET.
            method: if websocket {
                "GET".to_owned()
            } else {
                parts.method.as_str().to_owned()
            },
            url: match &self.inner.public_url {
                Some(url) => url(parts),
                None => own_url(parts),
            },
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
    /// one acceptance and one decision.
    pub(crate) async fn evaluate(
        &self,
        policy: &Policy,
        parts: &mut Parts,
    ) -> Result<Evaluation, Response> {
        // r[impl item.axum.public]
        let Some(admitted) = policy.admitted_token_kinds() else {
            return Ok(Evaluation::Public {
                verified: false,
                token: None,
            });
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
        let token = accepted.claims();
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
        let Ok(decision) = self.host().decide_accepted(&accepted, &requirements).await else {
            return Err(self.respond(Denied::Unavailable));
        };
        let denied = match decision {
            Decision::Allow { .. } => {
                return Ok(Evaluation::Allowed {
                    token: token.clone(),
                    admitted,
                });
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
