//! Extractors for the token a route's policy verified.

use std::collections::BTreeSet;
use std::ops::Deref;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use konklav_token::{AccessClaims, TokenKind};

use crate::evaluate::Evaluation;
use crate::{Konklav, RoutePolicyError};

fn evaluation(parts: &Parts, extractor: &'static str) -> Result<Evaluation, Response> {
    parts
        .extensions
        .get::<Evaluation>()
        .cloned()
        .ok_or_else(|| RoutePolicyError::NoPolicy { extractor }.into_response())
}

fn names(kinds: &BTreeSet<TokenKind>) -> String {
    kinds
        .iter()
        .filter_map(|kind| serde_json::to_value(kind).ok())
        .filter_map(|kind| kind.as_str().map(str::to_owned))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The allowed request's token, refusing a route whose policy admits a kind
/// `accepted` doesn't include, and public routes.
// r[impl item.axum.injected-kinds]
fn allowed(
    parts: &Parts,
    extractor: &'static str,
    accepted: Option<TokenKind>,
) -> Result<AccessClaims, Response> {
    match evaluation(parts, extractor)? {
        Evaluation::Public { .. } => Err(RoutePolicyError::Extractor {
            extractor,
            problem: "on a route whose policy is public; use OptionalToken".to_owned(),
        }
        .into_response()),
        Evaluation::Allowed {
            token, admitted, ..
        } => match accepted {
            Some(kind) if admitted.iter().any(|admitted| *admitted != kind) => {
                Err(RoutePolicyError::Extractor {
                    extractor,
                    problem: format!(
                        "takes only {} tokens, but its route's policy admits {}",
                        names(&BTreeSet::from([kind])),
                        names(&admitted)
                    ),
                }
                .into_response())
            }
            _ => Ok(token),
        },
    }
}

macro_rules! token_extractor {
    ($(#[$meta:meta])* $name:ident, $accepted:expr) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq)]
        pub struct $name(pub AccessClaims);

        impl Deref for $name {
            type Target = AccessClaims;

            fn deref(&self) -> &AccessClaims {
                &self.0
            }
        }

        impl<S: Send + Sync> FromRequestParts<S> for $name {
            type Rejection = Response;

            fn from_request_parts(
                parts: &mut Parts,
                _: &S,
            ) -> impl Future<Output = Result<Self, Response>> + Send {
                std::future::ready(allowed(parts, stringify!($name), $accepted).map(Self))
            }
        }
    };
}

// r[impl item.axum.injected-tokens]
token_extractor!(
    /// The request's verified token, of any kind the route's policy admits.
    CurrentToken,
    None
);
token_extractor!(
    /// The request's verified `identity` token.
    IdentityToken,
    Some(TokenKind::Identity)
);
token_extractor!(
    /// The request's verified `tenant` token.
    TenantToken,
    Some(TokenKind::Tenant)
);

/// The request's verified token, or `None` on a public route without one.
/// On a public route a presented token is verified, without a decision, and
/// the hooks run; an invalid one is refused.
#[derive(Clone, Debug, PartialEq)]
pub struct OptionalToken(pub Option<AccessClaims>);

impl Deref for OptionalToken {
    type Target = Option<AccessClaims>;

    fn deref(&self) -> &Option<AccessClaims> {
        &self.0
    }
}

impl<S: Send + Sync> FromRequestParts<S> for OptionalToken {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Response> {
        match evaluation(parts, "OptionalToken")? {
            Evaluation::Allowed { token, .. } => Ok(Self(Some(token))),
            Evaluation::Public {
                verified: true,
                token,
            } => Ok(Self(token)),
            Evaluation::Public {
                verified: false, ..
            } => {
                let konklav = Konklav::of(parts).map_err(IntoResponse::into_response)?;
                let token = konklav.verify(parts).await?;
                parts.extensions.insert(Evaluation::Public {
                    verified: true,
                    token: token.clone(),
                });
                Ok(Self(token))
            }
        }
    }
}
