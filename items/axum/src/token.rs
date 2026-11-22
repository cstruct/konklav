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

/// The token kinds of a signed-in subject. The others (`partial`, after
/// only a first factor, `reset_password` and `invite`) are valid tokens
/// that sign nobody in.
const SIGNED_IN: [TokenKind; 2] = [TokenKind::Identity, TokenKind::Tenant];

/// The request's verified token, if any, and whether its route is public.
/// On a public route a presented token is verified here, once, without a
/// decision, and the hooks run; an invalid one is refused.
async fn optional(
    parts: &mut Parts,
    extractor: &'static str,
) -> Result<(Option<AccessClaims>, bool), Response> {
    match evaluation(parts, extractor)? {
        Evaluation::Allowed { token, .. } => Ok((Some(token), false)),
        Evaluation::Public {
            verified: true,
            token,
        } => Ok((token, true)),
        Evaluation::Public {
            verified: false, ..
        } => {
            let konklav = Konklav::of(parts).map_err(IntoResponse::into_response)?;
            let token = konklav.verify(parts).await?;
            parts.extensions.insert(Evaluation::Public {
                verified: true,
                token: token.clone(),
            });
            Ok((token, true))
        }
    }
}

/// The request's verified token, or `None` on a public route without one.
/// On a public route a presented token is verified, without a decision, and
/// the hooks run; an invalid one is refused.
///
/// A public route admits no token kinds, so there this gives only the
/// token of a signed-in subject, an `identity` or `tenant` token, and
/// `None` for any other valid token: a handler that greets whoever it gets
/// must not take a `partial` token, issued before the second factor, for a
/// sign-in. [`OptionalTokenOfAnyKind`] gives those too.
#[derive(Clone, Debug, PartialEq)]
pub struct OptionalToken(pub Option<AccessClaims>);

impl Deref for OptionalToken {
    type Target = Option<AccessClaims>;

    fn deref(&self) -> &Option<AccessClaims> {
        &self.0
    }
}

// r[impl item.axum.injected-tokens]
impl<S: Send + Sync> FromRequestParts<S> for OptionalToken {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Response> {
        let (token, public) = optional(parts, "OptionalToken").await?;
        Ok(Self(
            token.filter(|token| !public || SIGNED_IN.contains(&token.knd)),
        ))
    }
}

/// As [`OptionalToken`], but on a public route it gives a valid token of
/// any kind, also `partial`, `reset_password` and `invite` tokens, which
/// sign nobody in: check its `knd` before relying on it.
#[derive(Clone, Debug, PartialEq)]
pub struct OptionalTokenOfAnyKind(pub Option<AccessClaims>);

impl Deref for OptionalTokenOfAnyKind {
    type Target = Option<AccessClaims>;

    fn deref(&self) -> &Option<AccessClaims> {
        &self.0
    }
}

impl<S: Send + Sync> FromRequestParts<S> for OptionalTokenOfAnyKind {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Response> {
        let (token, _) = optional(parts, "OptionalTokenOfAnyKind").await?;
        Ok(Self(token))
    }
}
