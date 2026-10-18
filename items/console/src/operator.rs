//! The signed-in operator, and the decisions around their access token.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;

use crate::api::types::{OwnCapabilities, TokenResponse};
use crate::grants::Grants;

/// The access-token claims the console reads. It never verifies them: the
/// token is for Conclave, which does.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub sid: String,
    pub exp: i64,
}

/// Reads the claims of a JWT without verifying it.
#[must_use]
pub fn claims(token: &str) -> Option<Claims> {
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// How the operator signed in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignIn {
    /// With their own credentials: the access token has a session and a
    /// refresh cookie behind it.
    Credentials { subject: String, session: String },
    /// With the bootstrap token, which can't be refreshed.
    Bootstrap,
}

/// The operator the console acts for. The access token lives only here, in
/// memory: a reload restores it from the refresh cookie, never from storage.
// r[impl item.console.token-in-memory]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operator {
    pub token: String,
    pub sign_in: SignIn,
    pub grants: Grants,
}

impl Operator {
    #[must_use]
    pub fn bootstrap(token: &str) -> Self {
        Self {
            token: token.trim().to_owned(),
            sign_in: SignIn::Bootstrap,
            grants: Grants::bootstrap(),
        }
    }

    #[must_use]
    pub fn signed_in(token: &TokenResponse, capabilities: OwnCapabilities) -> Self {
        Self {
            token: token.access_token.clone(),
            sign_in: SignIn::Credentials {
                subject: capabilities.subject,
                session: token.session_id.clone(),
            },
            grants: Grants::held(capabilities.capabilities),
        }
    }

    #[must_use]
    pub fn can_refresh(&self) -> bool {
        matches!(self.sign_in, SignIn::Credentials { .. })
    }

    #[must_use]
    pub fn subject(&self) -> Option<&str> {
        match &self.sign_in {
            SignIn::Credentials { subject, .. } => Some(subject),
            SignIn::Bootstrap => None,
        }
    }
}

/// What to do when Conclave rejects the access token a request carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retry {
    /// Another request refreshed meanwhile: try again with the new token.
    WithCurrent,
    /// Refresh, then try again.
    Refresh,
    /// The operator has to sign in again.
    SignIn,
}

/// Decides how to recover from a rejected access token, given the token
/// the request carried and the operator now.
///
/// Every refresh rotates the refresh token, and Conclave revokes the
/// session when a rotated one is presented again. So a request that lost a
/// race with another refresh must reuse its result instead of refreshing
/// again.
#[must_use]
pub fn after_rejection(used: Option<&str>, now: Option<&Operator>) -> Retry {
    match now {
        Some(operator) if used != Some(operator.token.as_str()) => Retry::WithCurrent,
        Some(operator) if operator.can_refresh() => Retry::Refresh,
        _ => Retry::SignIn,
    }
}

/// What comes after the first factor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AfterLogin {
    /// The credential requires MFA; the partial token can only list
    /// factors and complete it.
    Mfa(TokenResponse),
    Done(TokenResponse),
}

#[must_use]
pub fn after_login(token: TokenResponse) -> AfterLogin {
    if token.token_kind == "partial" {
        AfterLogin::Mfa(token)
    } else {
        AfterLogin::Done(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(kind: &str) -> TokenResponse {
        TokenResponse {
            access_token: "header.payload.signature".into(),
            token_kind: kind.into(),
            expires_in: 900,
            session_id: "s1".into(),
        }
    }

    fn operator(token: &str) -> Operator {
        Operator::signed_in(
            &TokenResponse {
                access_token: token.into(),
                ..self::token("identity")
            },
            OwnCapabilities {
                subject: "ada".into(),
                capabilities: vec![],
            },
        )
    }

    #[test]
    fn reads_claims_without_verifying() {
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"ada","sid":"s1","exp":42,"sv":1}"#);
        let claims = claims(&format!("e30.{payload}.sig")).unwrap();
        assert_eq!(claims.sub, "ada");
        assert_eq!(claims.exp, 42);
        assert_eq!(super::claims("not-a-jwt"), None);
    }

    #[test]
    fn rejected_requests_reuse_a_newer_token_before_refreshing() {
        let now = operator("new");
        assert_eq!(after_rejection(Some("old"), Some(&now)), Retry::WithCurrent);
        assert_eq!(after_rejection(Some("new"), Some(&now)), Retry::Refresh);
        assert_eq!(after_rejection(Some("new"), None), Retry::SignIn);
    }

    #[test]
    fn bootstrap_tokens_are_never_refreshed() {
        let bootstrap = Operator::bootstrap(" token ");
        assert_eq!(bootstrap.token, "token");
        assert_eq!(bootstrap.subject(), None);
        assert_eq!(
            after_rejection(Some("token"), Some(&bootstrap)),
            Retry::SignIn
        );
    }

    #[test]
    fn partial_tokens_lead_to_mfa() {
        assert!(matches!(after_login(token("partial")), AfterLogin::Mfa(_)));
        assert!(matches!(
            after_login(token("identity")),
            AfterLogin::Done(_)
        ));
    }

    #[test]
    fn signed_in_operators_know_their_subject_and_grants() {
        let operator = Operator::signed_in(
            &token("identity"),
            OwnCapabilities {
                subject: "ada".into(),
                capabilities: vec!["konklav:keys:manage".into()],
            },
        );
        assert_eq!(operator.subject(), Some("ada"));
        assert!(operator.can_refresh());
        assert!(operator.grants.allows(crate::grants::Capability::Keys));
    }
}
