//! Minting access tokens for sessions.

use std::collections::BTreeMap;

use chrono::Utc;
use conclave_store::Connection;
use conclave_store::catalog::{self, FactTarget};
use conclave_store::sessions::{Session, Stage};
use conclave_store::{memberships, signing_keys, tenants};
use conclave_token::{AccessClaims, Actor, TokenKind};
use serde::Serialize;

use crate::AuthContext;
use crate::error::{ApiError, ErrorCode};

#[derive(Debug, Serialize)]
pub struct IssuedToken {
    pub access_token: String,
    pub token_type: &'static str,
    pub token_kind: TokenKind,
    pub expires_in: i64,
    pub session_id: conclave_core::SessionId,
}

/// The portable facts of the session's tenant and membership.
// r[impl token.access.facts]
async fn portable_facts(
    conn: &mut Connection,
    session: &Session,
) -> Result<BTreeMap<String, serde_json::Value>, ApiError> {
    let (Some(tenant), Some(membership)) = (session.tenant_id, session.membership_id) else {
        return Ok(BTreeMap::new());
    };
    let document = catalog::load(conn).await?;
    let tenant = tenants::get(conn, tenant).await?;
    let membership = memberships::get(conn, membership).await?;
    let mut facts = catalog::portable_facts(&document, FactTarget::Tenant, &tenant.facts);
    facts.extend(catalog::portable_facts(
        &document,
        FactTarget::Membership,
        &membership.facts,
    ));
    Ok(facts)
}

/// Signs an access token for the session's current state.
///
/// Issuance stops while the configured signing key is revoked.
// r[impl token.access.ttl]
pub async fn access_token(
    conn: &mut Connection,
    auth: &AuthContext,
    session: &Session,
) -> Result<IssuedToken, ApiError> {
    let usable = signing_keys::list(conn)
        .await?
        .iter()
        .any(|key| key.kid == auth.signer.kid() && key.is_active());
    if !usable {
        return Err(ApiError::new(
            ErrorCode::SigningKeyUnavailable,
            "no signing key is available",
        ));
    }

    let now = Utc::now();
    // Never outlive the session.
    // r[impl session.expiry]
    let expires_at = (now + auth.access_ttl).min(session.expires_at);
    let token_kind = match session.stage {
        Stage::Partial => TokenKind::Partial,
        Stage::Identity => TokenKind::Identity,
        Stage::Tenant => TokenKind::Tenant,
    };
    let claims = AccessClaims {
        iss: auth.issuer.clone(),
        aud: auth.audience.clone(),
        sub: session.subject_id,
        jti: uuid::Uuid::now_v7().to_string(),
        iat: now.timestamp(),
        exp: expires_at.timestamp(),
        knd: token_kind,
        sid: session.id,
        sv: session.version,
        amr: session.amr.clone(),
        auth_time: session.auth_time.timestamp(),
        tid: session.tenant_id,
        mid: session.membership_id,
        sfl: session.flags.clone(),
        fct: portable_facts(conn, session).await?,
        act: session
            .impersonator_subject_id
            .map(|sub| Actor { sub, tid: None }),
    };
    Ok(IssuedToken {
        access_token: auth.signer.sign(&claims),
        token_type: "Bearer",
        token_kind,
        expires_in: (expires_at - now).num_seconds(),
        session_id: session.id,
    })
}
