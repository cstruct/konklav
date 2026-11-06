//! Sessions.

use konklav_api as api;
use konklav_store::sessions::{ClientKind, Session, SessionFilter, Stage};

pub(crate) fn session(session: Session) -> api::Session {
    api::Session {
        id: session.id,
        subject_id: session.subject_id,
        credential_id: session.credential_id,
        tenant_id: session.tenant_id,
        membership_id: session.membership_id,
        stage: match session.stage {
            Stage::Partial => api::SessionStage::Partial,
            Stage::Identity => api::SessionStage::Identity,
            Stage::Tenant => api::SessionStage::Tenant,
        },
        client_kind: match session.client_kind {
            ClientKind::Browser => api::ClientKind::Browser,
            ClientKind::Native => api::ClientKind::Native,
        },
        amr: session.amr,
        auth_time: session.auth_time,
        flags: session.flags,
        impersonator_subject_id: session.impersonator_subject_id,
        mfa_factors: session.mfa_factors,
        parent_session_id: session.parent_session_id,
        oidc_client_id: session.oidc_client_id,
        oidc_scopes: session.oidc_scopes,
        oidc_claims: api::RequestedClaims {
            userinfo: session.oidc_claims.userinfo,
            id_token: session.oidc_claims.id_token,
        },
        identity_claims: session.identity_claims,
        dpop_jkt: session.dpop_jkt,
        version: session.version,
        created_at: session.created_at,
        updated_at: session.updated_at,
        expires_at: session.expires_at,
        revoked_at: session.revoked_at,
        revoked_reason: session.revoked_reason,
    }
}

pub(crate) fn session_filter(filter: &api::SessionFilter) -> SessionFilter {
    SessionFilter {
        session: filter.session,
        subject: filter.subject,
        credential: filter.credential,
        tenant: filter.tenant,
        membership: filter.membership,
    }
}
