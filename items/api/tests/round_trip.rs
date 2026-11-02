//! Every transport type reads back what it writes.

use konklav_api::{
    AssignmentTarget, CreateCredential, CreatedCredential, ErrorCode, ErrorResponse,
    MembershipDetail, RevokeSessions, RevokedKey, RevokedSessions, RotatedSlot, SessionPage,
    SigningKey, SubjectDetail, SubjectPage, TenantPage, Written,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

fn round_trips<T: Serialize + DeserializeOwned>(value: &Value) {
    let typed: T = serde_json::from_value(value.clone()).expect("deserializes");
    assert_eq!(&serde_json::to_value(&typed).expect("serializes"), value);
}

fn tenant(id: &str, parent: Option<&str>) -> Value {
    json!({
        "id": id,
        "parent_id": parent,
        "state": "active",
        "facts": {"plan": "pro"},
        "created_at": "2026-11-02T10:00:00Z",
        "updated_at": "2026-11-02T10:00:00Z",
    })
}

// r[verify item.api.both-directions]
#[test]
fn written_tenants_round_trip_with_and_without_a_cursor() {
    let id = "0195e0a0-0000-7000-8000-000000000001";
    let mut written = tenant(id, None);
    written["cursor"] = json!(42);
    round_trips::<Written<konklav_api::Tenant>>(&written);
    round_trips::<Written<konklav_api::Tenant>>(&tenant(id, None));
}

#[test]
fn tenant_pages_round_trip() {
    let id = "0195e0a0-0000-7000-8000-000000000001";
    let child = "0195e0a0-0000-7000-8000-000000000002";
    round_trips::<TenantPage>(&json!({
        "tenants": [tenant(id, None), tenant(child, Some(id))],
        "next": child,
    }));
}

#[test]
fn membership_details_round_trip_with_tagged_targets() {
    let membership = "0195e0a0-0000-7000-8000-000000000003";
    round_trips::<MembershipDetail>(&json!({
        "id": membership,
        "subject_id": "0195e0a0-0000-7000-8000-000000000004",
        "tenant_id": "0195e0a0-0000-7000-8000-000000000001",
        "state": "ended",
        "facts": {},
        "managed_by": null,
        "created_at": "2026-11-02T10:00:00Z",
        "updated_at": "2026-11-02T11:00:00Z",
        "assignments": [{
            "id": "0195e0a0-0000-7000-8000-000000000005",
            "role_id": "0195e0a0-0000-7000-8000-000000000006",
            "target": {"type": "membership", "id": membership},
            "scope": {"kind": "project", "id": "p1"},
            "managed_by": "okta",
            "created_at": "2026-11-02T10:30:00Z",
        }],
    }));
    let target: AssignmentTarget =
        serde_json::from_value(json!({"type": "membership", "id": membership})).unwrap();
    assert!(matches!(target, AssignmentTarget::Membership(_)));
}

#[test]
fn error_responses_round_trip_and_map_to_statuses() {
    round_trips::<ErrorResponse>(&json!({
        "error": {"code": "RATE_LIMITED", "message": "slow down"},
    }));
    assert_eq!(
        ErrorCode::RateLimited.status(),
        http::StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        ErrorCode::SessionEnded.status(),
        http::StatusCode::UNAUTHORIZED
    );
}

const SUBJECT: &str = "0195e0a0-0000-7000-8000-000000000004";
const CREDENTIAL: &str = "0195e0a0-0000-7000-8000-000000000007";

fn subject() -> Value {
    json!({
        "id": SUBJECT,
        "kind": "service",
        "state": "active",
        "created_at": "2026-11-02T10:00:00Z",
    })
}

fn credential(kind: &str) -> Value {
    json!({
        "id": CREDENTIAL,
        "subject_id": SUBJECT,
        "kind": kind,
        "identifier": CREDENTIAL,
        "mfa_factors_required": 0,
        "replaces": null,
        "created_at": "2026-11-02T10:00:00Z",
        "revoked_at": null,
        "revoked_reason": null,
        "break_glass": false,
        "session_flags": [],
    })
}

fn secret_key() -> Value {
    let mut credential = credential("secret_key");
    credential["slots"] = json!({
        "a": {"created_at": "2026-11-02T10:00:00Z", "expires_at": null},
        "b": {"created_at": "2026-11-02T10:00:00Z", "expires_at": "2027-11-02T10:00:00Z"},
    });
    credential
}

#[test]
fn subject_details_round_trip_with_flattened_subjects_and_omitted_credential_parts() {
    let mut passkey = credential("public_key");
    passkey["passkey"] = json!({"label": "Laptop", "last_used_at": null});
    let mut detail = subject();
    detail["credentials"] = json!([credential("password"), secret_key(), passkey]);
    round_trips::<SubjectDetail>(&detail);
    round_trips::<SubjectPage>(&json!({"subjects": [subject()], "next": null}));
    let mut written = subject();
    written["cursor"] = json!(7);
    round_trips::<Written<konklav_api::Subject>>(&written);
}

#[test]
fn credential_creations_round_trip_tagged_by_kind() {
    round_trips::<CreateCredential>(&json!({
        "kind": "password",
        "id": null,
        "identifier": "ada@example.com",
        "password": "correct horse",
        "password_hash": null,
        "mfa_factors_required": 1,
    }));
    round_trips::<CreateCredential>(&json!({
        "kind": "secret_key",
        "id": CREDENTIAL,
        "expires_at": "2027-11-02T10:00:00Z",
    }));
    round_trips::<CreateCredential>(&json!({
        "kind": "phone_otp", "id": null, "identifier": "+46700000000",
    }));
    round_trips::<CreateCredential>(&json!({
        "kind": "federated", "id": null, "provider": "okta", "subject": "workload",
    }));
    let defaulted: CreateCredential = serde_json::from_value(json!({
        "kind": "password", "identifier": "ada@example.com", "password": "correct horse",
    }))
    .unwrap();
    assert!(matches!(
        defaulted,
        CreateCredential::Password {
            mfa_factors_required: 0,
            ..
        }
    ));
}

#[test]
fn secrets_round_trip_and_are_omitted_when_absent() {
    round_trips::<CreatedCredential>(&json!({
        "credential": secret_key(),
        "secret_keys": {"a": format!("{CREDENTIAL}.a"), "b": format!("{CREDENTIAL}.b")},
    }));
    round_trips::<CreatedCredential>(&json!({"credential": credential("email_link")}));
    round_trips::<RotatedSlot>(&json!({
        "credential": secret_key(),
        "slot": "b",
        "secret_key": format!("{CREDENTIAL}.b"),
    }));
}

#[test]
fn sessions_round_trip() {
    let session = "0195e0a0-0000-7000-8000-000000000008";
    round_trips::<SessionPage>(&json!({
        "sessions": [{
            "id": session,
            "subject_id": SUBJECT,
            "credential_id": CREDENTIAL,
            "tenant_id": null,
            "membership_id": null,
            "stage": "identity",
            "client_kind": "browser",
            "amr": ["pwd"],
            "auth_time": "2026-11-02T10:00:00Z",
            "flags": [],
            "impersonator_subject_id": null,
            "mfa_factors": [],
            "parent_session_id": null,
            "oidc_client_id": "app",
            "oidc_scopes": ["openid"],
            "oidc_claims": {"userinfo": ["email"], "id_token": []},
            "identity_claims": {"email": {"email": "ada@example.com"}},
            "version": 1,
            "created_at": "2026-11-02T10:00:00Z",
            "updated_at": "2026-11-02T10:00:00Z",
            "expires_at": "2026-11-03T10:00:00Z",
            "revoked_at": null,
            "revoked_reason": null,
        }],
        "next": session,
    }));
}

#[test]
fn session_revocations_round_trip_with_a_flattened_filter() {
    round_trips::<RevokeSessions>(&json!({
        "session": null,
        "subject": SUBJECT,
        "credential": null,
        "tenant": null,
        "membership": null,
        "keep": "0195e0a0-0000-7000-8000-000000000008",
        "reason": null,
    }));
    let sparse: RevokeSessions = serde_json::from_value(json!({"subject": SUBJECT})).unwrap();
    assert_eq!(
        sparse.filter.subject.map(|id| id.to_string()).as_deref(),
        Some(SUBJECT)
    );
    assert!(sparse.keep.is_none() && sparse.filter.tenant.is_none());
    round_trips::<Written<RevokedSessions>>(&json!({
        "revoked": ["0195e0a0-0000-7000-8000-000000000008"],
        "cursor": 9,
    }));
}

#[test]
fn signing_keys_round_trip() {
    round_trips::<Vec<SigningKey>>(&json!([{
        "kid": "k1",
        "algorithm": "EdDSA",
        "published_at": "2026-11-02T10:00:00Z",
        "activated_at": "2026-11-02T10:00:00Z",
        "retired_at": null,
        "revoked_at": null,
    }]));
    round_trips::<RevokedKey>(&json!({"kid": "k1", "revoked": true}));
}
