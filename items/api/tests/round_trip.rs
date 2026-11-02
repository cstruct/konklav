//! Every transport type reads back what it writes.

use konklav_api::{
    AssignRole, AssignmentTarget, CatalogDocument, CreateCredential, CreatedCredential,
    DecisionExplanation, Deleted, Entitlements, ErrorCode, ErrorResponse, ExplainDecision,
    Explanation, MembershipDetail, PutRole, PutTemplate, Reason, RevokeSessions, RevokedKey,
    RevokedSessions, Role, RotatedSlot, SessionPage, SigningKey, SubjectDetail, SubjectPage,
    Template, TenantPage, Written,
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

/// The catalog of the server's authorization tests, as `GET /v1/catalog`
/// returns it: with every default written out.
fn catalog() -> Value {
    json!({
        "actions": [
            {"name": "project:read", "description": ""},
            {"name": "document:read", "description": "Read documents"},
        ],
        "groups": [
            {"name": "tenant:all", "description": "", "all_except_prefixes": ["sys:"]},
            {"name": "readers", "description": "", "actions": ["document:read", "project:read"]},
        ],
        "scope_kinds": [
            {"name": "project", "description": ""},
            {"name": "document", "description": "", "registered": true},
        ],
        "facts": [
            {"key": "tenant_type", "target": "tenant", "type": "string", "portable": true, "description": ""},
            {"key": "period", "target": "membership", "type": "date_range", "portable": false, "description": ""},
        ],
        "session_flags": [
            {"name": "personal_only", "kind": "restrictive", "requestable": true, "description": ""},
            {"name": "device_bound", "kind": "assertive", "requestable": false, "description": ""},
        ],
    })
}

#[test]
fn catalogs_round_trip_with_flattened_groups() {
    round_trips::<CatalogDocument>(&catalog());
    let mut written = catalog();
    written["cursor"] = json!(3);
    round_trips::<Written<CatalogDocument>>(&written);
    let sparse: CatalogDocument = serde_json::from_value(json!({
        "actions": [{"name": "project:read"}],
        "groups": [{"name": "sys:all", "all_except_prefixes": []}],
    }))
    .unwrap();
    assert!(sparse.scope_kinds.is_empty() && sparse.actions[0].description.is_empty());
}

fn policies() -> Value {
    json!([
        {"action": "project:read", "effect": "allow", "scope_bound": false},
        {"action": "document:read", "effect": "deny", "scope_bound": true},
    ])
}

#[test]
fn roles_and_templates_round_trip_with_their_policies() {
    round_trips::<Written<Role>>(&json!({
        "id": "0195e0a0-0000-7000-8000-000000000009",
        "tenant_id": "0195e0a0-0000-7000-8000-000000000001",
        "key": "editor",
        "template": "reader",
        "priority": 5,
        "metadata": {"label": "Editor"},
        "policies": policies(),
        "builtin": false,
        "created_at": "2026-11-02T10:00:00Z",
        "updated_at": "2026-11-02T10:00:00Z",
        "cursor": 4,
    }));
    round_trips::<Template>(&json!({
        "id": "0195e0a0-0000-7000-8000-00000000000a",
        "key": "reader",
        "description": "Reads",
        "metadata": {},
        "policies": policies(),
        "created_at": "2026-11-02T10:00:00Z",
        "updated_at": "2026-11-02T10:00:00Z",
    }));
    round_trips::<PutRole>(&json!({
        "template": null,
        "priority": 0,
        "metadata": {},
        "policies": policies(),
    }));
    let sparse: PutRole = serde_json::from_value(json!({"template": "reader"})).unwrap();
    assert_eq!(sparse.metadata, json!({}));
    let sparse: PutTemplate = serde_json::from_value(json!({"policies": [
        {"action": "document:read", "effect": "allow"},
    ]}))
    .unwrap();
    assert!(!sparse.policies[0].scope_bound && sparse.metadata == json!({}));
    round_trips::<Written<Deleted>>(&json!({"deleted": true, "cursor": 5}));
}

#[test]
fn assignments_round_trip_with_optional_scopes() {
    round_trips::<AssignRole>(&json!({"role": "editor", "scope": {"kind": "project", "id": "p1"}}));
    round_trips::<AssignRole>(&json!({"role": "admin", "scope": null}));
}

#[test]
fn entitlements_round_trip_with_scopes_as_a_list() {
    round_trips::<Entitlements>(&json!({
        "global": [],
        "tenant": ["project:read"],
        "scoped": [{"kind": "project", "id": "p1", "actions": ["document:read"]}],
        "shared": [{
            "share": "0195e0a0-0000-7000-8000-00000000000b",
            "owner_tenant": "0195e0a0-0000-7000-8000-00000000000c",
            "kind": "project",
            "id": "q-3",
            "actions": ["document:read"],
            "attributes": {"watermark": true},
            "valid_until": 1_800_000_000,
        }],
    }));
    round_trips::<Entitlements>(&json!({"global": [], "tenant": [], "scoped": []}));
}

fn contribution(effect: &str, priority: i32) -> Value {
    json!({
        "assignment": "editor (0195e0a0-0000-7000-8000-000000000005)",
        "level": "project/p1",
        "policy": "document:*",
        "effect": effect,
        "priority": priority,
        "from_template": false,
    })
}

#[test]
fn explanations_round_trip() {
    round_trips::<Explanation>(&json!({
        "action": "document:write",
        "contributions": [contribution("allow", 0)],
        "granted_at": ["project/p1"],
    }));
    round_trips::<ExplainDecision>(&json!({
        "tenant": "root",
        "session": null,
        "requirements": {
            "token_kinds": ["identity", "tenant"],
            "scopes": [{"kind": "project", "id": "p1", "actions": ["document:write"]}],
            "step_up": {"min_methods": 2},
        },
        "at": "2026-11-02T10:00:00Z",
    }));
    let sparse: ExplainDecision = serde_json::from_value(json!({})).unwrap();
    assert_eq!(sparse, ExplainDecision::default());
}

#[test]
fn decision_explanations_round_trip_with_tagged_decisions_and_reasons() {
    round_trips::<DecisionExplanation>(&json!({
        "decision": {"decision": "deny", "reason": {"missing_actions": {"actions": ["document:write"]}}},
        "allowed": false,
        "checks": [
            {"check": "subject_active", "passed": true, "message": "The subject is active."},
        ],
        "actions": [{
            "action": "document:write",
            "level": "project/p1",
            "granted": false,
            "message": "Denied: …",
            "reason": {
                "kind": "denied",
                "by": contribution("deny", 5),
                "overrides": [contribution("allow", 0)],
            },
            "contributions": [contribution("deny", 5), contribution("allow", 0)],
        }],
    }));
    round_trips::<DecisionExplanation>(&json!({
        "decision": {"decision": "step_up", "requirement": {"max_age_seconds": 300}},
        "allowed": false,
        "checks": [],
        "actions": [],
    }));
    round_trips::<DecisionExplanation>(&json!({
        "decision": {"decision": "deny", "reason": "no_tenant"},
        "allowed": false,
        "checks": [],
        "actions": [],
    }));
    let share = "0195e0a0-0000-7000-8000-00000000000b";
    round_trips::<Reason>(&json!({
        "kind": "allowed_by_share",
        "share": share,
        "recipient": "tenant",
        "held": {"kind": "allowed", "by": contribution("allow", 0), "ineffective": []},
    }));
    round_trips::<Reason>(&json!({
        "kind": "share_not_valid",
        "share": share,
        "valid_from": null,
        "valid_until": 1_800_000_000,
    }));
}
