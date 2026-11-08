//! Every transport type reads back what it writes.

use konklav_api::{
    AssignRole, AssignmentTarget, Batch, BatchResults, CatalogDocument, CreateCredential,
    CreateInvite, CreatedCredential, CreatedInvite, DecisionExplanation, Deleted, Entitlements,
    ErrorCode, ErrorResponse, ExplainDecision, Explanation, IdTokenAlgorithm, ImportCredentials,
    ImportFactors, ImportSessions, ImportSubjects, Imported, ImportedCredentialMaterial, Invite,
    InvitePage, MembershipDetail, OfferShare, OidcClient, OidcClientDefinition, OidcClientSecret,
    PutRole, PutTemplate, Reason, RecordRegisteredScope, RegisteredScope, RegisteredScopeBatch,
    RegisteredScopeChanges, RevokeSessions, RevokeShare, RevokedKey, RevokedSessions, Role,
    RotatedSlot, SessionPage, Share, ShareList, ShareTerms, SigningKey, SlotExpiry, SubjectDetail,
    SubjectPage, Template, TenantPage, Written,
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
        "metadata": {"billing_id": "b-1"},
        "metadata_etag": "0123456789abcdef0123456789abcdef",
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
        "metadata": {},
        "metadata_etag": "0123456789abcdef0123456789abcdef",
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
    assert_eq!(
        ErrorCode::PreconditionFailed.status(),
        http::StatusCode::PRECONDITION_FAILED
    );
    round_trips::<ErrorResponse>(&json!({
        "error": {"code": "METADATA_TOO_LARGE", "message": "too large"},
    }));
}

const SUBJECT: &str = "0195e0a0-0000-7000-8000-000000000004";
const CREDENTIAL: &str = "0195e0a0-0000-7000-8000-000000000007";

fn subject() -> Value {
    json!({
        "id": SUBJECT,
        "kind": "service",
        "state": "active",
        "metadata": {"locale": "sv-SE", "tags": ["beta"]},
        "metadata_etag": "0123456789abcdef0123456789abcdef",
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
        "metadata": {"name": "CI key"},
        "metadata_etag": "0123456789abcdef0123456789abcdef",
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
    detail["mfa_factors"] = json!([
        {"id": CREDENTIAL, "kind": "totp", "active": true, "created_at": "2026-11-02T10:00:00Z"},
        {
            "id": CREDENTIAL,
            "kind": "email_code",
            "active": false,
            "email": "ada@example.com",
            "created_at": "2026-11-02T10:00:00Z",
        },
    ]);
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
        "metadata": {"device": "laptop"},
    }));
    round_trips::<CreateCredential>(&json!({
        "kind": "secret_key",
        "id": CREDENTIAL,
        "expires_at": "2027-11-02T10:00:00Z",
        "metadata": {"name": "Nightly sync", "rotate_every_days": 90},
    }));
    round_trips::<CreateCredential>(&json!({
        "kind": "phone_otp", "id": null, "identifier": "+46700000000", "metadata": {},
    }));
    round_trips::<CreateCredential>(&json!({
        "kind": "federated", "id": null, "provider": "okta", "subject": "workload",
        "metadata": {},
    }));
    let defaulted: CreateCredential = serde_json::from_value(json!({
        "kind": "password", "identifier": "ada@example.com", "password": "correct horse",
    }))
    .unwrap();
    assert!(matches!(
        defaulted,
        CreateCredential::Password {
            mfa_factors_required: 0,
            ref metadata,
            ..
        } if *metadata == json!({})
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
    round_trips::<SlotExpiry>(&json!({"expires_at": "2026-12-01T00:00:00Z"}));
    round_trips::<SlotExpiry>(&json!({"expires_at": null}));
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
        "metadata_etag": "0123456789abcdef0123456789abcdef",
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
        "metadata_etag": "0123456789abcdef0123456789abcdef",
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

fn reads<T: DeserializeOwned>(value: Value) -> T {
    serde_json::from_value(value).expect("deserializes")
}

fn share_terms() -> Value {
    json!({
        "owner": "0195e0a0-0000-7000-8000-000000000001",
        "scope": {"kind": "project", "id": "p-17"},
        "recipient": "0195e0a0-0000-7000-8000-000000000002",
        "recipient_scope": null,
        "actions": ["document:read"],
        "attributes": {"data_range": {"from": "2026-01-01", "until": "2026-06-30"}},
        "valid_from": null,
        "valid_until": "2027-01-01T00:00:00Z",
    })
}

fn share(state: &str) -> Value {
    let mut share = share_terms();
    let fields = json!({
        "id": "0195e0a0-0000-7000-8000-00000000000b",
        "state": state,
        "accepted_at": "2026-11-02T11:00:00Z",
        "revoked_at": "2026-11-02T12:00:00Z",
        "revoked_by": "recipient",
        "metadata": {"label": "Shared plan"},
        "metadata_etag": "0123456789abcdef0123456789abcdef",
        "created_at": "2026-11-02T10:00:00Z",
        "updated_at": "2026-11-02T12:00:00Z",
    });
    share
        .as_object_mut()
        .unwrap()
        .extend(fields.as_object().unwrap().clone());
    share
}

#[test]
fn shares_round_trip_with_flattened_terms() {
    round_trips::<ShareTerms>(&share_terms());
    let minimal: ShareTerms = reads(json!({
        "owner": "0195e0a0-0000-7000-8000-000000000001",
        "scope": {"kind": "project", "id": "p-17"},
        "recipient": "0195e0a0-0000-7000-8000-000000000002",
        "actions": ["document:read"],
    }));
    assert_eq!(minimal.attributes, serde_json::Map::new());
    assert_eq!(minimal.recipient_scope, None);
    let mut written = share("revoked");
    written["cursor"] = json!(7);
    round_trips::<Written<Share>>(&written);
    round_trips::<ShareList>(&json!({"shares": [share("offered"), share("accepted")]}));
    round_trips::<RevokeShare>(&json!({"by": "owner"}));
    let mut offer = share_terms();
    offer["metadata"] = json!({"label": "Shared plan"});
    round_trips::<OfferShare>(&offer);
    let bare: OfferShare = reads(share_terms());
    assert_eq!(bare.metadata, json!({}));
}

fn registered_scope(state: &str) -> Value {
    json!({
        "kind": "document",
        "id": "d-1",
        "tenant": "0195e0a0-0000-7000-8000-000000000001",
        "containers": [{"kind": "project", "id": "p-1"}],
        "state": state,
        "created_at": "2026-11-02T10:00:00Z",
        "updated_at": "2026-11-02T10:00:00Z",
    })
}

#[test]
fn registered_scopes_round_trip_with_tagged_changes() {
    let tenant = "0195e0a0-0000-7000-8000-000000000001";
    round_trips::<RecordRegisteredScope>(&json!({
        "tenant": tenant,
        "containers": [{"kind": "project", "id": "p-1"}],
    }));
    let bare: RecordRegisteredScope = reads(json!({"tenant": tenant}));
    assert_eq!(bare.containers, Vec::new());
    round_trips::<RegisteredScopeChanges>(&json!({"changes": [
        {"op": "record", "kind": "document", "id": "d-1", "tenant": tenant,
         "containers": [{"kind": "project", "id": "p-1"}]},
        {"op": "remove", "kind": "document", "id": "d-2"},
    ]}));
    round_trips::<Written<RegisteredScope>>(&registered_scope("active"));
    round_trips::<Written<RegisteredScopeBatch>>(&json!({
        "scopes": [registered_scope("active"), null, registered_scope("removed")],
        "cursor": 12,
    }));
    round_trips::<Written<RegisteredScopeBatch>>(&json!({"scopes": []}));
}

#[test]
fn invites_round_trip() {
    round_trips::<CreateInvite>(&json!({
        "email": "ada@example.com",
        "tenant": "root",
        "roles": ["member"],
        "facts": {"department": "ops"},
        "membership": "0195e0a0-0000-7000-8000-000000000003",
        "expires_in_hours": 24,
        "metadata": {"tenant_id": "t-1", "invited_by": "u-9"},
    }));
    let minimal: CreateInvite = reads(json!({"email": "ada@example.com"}));
    assert_eq!((minimal.expires_in_hours, minimal.facts), (72, json!({})));
    round_trips::<Written<CreatedInvite>>(&json!({
        "invite_id": "0195e0a0-0000-7000-8000-00000000000c",
        "expires_at": "2026-11-05T10:00:00Z",
        "cursor": 9,
    }));
    let invite = json!({
        "id": "0195e0a0-0000-7000-8000-00000000000c",
        "email": "ada@example.com",
        "tenant": "root",
        "roles": ["reader"],
        "membership": null,
        "state": "revoked",
        "expires_at": "2026-11-05T10:00:00Z",
        "consumed_at": "2026-11-04T10:00:00Z",
        "metadata": {"tenant_id": "t-1"},
        "metadata_etag": "0123456789abcdef0123456789abcdef",
    });
    round_trips::<Invite>(&invite);
    round_trips::<InvitePage>(&json!({"invites": [invite], "next": null}));
}

fn client_definition() -> Value {
    json!({
        "kind": "confidential",
        "redirect_uris": ["https://console.example.com/callback"],
        "scopes": ["openid", "email", "phone", "groups", "tenant", "profile"],
        "audience": "console",
        "visible_groups": ["ops-*"],
        "login_url": null,
        "id_token_alg": "RS256",
        "refresh": true,
        "service_subject": "0195e0a0-0000-7000-8000-000000000004",
        "jwks": {"keys": []},
        "post_logout_redirect_uris": [],
        "backchannel_logout_uri": "https://console.example.com/logout",
        "require_pkce": false,
        "require_dpop": true,
        "metadata": {"owner": "web team"},
    })
}

#[test]
fn oidc_clients_round_trip_with_flattened_definitions() {
    round_trips::<OidcClientDefinition>(&client_definition());
    let minimal: OidcClientDefinition = reads(json!({
        "kind": "public",
        "redirect_uris": ["https://spa.example.com/callback"],
        "audience": "spa",
    }));
    assert_eq!(minimal.scopes, ["openid"]);
    assert_eq!(minimal.id_token_alg, IdTokenAlgorithm::Es256);
    assert!(minimal.refresh && minimal.require_pkce && !minimal.require_dpop);
    let mut client = client_definition();
    let fields = json!({
        "id": "console",
        "has_secret": true,
        "metadata_etag": "0123456789abcdef0123456789abcdef",
        "disabled_at": null,
        "created_at": "2026-11-02T10:00:00Z",
        "updated_at": "2026-11-02T10:00:00Z",
    });
    client
        .as_object_mut()
        .unwrap()
        .extend(fields.as_object().unwrap().clone());
    round_trips::<OidcClient>(&client);
    round_trips::<Vec<OidcClient>>(&json!([client]));
    round_trips::<OidcClientSecret>(&json!({"client_secret": "s3cr3t"}));
}

#[test]
fn imports_round_trip_with_tagged_material() {
    let subject = "0195e0a0-0000-7000-8000-000000000001";
    let credential = "0195e0a0-0000-7000-8000-000000000002";
    round_trips::<ImportSubjects>(&json!({"subjects": [
        {"id": subject, "kind": "service", "state": "active", "metadata": {"team": "ops"}},
        {"id": "0195e0a0-0000-7000-8000-000000000003", "kind": "human", "state": "disabled",
         "metadata": {}},
    ]}));
    let slot = json!({"hash": "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA",
                      "created_at": "2026-01-01T00:00:00Z", "expires_at": null});
    round_trips::<ImportCredentials>(&json!({"credentials": [
        {"id": credential, "subject": subject, "identifier": credential,
         "mfa_factors_required": 0, "session_flags": [], "metadata": {"name": "legacy"},
         "kind": "secret_key", "a": slot, "b": slot},
        {"id": "0195e0a0-0000-7000-8000-000000000004", "subject": subject,
         "identifier": "legacy@example.com", "mfa_factors_required": 1,
         "session_flags": ["personal_only"], "metadata": {}, "kind": "password",
         "password_hash": "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA"},
        {"id": "0195e0a0-0000-7000-8000-000000000005", "subject": subject,
         "identifier": "+46700000000", "mfa_factors_required": 0, "session_flags": [],
         "metadata": {}, "kind": "phone_otp"},
    ]}));
    let from_a_test: ImportCredentials = reads(json!({"credentials": [{
        "id": credential, "subject": subject, "identifier": "x@y",
        "kind": "password", "password_hash": "plaintext",
    }]}));
    assert!(matches!(
        from_a_test.credentials[0].material,
        ImportedCredentialMaterial::Password { .. }
    ));
    round_trips::<ImportFactors>(&json!({"factors": [
        {"id": "0195e0a0-0000-7000-8000-000000000006", "subject": subject, "active": true,
         "kind": "totp", "seed_base32": "JBSWY3DPEHPK3PXP"},
        {"id": "0195e0a0-0000-7000-8000-000000000007", "subject": subject, "active": false,
         "kind": "email_code", "email": "legacy@example.com"},
    ]}));
    round_trips::<ImportSessions>(&json!({"sessions": [{
        "id": "0195e0a0-0000-7000-8000-000000000008",
        "subject": subject,
        "credential": credential,
        "tenant": null,
        "membership": null,
        "stage": "identity",
        "client_kind": "browser",
        "amr": ["pwd"],
        "flags": [],
        "impersonator": null,
        "auth_time": "2026-11-02T10:00:00Z",
        "version": 3,
        "refresh_hash": "00".repeat(32),
        "expires_at": "2026-12-02T10:00:00Z",
        "revoked_at": null,
    }]}));
    round_trips::<Imported>(&json!({"imported": 2, "skipped": 1, "updated": 0}));
}

#[test]
fn batches_round_trip() {
    round_trips::<Batch>(&json!({"operations": [
        {"method": "PUT", "path": "/subjects/0195e0a0-0000-7000-8000-000000000001", "body": {"kind": "human"}},
        {"method": "DELETE", "path": "/assignments/0195e0a0-0000-7000-8000-000000000002"},
        {"method": "PATCH", "path": "/invites/0195e0a0-0000-7000-8000-000000000003/metadata",
         "body": {"tenant_id": "t-2"}, "if_match": "0123456789abcdef0123456789abcdef"},
    ]}));
    assert!(
        serde_json::from_value::<Batch>(
            json!({"operations": [{"method": "GET", "path": "/subjects"}]})
        )
        .is_err()
    );
    round_trips::<Written<BatchResults>>(&json!({
        "results": [{"status": 201, "body": {"id": "x"}}],
        "cursor": 9,
    }));
    round_trips::<ErrorResponse>(
        &json!({"error": {"code": "NOT_FOUND", "message": "role not found", "operation": 3}}),
    );
    round_trips::<ErrorResponse>(
        &json!({"error": {"code": "NOT_FOUND", "message": "role not found"}}),
    );
}
