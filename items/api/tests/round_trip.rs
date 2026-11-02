//! Every transport type reads back what it writes.

use konklav_api::{
    AssignmentTarget, ErrorCode, ErrorResponse, MembershipDetail, TenantPage, Written,
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
