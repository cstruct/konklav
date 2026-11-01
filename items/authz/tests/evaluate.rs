use std::collections::{BTreeMap, BTreeSet};

use konklav_authz::{
    Decision, DenyReason, Entitlements, Requirements, Scope, ScopeRequirement, StepUp, evaluate,
};
use konklav_core::{SessionId, SubjectId, TenantId};
use konklav_token::{AccessClaims, TokenKind};

const NOW: i64 = 10_000;

fn claims(kind: TokenKind, flags: &[&str], amr: &[&str], auth_age: i64) -> AccessClaims {
    AccessClaims {
        iss: "i".into(),
        aud: "a".into(),
        sub: SubjectId::new_v7(),
        jti: "j".into(),
        iat: NOW,
        exp: NOW + 900,
        knd: kind,
        sid: SessionId::new_v7(),
        cid: None,
        sv: 1,
        amr: amr.iter().map(|m| (*m).to_owned()).collect(),
        auth_time: NOW - auth_age,
        tid: (kind == TokenKind::Tenant).then(TenantId::new_v7),
        mid: None,
        sfl: flags.iter().map(|f| (*f).to_owned()).collect(),
        fct: BTreeMap::new(),
        act: None,
    }
}

fn tenant_token() -> AccessClaims {
    claims(TokenKind::Tenant, &[], &["pwd"], 0)
}

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|i| (*i).to_owned()).collect()
}

fn entitlements() -> Entitlements {
    Entitlements {
        global: set(&["me"]),
        tenant: set(&["role:list"]),
        scoped: BTreeMap::from([(
            Scope {
                kind: "project".into(),
                id: "p1".into(),
            },
            set(&["document:read"]),
        )]),
    }
}

fn restrictive() -> BTreeSet<String> {
    set(&["personal_only"])
}

fn decide(requirements: &Requirements, claims: &AccessClaims) -> Decision {
    evaluate(requirements, claims, &restrictive(), &entitlements(), NOW)
}

fn denied(reason: DenyReason) -> Decision {
    Decision::Deny { reason }
}

// r[verify relying.decision.requirements]
#[test]
fn checks_actions_at_each_level() {
    let token = tenant_token();
    let scope = |actions: &[&str]| ScopeRequirement {
        kind: "project".into(),
        id: "p1".into(),
        actions: set(actions),
    };
    let allowed = Requirements {
        global: set(&["me"]),
        tenant: set(&["role:list", "me"]),
        scopes: vec![scope(&["document:read", "role:list", "me"])],
        ..Default::default()
    };
    assert_eq!(decide(&allowed, &token), Decision::Allow);

    let tenant_action_globally = Requirements {
        global: set(&["role:list"]),
        ..Default::default()
    };
    assert_eq!(
        decide(&tenant_action_globally, &token),
        denied(DenyReason::MissingActions {
            actions: set(&["role:list"])
        })
    );
    let scoped_action_tenant_wide = Requirements {
        tenant: set(&["document:read"]),
        ..Default::default()
    };
    assert!(matches!(
        decide(&scoped_action_tenant_wide, &token),
        Decision::Deny { .. }
    ));
    let other_scope = Requirements {
        scopes: vec![ScopeRequirement {
            kind: "project".into(),
            id: "p2".into(),
            actions: set(&["document:read"]),
        }],
        ..Default::default()
    };
    assert!(matches!(
        decide(&other_scope, &token),
        Decision::Deny { .. }
    ));
}

#[test]
fn accepts_only_tenant_tokens_unless_told_otherwise() {
    let identity = claims(TokenKind::Identity, &[], &["pwd"], 0);
    let global_only = Requirements {
        global: set(&["me"]),
        ..Default::default()
    };
    assert_eq!(
        decide(&global_only, &identity),
        denied(DenyReason::TokenKind)
    );
    let identity_ok = Requirements {
        token_kinds: Some(BTreeSet::from([TokenKind::Identity, TokenKind::Tenant])),
        ..global_only
    };
    assert_eq!(decide(&identity_ok, &identity), Decision::Allow);

    let needs_tenant = Requirements {
        token_kinds: Some(BTreeSet::from([TokenKind::Identity])),
        tenant: set(&["role:list"]),
        ..Default::default()
    };
    assert_eq!(
        decide(&needs_tenant, &identity),
        denied(DenyReason::NoTenant)
    );
}

// r[verify session.flags.restrictive]
#[test]
fn restrictive_flags_deny_unless_admitted() {
    let restricted = claims(TokenKind::Tenant, &["personal_only"], &["pwd"], 0);
    let plain = Requirements::default();
    assert_eq!(
        decide(&plain, &restricted),
        denied(DenyReason::RestrictedSession {
            flag: "personal_only".into()
        })
    );
    let admitting = Requirements {
        admit_flags: set(&["personal_only"]),
        ..Default::default()
    };
    assert_eq!(decide(&admitting, &restricted), Decision::Allow);
    // Flags the catalog doesn't declare restrictive never restrict.
    let assertive = claims(TokenKind::Tenant, &["device_bound"], &["pwd"], 0);
    assert_eq!(decide(&plain, &assertive), Decision::Allow);
}

// r[verify session.flags.assertive]
#[test]
fn assertive_flags_must_be_present_when_required() {
    let requiring = Requirements {
        require_flags: set(&["device_bound"]),
        ..Default::default()
    };
    assert_eq!(
        decide(&requiring, &tenant_token()),
        denied(DenyReason::MissingFlag {
            flag: "device_bound".into()
        })
    );
    let bound = claims(TokenKind::Tenant, &["device_bound"], &["pwd"], 0);
    assert_eq!(decide(&requiring, &bound), Decision::Allow);
}

// r[verify authn.step-up.demand]
#[test]
fn unmet_step_up_is_a_demand_not_a_denial() {
    let two_factors = StepUp {
        min_methods: Some(2),
        ..Default::default()
    };
    let requiring = Requirements {
        step_up: two_factors.clone(),
        ..Default::default()
    };
    assert_eq!(
        decide(&requiring, &tenant_token()),
        Decision::StepUp {
            requirement: two_factors.clone()
        }
    );
    assert_eq!(
        decide(
            &requiring,
            &claims(TokenKind::Tenant, &[], &["pwd", "otp"], 0)
        ),
        Decision::Allow
    );

    let only_otp_counts = StepUp {
        min_methods: Some(1),
        allowed_methods: Some(set(&["otp", "hwk"])),
        ..Default::default()
    };
    let requiring = Requirements {
        step_up: only_otp_counts,
        ..Default::default()
    };
    assert!(matches!(
        decide(&requiring, &tenant_token()),
        Decision::StepUp { .. }
    ));

    let recent = Requirements {
        step_up: StepUp {
            max_age_seconds: Some(300),
            ..Default::default()
        },
        ..Default::default()
    };
    assert_eq!(
        decide(&recent, &claims(TokenKind::Tenant, &[], &["pwd"], 299)),
        Decision::Allow
    );
    assert!(matches!(
        decide(&recent, &claims(TokenKind::Tenant, &[], &["pwd"], 301)),
        Decision::StepUp { .. }
    ));
}

#[test]
fn decisions_serialize_with_a_tag() {
    let json = serde_json::to_value(denied(DenyReason::NoTenant)).unwrap();
    assert_eq!(
        json,
        serde_json::json!({"decision": "deny", "reason": "no_tenant"})
    );
}
