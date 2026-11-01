//! Shares: what one tenant's shared scope grants a member of another, and
//! how decisions at shared scopes are made.

use std::collections::{BTreeMap, BTreeSet};

use konklav_authz::{
    Assignment, Catalog, Decision, DenyReason, Effect, Entitlements, Group, Level, Obligation,
    Policy, Requirements, Scope, ScopeRequirement, Share, compile, evaluate, shared,
};
use konklav_core::{SessionId, ShareId, SubjectId, TenantId};
use konklav_token::{AccessClaims, TokenKind};

const NOW: i64 = 10_000;

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|i| (*i).to_owned()).collect()
}

fn catalog() -> Catalog {
    Catalog {
        actions: set(&["document:read", "document:write", "document:delete"]),
        groups: BTreeMap::from([(
            "document:all".to_owned(),
            Group::Actions(set(&["document:read", "document:write", "document:delete"])),
        )]),
    }
}

fn project(id: &str) -> Scope {
    Scope {
        kind: "project".into(),
        id: id.into(),
    }
}

fn allow(action: &str, scope_bound: bool) -> Policy {
    Policy {
        action: action.into(),
        effect: Effect::Allow,
        scope_bound,
    }
}

fn assignment(level: Level, policies: Vec<Policy>) -> Assignment {
    Assignment {
        label: "role".into(),
        level,
        priority: 0,
        template_policies: vec![],
        role_policies: policies,
    }
}

fn share(owner: TenantId, recipient_scope: Option<Scope>, actions: &[&str]) -> Share {
    Share {
        id: ShareId::new_v7(),
        owner_tenant: owner,
        scope: project("p-17"),
        recipient_scope,
        actions: set(actions),
        attributes:
            serde_json::json!({"data_range": {"from": "2026-01-01", "until": "2026-06-30"}})
                .as_object()
                .cloned()
                .unwrap(),
        valid_from: None,
        valid_until: None,
    }
}

// r[verify authz.share.ceiling]
#[test]
fn members_get_only_shared_actions_they_hold_at_the_recipient() {
    let owner = TenantId::new_v7();
    // Tenant-wide `document:read`, and `document:write` only at q-3.
    let assignments = [
        assignment(Level::Tenant, vec![allow("document:read", false)]),
        assignment(
            Level::Scope(project("q-3")),
            vec![allow("document:write", true)],
        ),
    ];
    let compiled = compile(&catalog(), &assignments);

    let tenant_wide = share(owner, None, &["document:all"]);
    let granted = shared(&catalog(), &compiled, &[tenant_wide]);
    assert_eq!(granted.len(), 1);
    assert_eq!(
        granted[0].actions,
        set(&["document:read"]),
        "the group expands, then only what the member holds tenant-wide"
    );

    let at_project = share(owner, Some(project("q-3")), &["document:all"]);
    let granted = shared(&catalog(), &compiled, &[at_project]);
    assert_eq!(
        granted[0].actions,
        set(&["document:read", "document:write"]),
        "at a recipient scope, what the member holds there counts too"
    );

    let unheld = share(owner, None, &["document:delete"]);
    assert!(
        shared(&catalog(), &compiled, &[unheld]).is_empty(),
        "a share granting nothing is left out"
    );
}

fn token(tenant: TenantId) -> AccessClaims {
    AccessClaims {
        iss: "i".into(),
        aud: "a".into(),
        sub: SubjectId::new_v7(),
        jti: "j".into(),
        iat: NOW,
        exp: NOW + 900,
        knd: TokenKind::Tenant,
        sid: SessionId::new_v7(),
        cid: None,
        sv: 1,
        amr: vec!["pwd".into()],
        auth_time: NOW,
        tid: Some(tenant),
        mid: None,
        sfl: vec![],
        fct: BTreeMap::new(),
        act: None,
    }
}

fn at(owner: Option<TenantId>, id: &str, actions: &[&str]) -> Requirements {
    Requirements {
        scopes: vec![ScopeRequirement {
            tenant: owner,
            kind: "project".into(),
            id: id.into(),
            actions: set(actions),
        }],
        ..Default::default()
    }
}

// r[verify authz.share.requirements]
// r[verify authz.share.attributes]
#[test]
fn shared_scopes_are_decided_through_shares_with_obligations() {
    let owner = TenantId::new_v7();
    let recipient = TenantId::new_v7();
    let claims = token(recipient);
    let mut entitlements = compile(
        &catalog(),
        &[assignment(
            Level::Tenant,
            vec![allow("document:read", false)],
        )],
    );
    let the_share = share(owner, None, &["document:read"]);
    entitlements.shared = shared(&catalog(), &entitlements, std::slice::from_ref(&the_share));
    let decide = |requirements: &Requirements| {
        evaluate(requirements, &claims, &BTreeSet::new(), &entitlements, NOW)
    };

    assert_eq!(
        decide(&at(Some(owner), "p-17", &["document:read"])),
        Decision::Allow {
            obligations: vec![Obligation {
                share: the_share.id,
                tenant: owner,
                kind: "project".into(),
                id: "p-17".into(),
                attributes: the_share.attributes.clone(),
            }],
        }
    );
    assert_eq!(
        decide(&at(Some(owner), "p-17", &["document:write"])),
        Decision::Deny {
            reason: DenyReason::MissingActions {
                actions: set(&["document:write"])
            }
        },
        "only what the share allows"
    );
    assert!(
        matches!(
            decide(&at(Some(owner), "p-18", &["document:read"])),
            Decision::Deny { .. }
        ),
        "only the shared scope"
    );
    assert!(
        matches!(
            decide(&at(Some(TenantId::new_v7()), "p-17", &["document:read"])),
            Decision::Deny { .. }
        ),
        "only the owner's scope of that id"
    );
    // The recipient's own scope of the same id is decided as before: the
    // member's tenant-wide grant applies there, without obligations.
    assert_eq!(
        decide(&at(None, "p-17", &["document:read"])),
        Decision::allow()
    );
    assert_eq!(
        decide(&at(Some(recipient), "p-17", &["document:read"])),
        Decision::allow()
    );
}

// r[verify authz.share.validity]
#[test]
fn shares_grant_only_while_valid() {
    let owner = TenantId::new_v7();
    let claims = token(TenantId::new_v7());
    let base = compile(
        &catalog(),
        &[assignment(
            Level::Tenant,
            vec![allow("document:read", false)],
        )],
    );
    let requirements = at(Some(owner), "p-17", &["document:read"]);
    for (from, until, allowed) in [
        (Some(NOW - 10), Some(NOW + 10), true),
        (Some(NOW + 1), None, false),
        (None, Some(NOW), false),
        (Some(NOW), None, true),
    ] {
        let mut the_share = share(owner, None, &["document:read"]);
        the_share.valid_from = from;
        the_share.valid_until = until;
        let entitlements = Entitlements {
            shared: shared(&catalog(), &base, &[the_share]),
            ..base.clone()
        };
        let decision = evaluate(&requirements, &claims, &BTreeSet::new(), &entitlements, NOW);
        assert_eq!(
            matches!(decision, Decision::Allow { .. }),
            allowed,
            "{from:?}..{until:?}: {decision:?}"
        );
    }
}

#[test]
fn shared_entries_round_trip_and_allow_keeps_its_shape() {
    let owner = TenantId::new_v7();
    let base = compile(
        &catalog(),
        &[assignment(
            Level::Tenant,
            vec![allow("document:read", false)],
        )],
    );
    let entitlements = Entitlements {
        shared: shared(&catalog(), &base, &[share(owner, None, &["document:read"])]),
        ..base.clone()
    };
    let json = serde_json::to_value(&entitlements).unwrap();
    assert_eq!(json["shared"][0]["owner_tenant"], serde_json::json!(owner));
    assert_eq!(json["shared"][0]["kind"], "project");
    assert_eq!(
        serde_json::from_value::<Entitlements>(json).unwrap(),
        entitlements
    );
    assert!(
        serde_json::to_value(&base).unwrap().get("shared").is_none(),
        "no shares, no field"
    );
    assert_eq!(
        serde_json::to_value(Decision::allow()).unwrap(),
        serde_json::json!({"decision": "allow"})
    );
}
