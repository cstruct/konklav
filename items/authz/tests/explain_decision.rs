#![allow(clippy::too_many_lines)]

//! Decision explanations: why each required action is granted or not, and
//! that the explanation always agrees with the decision.

use std::collections::{BTreeMap, BTreeSet};

use konklav_authz::{
    Assignment, Catalog, Check, Confinements, Decision, DecisionExplanation, Effect, ExplainInput,
    Level, Policy, Reason, RegisteredScopes, Requirements, Scope, ScopeRequirement, SessionContext,
    Share, StepUp, explain_decision,
};
use konklav_core::{SessionId, ShareId, SubjectId, TenantId};
use konklav_token::{AccessClaims, TokenKind};

const NOW: i64 = 10_000;

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|i| (*i).to_owned()).collect()
}

fn catalog() -> Catalog {
    Catalog {
        actions: set(&["document:read", "document:write"]),
        groups: BTreeMap::new(),
        vouches: BTreeMap::new(),
    }
}

fn project(id: &str) -> Scope {
    Scope {
        kind: "project".into(),
        id: id.into(),
    }
}

fn role(label: &str, level: Level, priority: i32, policies: &[(&str, Effect, bool)]) -> Assignment {
    Assignment {
        label: label.into(),
        level,
        priority,
        template_policies: vec![],
        role_policies: policies
            .iter()
            .map(|(action, effect, scope_bound)| Policy {
                action: (*action).into(),
                effect: *effect,
                scope_bound: *scope_bound,
            })
            .collect(),
    }
}

fn at_scope(id: &str, action: &str) -> Requirements {
    Requirements {
        scopes: vec![ScopeRequirement {
            tenant: None,
            kind: "project".into(),
            id: id.into(),
            actions: set(&[action]),
        }],
        ..Default::default()
    }
}

fn explain(assignments: &[Assignment], requirements: &Requirements) -> DecisionExplanation {
    explain_decision(
        &ExplainInput {
            catalog: &catalog(),
            assignments,
            shares: &[],
            offered: &[],
            requirements,
            registered: &RegisteredScopes::default(),
            tenant: Some(TenantId::new_v7()),
            tenant_facts: &std::collections::BTreeMap::new(),
            session: None,
            route: None,
            now: NOW,
        },
        vec![],
    )
}

// r[verify authz.explain.decision]
#[test]
fn no_rule_means_nothing_grants_it() {
    let explained = explain(&[], &at_scope("p1", "document:write"));
    assert!(!explained.allowed);
    assert_eq!(explained.actions[0].reason, Reason::NoRule);
    assert_eq!(
        explained.actions[0].message,
        "No policy grants `document:write`."
    );
}

// r[verify authz.explain.decision]
#[test]
fn an_allow_names_its_policy() {
    let assignments = [role(
        "editor (a1)",
        Level::Scope(project("p1")),
        0,
        &[("document:write", Effect::Allow, true)],
    )];
    let explained = explain(&assignments, &at_scope("p1", "document:write"));
    assert!(explained.allowed);
    let action = &explained.actions[0];
    assert!(matches!(&action.reason, Reason::Allowed { by, .. } if by.assignment == "editor (a1)"));
    assert_eq!(
        action.message,
        "Allowed: `editor (a1)` allows `document:write` at project/p1 (priority 0)."
    );

    // Elsewhere it isn't granted, and the explanation says where it is.
    let explained = explain(&assignments, &at_scope("p2", "document:write"));
    assert_eq!(
        explained.actions[0].reason,
        Reason::NotHere {
            granted_at: vec!["project/p1".into()]
        }
    );
}

// r[verify authz.explain.decision]
#[test]
fn a_higher_priority_deny_at_the_project_overrides_the_allow() {
    let assignments = [
        role(
            "editor (a1)",
            Level::Scope(project("p1")),
            1,
            &[("document:write", Effect::Allow, true)],
        ),
        role(
            "frozen (a2)",
            Level::Scope(project("p1")),
            5,
            &[("document:write", Effect::Deny, true)],
        ),
    ];
    let explained = explain(&assignments, &at_scope("p1", "document:write"));
    assert!(!explained.allowed);
    let Reason::Denied { by, overrides } = &explained.actions[0].reason else {
        panic!("{:?}", explained.actions[0].reason);
    };
    assert_eq!(by.assignment, "frozen (a2)");
    assert_eq!(overrides[0].assignment, "editor (a1)");
    assert_eq!(
        explained.actions[0].message,
        "Denied: `frozen (a2)` denies `document:write` at project/p1 (priority 5), which \
         overrides `editor (a1)` allows `document:write` at project/p1 (priority 1) with a \
         higher priority."
    );
}

// r[verify authz.explain.decision]
#[test]
fn a_project_deny_does_not_cancel_a_tenant_wide_allow() {
    let assignments = [
        role(
            "editor (a1)",
            Level::Tenant,
            0,
            &[("document:write", Effect::Allow, false)],
        ),
        role(
            "frozen (a2)",
            Level::Scope(project("p1")),
            9,
            &[("document:write", Effect::Deny, true)],
        ),
    ];
    let explained = explain(&assignments, &at_scope("p1", "document:write"));
    assert!(explained.allowed);
    let Reason::Allowed { ineffective, .. } = &explained.actions[0].reason else {
        panic!("{:?}", explained.actions[0].reason);
    };
    assert_eq!(ineffective[0].assignment, "frozen (a2)");
    assert!(
        explained.actions[0]
            .message
            .contains("doesn't cancel it: a deny only cancels allows at its own level"),
        "{}",
        explained.actions[0].message
    );
}

fn claims(tenant: TenantId, amr: &[&str], flags: &[&str]) -> AccessClaims {
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
        amr: amr.iter().map(|m| (*m).to_owned()).collect(),
        auth_time: NOW - 600,
        tid: Some(tenant),
        mid: None,
        sfl: flags.iter().map(|f| (*f).to_owned()).collect(),
        fct: BTreeMap::new(),
        act: None,
        cnf: None,
    }
}

// r[verify authz.explain.checks]
#[test]
fn session_checks_explain_authentication() {
    let tenant = TenantId::new_v7();
    let assignments = [role(
        "reader (a1)",
        Level::Tenant,
        0,
        &[("document:read", Effect::Allow, false)],
    )];
    let requirements = Requirements {
        tenant: set(&["document:read"]),
        step_up: StepUp {
            min_methods: Some(2),
            ..StepUp::default()
        },
        ..Default::default()
    };
    let claims = claims(tenant, &["pwd"], &["personal_only"]);
    let flags = set(&["personal_only"]);
    let explained = explain_decision(
        &ExplainInput {
            catalog: &catalog(),
            assignments: &assignments,
            shares: &[],
            offered: &[],
            requirements: &requirements,
            registered: &RegisteredScopes::default(),
            tenant: Some(tenant),
            tenant_facts: &std::collections::BTreeMap::new(),
            session: Some(SessionContext {
                claims: &claims,
                restrictive_flags: &flags,
                confinements: &Confinements::default(),
                current: true,
            }),
            route: None,
            now: NOW,
        },
        vec![Check::new("subject_active", true, "The subject is active.")],
    );
    let failed: Vec<&str> = explained
        .checks
        .iter()
        .filter(|check| !check.passed)
        .map(|check| check.check.as_str())
        .collect();
    assert_eq!(failed, ["restrictive_flags", "step_up"]);
    assert!(explained.actions[0].granted, "the action itself is granted");
    assert!(!explained.allowed);
    assert!(matches!(explained.decision, Some(Decision::Deny { .. })));
}

// r[verify authz.explain.decision]
#[test]
fn shares_explain_what_they_do_and_dont_grant() {
    let owner = TenantId::new_v7();
    let tenant = TenantId::new_v7();
    let assignments = [role(
        "reader (a1)",
        Level::Tenant,
        0,
        &[("document:read", Effect::Allow, false)],
    )];
    let share = |actions: &[&str], valid_until: Option<i64>| Share {
        id: ShareId::new_v7(),
        owner_tenant: owner,
        scope: project("p-17"),
        recipient_scope: None,
        actions: set(actions),
        attributes: serde_json::Map::new(),
        valid_from: None,
        valid_until,
    };
    let requirements = |action: &str| Requirements {
        scopes: vec![ScopeRequirement {
            tenant: Some(owner),
            kind: "project".into(),
            id: "p-17".into(),
            actions: set(&[action]),
        }],
        ..Default::default()
    };
    let explain = |shares: &[Share], offered: &[Share], action: &str| {
        let requirements = requirements(action);
        explain_decision(
            &ExplainInput {
                catalog: &catalog(),
                assignments: &assignments,
                shares,
                offered,
                requirements: &requirements,
                registered: &RegisteredScopes::default(),
                tenant: Some(tenant),
                tenant_facts: &std::collections::BTreeMap::new(),
                session: None,
                route: None,
                now: NOW,
            },
            vec![],
        )
        .actions
        .remove(0)
    };
    let readable = share(&["document:read", "document:write"], None);
    let explained = explain(std::slice::from_ref(&readable), &[], "document:read");
    assert!(
        matches!(explained.reason, Reason::AllowedByShare { .. }),
        "{explained:?}"
    );
    assert_eq!(explained.owner_tenant, Some(owner));
    assert!(matches!(
        explain(std::slice::from_ref(&readable), &[], "document:write").reason,
        Reason::NotHeldAtRecipient { .. }
    ));
    assert!(matches!(
        explain(&[share(&["document:write"], None)], &[], "document:read").reason,
        Reason::NotShared { .. }
    ));
    assert!(matches!(
        explain(
            &[share(&["document:read"], Some(NOW))],
            &[],
            "document:read"
        )
        .reason,
        Reason::ShareNotValid { .. }
    ));
    assert!(matches!(
        explain(&[], &[share(&["document:read"], None)], "document:read").reason,
        Reason::ShareNotAccepted { .. }
    ));
    assert_eq!(explain(&[], &[], "document:read").reason, Reason::NoShare);
}

// r[verify authz.explain.agreement]
#[test]
fn explanations_agree_with_decisions() {
    let tenant = TenantId::new_v7();
    let owner = TenantId::new_v7();
    let p1 = || Level::Scope(project("p1"));
    let shares = [Share {
        id: ShareId::new_v7(),
        owner_tenant: owner,
        scope: project("p-17"),
        recipient_scope: Some(project("p1")),
        actions: set(&["document:write"]),
        attributes: serde_json::Map::new(),
        valid_from: None,
        valid_until: None,
    }];
    let worlds: Vec<Vec<Assignment>> = vec![
        vec![],
        vec![role(
            "a",
            Level::Tenant,
            0,
            &[("document:read", Effect::Allow, false)],
        )],
        vec![
            role(
                "a",
                Level::Tenant,
                3,
                &[("document:read", Effect::Allow, false)],
            ),
            role(
                "b",
                Level::Tenant,
                3,
                &[("document:read", Effect::Deny, false)],
            ),
        ],
        vec![
            role("a", p1(), 1, &[("document:write", Effect::Allow, true)]),
            role("b", p1(), 2, &[("document:write", Effect::Deny, true)]),
        ],
        vec![
            role("a", p1(), 2, &[("document:write", Effect::Allow, true)]),
            role("b", p1(), 1, &[("document:write", Effect::Deny, true)]),
            role(
                "c",
                Level::Global,
                0,
                &[("document:read", Effect::Allow, false)],
            ),
        ],
        vec![role(
            "a",
            p1(),
            0,
            &[("document:read", Effect::Allow, false)],
        )],
    ];
    let requirements: Vec<Requirements> = ["document:read", "document:write"]
        .iter()
        .flat_map(|action| {
            [
                Requirements {
                    tenant: set(&[action]),
                    ..Default::default()
                },
                Requirements {
                    global: set(&[action]),
                    ..Default::default()
                },
                at_scope("p1", action),
                at_scope("p2", action),
                Requirements {
                    scopes: vec![ScopeRequirement {
                        tenant: Some(owner),
                        kind: "project".into(),
                        id: "p-17".into(),
                        actions: set(&[action]),
                    }],
                    ..Default::default()
                },
            ]
        })
        .collect();
    let claims = claims(tenant, &["pwd"], &[]);
    let flags = BTreeSet::new();
    for assignments in &worlds {
        for requirements in &requirements {
            let explained = explain_decision(
                &ExplainInput {
                    catalog: &catalog(),
                    assignments,
                    shares: &shares,
                    offered: &[],
                    requirements,
                    registered: &RegisteredScopes::default(),
                    tenant: Some(tenant),
                    tenant_facts: &std::collections::BTreeMap::new(),
                    session: Some(SessionContext {
                        claims: &claims,
                        restrictive_flags: &flags,
                        confinements: &Confinements::default(),
                        current: true,
                    }),
                    route: None,
                    now: NOW,
                },
                vec![],
            );
            assert_eq!(
                explained.allowed,
                matches!(explained.decision, Some(Decision::Allow { .. })),
                "{assignments:?} {requirements:?}: {explained:#?}"
            );
        }
    }
}
