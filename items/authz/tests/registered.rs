//! Registered scopes: requirements that name a scope alone, decided from
//! Konklav's record of its tenant and containing scopes.

use std::collections::{BTreeMap, BTreeSet};

use konklav_authz::{
    Assignment, Catalog, Decision, DenyReason, Effect, Entitlements, ExplainInput, Level,
    Obligation, Policy, RegisteredScopes, Registration, Requirements, Scope, ScopeRequirement,
    SessionContext, Share, compile, evaluate, explain_decision, shared,
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
    }
}

fn scope(kind: &str, id: &str) -> Scope {
    Scope {
        kind: kind.into(),
        id: id.into(),
    }
}

fn policy(action: &str, effect: Effect) -> Policy {
    Policy {
        action: action.into(),
        effect,
        scope_bound: true,
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

fn token(tenant: Option<TenantId>) -> AccessClaims {
    AccessClaims {
        iss: "i".into(),
        aud: "a".into(),
        sub: SubjectId::new_v7(),
        jti: "j".into(),
        iat: NOW,
        exp: NOW + 900,
        knd: if tenant.is_some() {
            TokenKind::Tenant
        } else {
            TokenKind::Identity
        },
        sid: SessionId::new_v7(),
        cid: None,
        sv: 1,
        amr: vec!["pwd".into()],
        auth_time: NOW,
        tid: tenant,
        mid: None,
        sfl: vec![],
        fct: BTreeMap::new(),
        act: None,
        cnf: None,
    }
}

/// `document/d-1`, recorded in `tenant` inside projects p-1 and p-2.
fn registered(tenant: TenantId) -> RegisteredScopes {
    let d1 = scope("document", "d-1");
    RegisteredScopes {
        kinds: set(&["document"]),
        records: BTreeMap::from([(
            d1,
            Some(Registration {
                kind: "document".into(),
                id: "d-1".into(),
                tenant,
                containers: vec![scope("project", "p-1"), scope("project", "p-2")],
            }),
        )]),
    }
}

fn read(id: &str, tenant: Option<TenantId>) -> Requirements {
    Requirements {
        token_kinds: Some([TokenKind::Tenant, TokenKind::Identity].into()),
        scopes: vec![ScopeRequirement {
            tenant,
            kind: "document".into(),
            id: id.into(),
            actions: set(&["document:read"]),
        }],
        ..Default::default()
    }
}

fn decide(
    requirements: &Requirements,
    claims: &AccessClaims,
    entitlements: &Entitlements,
    registered: &RegisteredScopes,
) -> Decision {
    evaluate(
        requirements,
        claims,
        &BTreeSet::new(),
        entitlements,
        registered,
        NOW,
    )
}

fn missing_read() -> Decision {
    Decision::Deny {
        reason: DenyReason::MissingActions {
            actions: set(&["document:read"]),
        },
    }
}

// r[verify authz.registered.evaluation]
#[test]
fn own_tenant_grants_count_tenant_wide_at_the_scope_or_at_any_container() {
    let tenant = TenantId::new_v7();
    let claims = token(Some(tenant));
    let registered = registered(tenant);
    let read_allow = || vec![policy("document:read", Effect::Allow)];
    for level in [
        Level::Tenant,
        Level::Scope(scope("document", "d-1")),
        Level::Scope(scope("project", "p-1")),
        Level::Scope(scope("project", "p-2")),
    ] {
        let entitlements = compile(&catalog(), &[assignment(level.clone(), read_allow())]);
        assert_eq!(
            decide(&read("d-1", None), &claims, &entitlements, &registered),
            Decision::allow(),
            "granted at {level:?}"
        );
    }

    let elsewhere = compile(
        &catalog(),
        &[assignment(
            Level::Scope(scope("project", "p-3")),
            read_allow(),
        )],
    );
    assert_eq!(
        decide(&read("d-1", None), &claims, &elsewhere, &registered),
        missing_read(),
        "a project the document isn't in grants nothing"
    );
}

// r[verify authz.registered.evaluation]
#[test]
fn a_deny_at_one_container_does_not_cancel_an_allow_at_another() {
    let tenant = TenantId::new_v7();
    let entitlements = compile(
        &catalog(),
        &[
            assignment(
                Level::Scope(scope("project", "p-1")),
                vec![policy("document:read", Effect::Deny)],
            ),
            assignment(
                Level::Scope(scope("project", "p-2")),
                vec![policy("document:read", Effect::Allow)],
            ),
        ],
    );
    assert_eq!(
        decide(
            &read("d-1", None),
            &token(Some(tenant)),
            &entitlements,
            &registered(tenant),
        ),
        Decision::allow()
    );
}

// r[verify authz.registered.evaluation]
#[test]
fn another_tenant_is_denied_whatever_it_holds_or_names() {
    let owner = TenantId::new_v7();
    let other = TenantId::new_v7();
    let entitlements = compile(
        &catalog(),
        &[assignment(
            Level::Tenant,
            vec![policy("document:read", Effect::Allow)],
        )],
    );
    let registered = registered(owner);
    assert_eq!(
        decide(
            &read("d-1", None),
            &token(Some(other)),
            &entitlements,
            &registered
        ),
        missing_read(),
        "tenant-wide grants elsewhere don't reach another tenant's scope"
    );
    assert_eq!(
        decide(
            &read("d-1", Some(other)),
            &token(Some(other)),
            &entitlements,
            &registered
        ),
        Decision::Deny {
            reason: DenyReason::UnknownScope {
                kind: "document".into(),
                id: "d-1".into(),
            },
        },
        "naming the caller's tenant doesn't move the scope there"
    );
}

// r[verify authz.registered.unknown-denies]
#[test]
fn unknown_and_removed_scopes_deny() {
    let tenant = TenantId::new_v7();
    let entitlements = compile(
        &catalog(),
        &[assignment(
            Level::Tenant,
            vec![policy("document:read", Effect::Allow)],
        )],
    );
    let unknown = Decision::Deny {
        reason: DenyReason::UnknownScope {
            kind: "document".into(),
            id: "d-9".into(),
        },
    };
    let mut registered = registered(tenant);
    assert_eq!(
        decide(
            &read("d-9", None),
            &token(Some(tenant)),
            &entitlements,
            &registered
        ),
        unknown,
        "no record at all"
    );
    registered.records.insert(scope("document", "d-9"), None);
    assert_eq!(
        decide(
            &read("d-9", None),
            &token(Some(tenant)),
            &entitlements,
            &registered
        ),
        unknown,
        "known to be unknown or removed"
    );
}

// r[verify authz.registered.shares]
#[test]
fn another_tenant_gets_shares_of_the_scope_or_a_container_with_obligations() {
    let owner = TenantId::new_v7();
    let recipient = TenantId::new_v7();
    let mut entitlements = compile(
        &catalog(),
        &[assignment(
            Level::Tenant,
            vec![Policy {
                scope_bound: false,
                ..policy("document:read", Effect::Allow)
            }],
        )],
    );
    let the_share = Share {
        id: ShareId::new_v7(),
        owner_tenant: owner,
        scope: scope("project", "p-2"),
        recipient_scope: None,
        actions: set(&["document:read"]),
        attributes: serde_json::Map::new(),
        valid_from: None,
        valid_until: Some(NOW + 1),
    };
    entitlements.shared = shared(&catalog(), &entitlements, std::slice::from_ref(&the_share));
    let claims = token(Some(recipient));
    let registered = registered(owner);
    assert_eq!(
        decide(&read("d-1", None), &claims, &entitlements, &registered),
        Decision::Allow {
            obligations: vec![Obligation {
                share: the_share.id,
                tenant: owner,
                kind: "project".into(),
                id: "p-2".into(),
                attributes: serde_json::Map::new(),
            }],
        }
    );
    assert_eq!(
        evaluate(
            &read("d-1", None),
            &claims,
            &BTreeSet::new(),
            &entitlements,
            &registered,
            NOW + 1,
        ),
        missing_read(),
        "an expired share grants nothing"
    );
}

// r[verify authz.registered.no-tenant]
#[test]
fn without_a_tenant_only_global_actions_count() {
    let tenant = TenantId::new_v7();
    let registered = registered(tenant);
    let claims = token(None);
    let tenant_wide = compile(
        &catalog(),
        &[assignment(
            Level::Tenant,
            vec![policy("document:read", Effect::Allow)],
        )],
    );
    assert_eq!(
        decide(&read("d-1", None), &claims, &tenant_wide, &registered),
        missing_read()
    );
    let global = compile(
        &catalog(),
        &[assignment(
            Level::Global,
            vec![policy("document:read", Effect::Allow)],
        )],
    );
    assert_eq!(
        decide(&read("d-1", None), &claims, &global, &registered),
        Decision::allow()
    );
}

#[test]
fn kinds_that_are_not_registered_are_decided_as_before() {
    let tenant = TenantId::new_v7();
    let entitlements = compile(
        &catalog(),
        &[assignment(
            Level::Scope(scope("folder", "f-1")),
            vec![policy("document:read", Effect::Allow)],
        )],
    );
    let requirements = Requirements {
        scopes: vec![ScopeRequirement {
            tenant: None,
            kind: "folder".into(),
            id: "f-1".into(),
            actions: set(&["document:read"]),
        }],
        ..Default::default()
    };
    assert_eq!(
        decide(
            &requirements,
            &token(Some(tenant)),
            &entitlements,
            &registered(tenant),
        ),
        Decision::allow()
    );
}

// r[verify authz.explain.agreement]
#[test]
fn explanations_agree_with_decisions_at_registered_scopes() {
    let owner = TenantId::new_v7();
    let other = TenantId::new_v7();
    let worlds: Vec<Vec<Assignment>> = vec![
        vec![],
        vec![assignment(
            Level::Scope(scope("project", "p-2")),
            vec![policy("document:read", Effect::Allow)],
        )],
        vec![
            assignment(
                Level::Scope(scope("project", "p-1")),
                vec![policy("document:read", Effect::Deny)],
            ),
            assignment(
                Level::Scope(scope("document", "d-1")),
                vec![policy("document:read", Effect::Allow)],
            ),
        ],
        vec![assignment(
            Level::Global,
            vec![policy("document:read", Effect::Allow)],
        )],
    ];
    let shares = [Share {
        id: ShareId::new_v7(),
        owner_tenant: owner,
        scope: scope("project", "p-1"),
        recipient_scope: None,
        actions: set(&["document:read"]),
        attributes: serde_json::Map::new(),
        valid_from: None,
        valid_until: None,
    }];
    let registered = registered(owner);
    let flags = BTreeSet::new();
    for tenant in [Some(owner), Some(other), None] {
        let claims = token(tenant);
        for assignments in &worlds {
            for id in ["d-1", "d-9"] {
                let requirements = read(id, None);
                let explained = explain_decision(
                    &ExplainInput {
                        catalog: &catalog(),
                        assignments,
                        shares: if tenant == Some(other) { &shares } else { &[] },
                        offered: &[],
                        requirements: &requirements,
                        registered: &registered,
                        tenant,
                        session: Some(SessionContext {
                            claims: &claims,
                            restrictive_flags: &flags,
                            current: true,
                        }),
                        now: NOW,
                    },
                    vec![],
                );
                assert_eq!(
                    explained.allowed,
                    matches!(explained.decision, Some(Decision::Allow { .. })),
                    "{tenant:?} {assignments:?} {id}: {explained:#?}"
                );
            }
        }
    }
}
