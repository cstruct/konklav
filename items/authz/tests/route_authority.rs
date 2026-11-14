#![allow(clippy::too_many_lines)]

//! Route authority: `user:manage_data` vouches for `user:write` and the
//! `user:data` group, so a request whose route decision required it can
//! make narrower checks the subject doesn't pass on its own.

use std::collections::{BTreeMap, BTreeSet};

use konklav_authz::{
    Assignment, Catalog, Confinements, Decision, DenyReason, Effect, Entitlements, Group, Level,
    Policy, RegisteredScopes, Registration, Requirements, RouteAuthority, Scope, ScopeRequirement,
    StepUp, VouchedScope, compile, evaluate, evaluate_with_route_authority,
};
use konklav_core::{SessionId, SubjectId, TenantId};
use konklav_token::{AccessClaims, TokenKind};

const NOW: i64 = 10_000;

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|i| (*i).to_owned()).collect()
}

fn catalog() -> Catalog {
    Catalog {
        actions: set(&[
            "user:manage_data",
            "user:write",
            "user:read",
            "user:export",
            "project:admin",
            "project:edit",
        ]),
        groups: BTreeMap::from([
            (
                "user:data".to_owned(),
                Group::Actions(set(&["user:read", "user:export"])),
            ),
            (
                "project:owner".to_owned(),
                Group::Actions(set(&["project:admin"])),
            ),
        ]),
        vouches: BTreeMap::from([
            (
                "user:manage_data".to_owned(),
                set(&["user:write", "user:data"]),
            ),
            ("project:owner".to_owned(), set(&["project:edit"])),
        ]),
    }
}

/// What `user:manage_data` vouches for, with the group expanded.
fn manage_data_vouches() -> BTreeSet<String> {
    set(&["user:write", "user:data", "user:read", "user:export"])
}

fn scope(kind: &str, id: &str) -> Scope {
    Scope {
        kind: kind.into(),
        id: id.into(),
    }
}

fn policy(action: &str, effect: Effect, scope_bound: bool) -> Policy {
    Policy {
        action: action.into(),
        effect,
        scope_bound,
    }
}

fn assignment(level: Level, priority: i32, policies: Vec<Policy>) -> Assignment {
    Assignment {
        label: "role".into(),
        level,
        priority,
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

/// `document/d-1` in project p-1 and `document/d-2` in project p-2, both
/// recorded in `tenant`; `document/d-3` recorded in `other`.
fn registered(tenant: TenantId, other: TenantId) -> RegisteredScopes {
    let record = |id: &str, tenant: TenantId, project: &str| {
        (
            scope("document", id),
            Some(Registration {
                kind: "document".into(),
                id: id.into(),
                tenant,
                containers: vec![scope("project", project)],
            }),
        )
    };
    RegisteredScopes {
        kinds: set(&["document"]),
        records: BTreeMap::from([
            record("d-1", tenant, "p-1"),
            record("d-2", tenant, "p-2"),
            record("d-3", other, "p-1"),
            (scope("document", "d-gone"), None),
        ]),
    }
}

fn tenant_requirements(actions: &[&str]) -> Requirements {
    Requirements {
        tenant: set(actions),
        ..Default::default()
    }
}

fn scope_requirements(kind: &str, id: &str, actions: &[&str]) -> Requirements {
    Requirements {
        scopes: vec![ScopeRequirement {
            tenant: None,
            kind: kind.into(),
            id: id.into(),
            actions: set(actions),
        }],
        ..Default::default()
    }
}

fn decide(
    requirements: &Requirements,
    authority: Option<&RouteAuthority>,
    claims: &AccessClaims,
    entitlements: &Entitlements,
    registered: &RegisteredScopes,
) -> Decision {
    evaluate_with_route_authority(
        requirements,
        authority,
        claims,
        &BTreeSet::new(),
        &Confinements::default(),
        entitlements,
        registered,
        NOW,
    )
}

fn vouches(decision: &Decision) -> RouteAuthority {
    match decision {
        Decision::Allow { vouches, .. } => vouches.clone(),
        other => panic!("not an allow: {other:?}"),
    }
}

fn missing(actions: &[&str]) -> Decision {
    Decision::Deny {
        reason: DenyReason::MissingActions {
            actions: set(actions),
        },
    }
}

fn tenant_authority(actions: &[&str]) -> RouteAuthority {
    RouteAuthority {
        tenant: set(actions),
        ..Default::default()
    }
}

fn scope_authority(kind: &str, id: &str, actions: &[&str]) -> RouteAuthority {
    RouteAuthority {
        scopes: vec![VouchedScope {
            kind: kind.into(),
            id: id.into(),
            actions: set(actions),
        }],
        ..Default::default()
    }
}

// r[verify authz.compile.vouches]
#[test]
fn entitlement_sets_carry_the_vouches_of_held_vouching_actions() {
    let allow = |action: &str, scope_bound| policy(action, Effect::Allow, scope_bound);
    let held = compile(
        &catalog(),
        &[assignment(
            Level::Tenant,
            0,
            vec![allow("user:manage_data", false)],
        )],
    );
    assert_eq!(
        held.vouches,
        BTreeMap::from([("user:manage_data".to_owned(), manage_data_vouches())]),
        "vouched groups are expanded"
    );
    assert!(
        !held.tenant.contains("user:write"),
        "a vouch grants nothing: {held:?}"
    );

    let at_scope = compile(
        &catalog(),
        &[assignment(
            Level::Scope(scope("project", "p-1")),
            0,
            vec![allow("project:owner", true)],
        )],
    );
    assert_eq!(
        at_scope.vouches,
        BTreeMap::from([("project:owner".to_owned(), set(&["project:edit"]))]),
        "a group vouches, held at a scope"
    );

    let not_held = compile(
        &catalog(),
        &[assignment(
            Level::Tenant,
            0,
            vec![allow("user:write", false)],
        )],
    );
    assert!(not_held.vouches.is_empty(), "{not_held:?}");
    let json = serde_json::to_value(&not_held).unwrap();
    assert!(json.get("vouches").is_none(), "{json}");

    let denied = compile(
        &catalog(),
        &[
            assignment(Level::Tenant, 0, vec![allow("user:manage_data", false)]),
            assignment(
                Level::Tenant,
                1,
                vec![policy("user:manage_data", Effect::Deny, false)],
            ),
        ],
    );
    assert!(
        denied.vouches.is_empty(),
        "a denied vouching action vouches for nothing: {denied:?}"
    );
}

// r[verify authz.decision.vouches]
#[test]
fn an_allow_names_what_it_vouches_for_where_it_was_required() {
    let tenant = TenantId::new_v7();
    let other = TenantId::new_v7();
    let claims = token(Some(tenant));
    let registered = registered(tenant, other);
    let entitlements = Entitlements {
        global: set(&["user:manage_data"]),
        vouches: BTreeMap::from([("user:manage_data".to_owned(), manage_data_vouches())]),
        ..Default::default()
    };
    let route = |requirements: &Requirements| {
        vouches(&decide(
            requirements,
            None,
            &claims,
            &entitlements,
            &registered,
        ))
    };

    assert_eq!(
        route(&Requirements {
            global: set(&["user:manage_data"]),
            ..Default::default()
        }),
        RouteAuthority {
            global: manage_data_vouches(),
            ..Default::default()
        }
    );
    assert_eq!(
        route(&tenant_requirements(&["user:manage_data"])),
        RouteAuthority {
            tenant: manage_data_vouches(),
            ..Default::default()
        }
    );
    assert_eq!(
        route(&scope_requirements("project", "p-1", &["user:manage_data"])),
        RouteAuthority {
            scopes: vec![VouchedScope {
                kind: "project".into(),
                id: "p-1".into(),
                actions: manage_data_vouches(),
            }],
            ..Default::default()
        }
    );
    assert_eq!(
        route(&scope_requirements(
            "document",
            "d-1",
            &["user:manage_data"]
        )),
        RouteAuthority {
            scopes: vec![VouchedScope {
                kind: "document".into(),
                id: "d-1".into(),
                actions: manage_data_vouches(),
            }],
            ..Default::default()
        },
        "at the registered scope itself"
    );
    assert!(
        route(&scope_requirements(
            "document",
            "d-3",
            &["user:manage_data"]
        ))
        .is_empty(),
        "never at another tenant's registered scope"
    );
    assert!(
        route(&tenant_requirements(&[])).is_empty(),
        "nothing required, nothing vouched for"
    );

    let allow = decide(
        &tenant_requirements(&["user:manage_data"]),
        None,
        &claims,
        &entitlements,
        &registered,
    );
    let json = serde_json::to_value(&allow).unwrap();
    assert_eq!(json["vouches"]["tenant"][0], "user:data", "{json}");
    let plain = Decision::allow();
    assert_eq!(
        serde_json::to_value(&plain).unwrap(),
        serde_json::json!({"decision": "allow"}),
        "an allow without vouches serializes as before"
    );
}

// r[verify authz.decision.route-authority]
#[test]
fn route_authority_covers_what_the_subject_lacks_and_vouches_for_nothing() {
    let tenant = TenantId::new_v7();
    let claims = token(Some(tenant));
    let registered = registered(tenant, TenantId::new_v7());
    // Allowed `user:manage_data`, explicitly denied `user:write`.
    let entitlements = compile(
        &catalog(),
        &[assignment(
            Level::Tenant,
            0,
            vec![
                policy("user:manage_data", Effect::Allow, false),
                policy("user:write", Effect::Deny, false),
            ],
        )],
    );
    let write = tenant_requirements(&["user:write"]);
    assert_eq!(
        decide(&write, None, &claims, &entitlements, &registered),
        missing(&["user:write"]),
        "without route authority, as before"
    );

    let route = decide(
        &tenant_requirements(&["user:manage_data"]),
        None,
        &claims,
        &entitlements,
        &registered,
    );
    let authority = vouches(&route);
    let inner = decide(
        &write,
        Some(&authority),
        &claims,
        &entitlements,
        &registered,
    );
    assert!(
        matches!(&inner, Decision::Allow { .. }),
        "the vouch overrides the deny: {inner:?}"
    );
    assert!(
        vouches(&inner).is_empty(),
        "route authority isn't transitive"
    );
    assert_eq!(
        vouches(&decide(
            &tenant_requirements(&["user:manage_data"]),
            Some(&authority),
            &claims,
            &entitlements,
            &registered,
        )),
        RouteAuthority::default(),
        "nor does a later decision requiring the vouching action vouch"
    );
    assert_eq!(
        decide(
            &tenant_requirements(&["user:write", "project:edit"]),
            Some(&authority),
            &claims,
            &entitlements,
            &registered,
        ),
        missing(&["project:edit"]),
        "only what it covers"
    );
    assert_eq!(
        decide(
            &Requirements {
                token_kinds: Some([TokenKind::Identity].into()),
                ..write.clone()
            },
            Some(&authority),
            &claims,
            &entitlements,
            &registered,
        ),
        Decision::Deny {
            reason: DenyReason::TokenKind
        },
        "other checks still apply"
    );
    let fresh = StepUp {
        max_age_seconds: Some(-1),
        ..Default::default()
    };
    assert!(
        matches!(
            decide(
                &Requirements {
                    step_up: fresh,
                    ..write.clone()
                },
                Some(&authority),
                &claims,
                &entitlements,
                &registered,
            ),
            Decision::StepUp { .. }
        ),
        "step-up is still demanded"
    );
    assert_eq!(
        evaluate(
            &write,
            &claims,
            &BTreeSet::new(),
            &Confinements::default(),
            &entitlements,
            &registered,
            NOW,
        ),
        missing(&["user:write"]),
        "evaluate decides without route authority"
    );
}

// r[verify authz.decision.route-authority.coverage]
#[test]
fn route_authority_covers_its_placement_and_what_it_contains() {
    let tenant = TenantId::new_v7();
    let other = TenantId::new_v7();
    let claims = token(Some(tenant));
    let registered = registered(tenant, other);
    let none = Entitlements::default();
    let allowed = |requirements: &Requirements, authority: &RouteAuthority| {
        matches!(
            decide(requirements, Some(authority), &claims, &none, &registered),
            Decision::Allow { .. }
        )
    };
    let at = |kind: &str, id: &str| scope_requirements(kind, id, &["user:write"]);
    let global = RouteAuthority {
        global: set(&["user:write"]),
        ..Default::default()
    };
    let tenant_wide = tenant_authority(&["user:write"]);
    let p1 = scope_authority("project", "p-1", &["user:write"]);
    let d1 = scope_authority("document", "d-1", &["user:write"]);

    let cases = [
        ("global, globally", &global, global_write(), true),
        (
            "global, tenant-wide",
            &global,
            tenant_requirements(&["user:write"]),
            true,
        ),
        ("global, at a scope", &global, at("project", "p-3"), true),
        ("tenant-wide, globally", &tenant_wide, global_write(), false),
        (
            "tenant-wide, tenant-wide",
            &tenant_wide,
            tenant_requirements(&["user:write"]),
            true,
        ),
        (
            "tenant-wide, at a scope",
            &tenant_wide,
            at("project", "p-3"),
            true,
        ),
        (
            "tenant-wide, at a registered scope",
            &tenant_wide,
            at("document", "d-2"),
            true,
        ),
        ("a scope, at itself", &p1, at("project", "p-1"), true),
        ("a scope, at another", &p1, at("project", "p-2"), false),
        (
            "a scope, tenant-wide",
            &p1,
            tenant_requirements(&["user:write"]),
            false,
        ),
        (
            "a scope, at a document it contains",
            &p1,
            at("document", "d-1"),
            true,
        ),
        (
            "a scope, at a document elsewhere",
            &p1,
            at("document", "d-2"),
            false,
        ),
        (
            "a scope, at another tenant's document in it",
            &p1,
            at("document", "d-3"),
            false,
        ),
        (
            "tenant-wide, at another tenant's document",
            &tenant_wide,
            at("document", "d-3"),
            false,
        ),
        (
            "global, at another tenant's document",
            &global,
            at("document", "d-3"),
            false,
        ),
        (
            "a registered scope, at itself",
            &d1,
            at("document", "d-1"),
            true,
        ),
        (
            "a registered scope, at its container",
            &d1,
            at("project", "p-1"),
            false,
        ),
    ];
    for (case, authority, requirements, expected) in cases {
        assert_eq!(allowed(&requirements, authority), expected, "{case}");
    }

    let owned_elsewhere = Requirements {
        scopes: vec![ScopeRequirement {
            tenant: Some(other),
            kind: "project".into(),
            id: "p-1".into(),
            actions: set(&["user:write"]),
        }],
        ..Default::default()
    };
    assert!(
        !allowed(&owned_elsewhere, &global),
        "another tenant's scope is never covered"
    );
    assert_eq!(
        decide(
            &at("document", "d-gone"),
            Some(&p1),
            &claims,
            &none,
            &registered
        ),
        Decision::Deny {
            reason: DenyReason::UnknownScope {
                kind: "document".into(),
                id: "d-gone".into(),
            }
        },
        "a removed registered scope still denies"
    );

    let identity = token(None);
    let as_identity = |requirements: Requirements| Requirements {
        token_kinds: Some([TokenKind::Identity].into()),
        ..requirements
    };
    assert!(
        matches!(
            decide(
                &as_identity(global_write()),
                Some(&global),
                &identity,
                &none,
                &registered
            ),
            Decision::Allow { .. }
        ),
        "without a tenant, global route authority covers global requirements"
    );
    assert!(
        !matches!(
            decide(
                &as_identity(at("document", "d-1")),
                Some(&global),
                &identity,
                &none,
                &registered
            ),
            Decision::Allow { .. }
        ),
        "but no scope, since none is the token's tenant's"
    );
}

fn global_write() -> Requirements {
    Requirements {
        global: set(&["user:write"]),
        ..Default::default()
    }
}

/// Explains `requirements` for a subject holding `assignments` in
/// `tenant`, with the route's requirements when given, for a session when
/// `claims` are given.
fn explain(
    assignments: &[Assignment],
    requirements: &Requirements,
    route: Option<&Requirements>,
    tenant: TenantId,
    claims: Option<&AccessClaims>,
) -> konklav_authz::DecisionExplanation {
    let other = TenantId::new_v7();
    let restrictive = BTreeSet::new();
    let confinements = Confinements::default();
    konklav_authz::explain_decision(
        &konklav_authz::ExplainInput {
            catalog: &catalog(),
            assignments,
            shares: &[],
            offered: &[],
            requirements,
            registered: &registered(tenant, other),
            tenant: Some(tenant),
            tenant_facts: &BTreeMap::new(),
            session: claims.map(|claims| konklav_authz::SessionContext {
                claims,
                restrictive_flags: &restrictive,
                confinements: &confinements,
                current: true,
            }),
            route,
            now: NOW,
        },
        vec![],
    )
}

/// A steward: `user:manage_data` allowed tenant-wide, `user:write`
/// explicitly denied there.
fn steward() -> Vec<Assignment> {
    vec![assignment(
        Level::Tenant,
        0,
        vec![
            policy("user:manage_data", Effect::Allow, false),
            policy("user:write", Effect::Deny, false),
        ],
    )]
}

// r[verify authz.explain.route-authority]
// r[verify authz.explain.agreement]
#[test]
fn explanations_name_the_vouch_that_grants_an_action() {
    let tenant = TenantId::new_v7();
    let claims = token(Some(tenant));
    let route = tenant_requirements(&["user:manage_data"]);
    let write = tenant_requirements(&["user:write"]);

    let alone = explain(&steward(), &write, None, tenant, Some(&claims));
    assert!(!alone.allowed);
    assert!(alone.route.is_none());
    assert!(
        matches!(
            alone.actions[0].reason,
            konklav_authz::Reason::Denied { .. }
        ),
        "{alone:?}"
    );

    let explained = explain(&steward(), &write, Some(&route), tenant, Some(&claims));
    assert!(explained.allowed, "{explained:?}");
    assert!(
        matches!(explained.decision, Some(Decision::Allow { ref vouches, .. }) if vouches.is_empty()),
        "an allow made with route authority vouches for nothing: {explained:?}"
    );
    let routed = explained.route.as_ref().unwrap();
    assert!(routed.allowed);
    assert_eq!(
        routed.vouches,
        RouteAuthority {
            tenant: manage_data_vouches(),
            ..Default::default()
        }
    );
    assert!(routed.explanation.allowed);
    let action = &explained.actions[0];
    assert!(action.granted);
    match &action.reason {
        konklav_authz::Reason::Vouched { vouching, at, held } => {
            assert_eq!(vouching, "user:manage_data");
            assert_eq!(at, "tenant");
            assert!(
                matches!(**held, konklav_authz::Reason::Denied { .. }),
                "the vouch overrides the deny: {held:?}"
            );
        }
        other => panic!("{other:?}"),
    }
    assert!(
        action
            .message
            .starts_with("Allowed through route authority: the route required `user:manage_data` at tenant, which vouches for `user:write`. Without it: Denied"),
        "{}",
        action.message
    );

    // Without a session, the same explanation.
    let tenant_only = explain(&steward(), &write, Some(&route), tenant, None);
    assert!(tenant_only.allowed);
    assert_eq!(tenant_only.actions, explained.actions);
}

// r[verify authz.explain.route-authority]
#[test]
fn a_scopes_vouch_is_explained_at_the_registered_scopes_it_contains() {
    let tenant = TenantId::new_v7();
    let claims = token(Some(tenant));
    let assignments = [assignment(
        Level::Scope(scope("project", "p-1")),
        0,
        vec![policy("user:manage_data", Effect::Allow, true)],
    )];
    let route = scope_requirements("project", "p-1", &["user:manage_data"]);
    let read = |id: &str| {
        explain(
            &assignments,
            &scope_requirements("document", id, &["user:read"]),
            Some(&route),
            tenant,
            Some(&claims),
        )
    };

    let inside = read("d-1");
    assert!(inside.allowed, "{inside:?}");
    assert!(
        matches!(&inside.actions[0].reason, konklav_authz::Reason::Vouched { at, .. } if at == "project/p-1"),
        "{inside:?}"
    );
    for id in ["d-2", "d-3"] {
        let outside = read(id);
        assert!(!outside.allowed, "{id}: {outside:?}");
        assert!(
            matches!(outside.decision, Some(Decision::Deny { .. })),
            "{id}: {outside:?}"
        );
        assert!(
            !matches!(
                outside.actions[0].reason,
                konklav_authz::Reason::Vouched { .. }
            ),
            "{id}: {outside:?}"
        );
    }
}

// r[verify authz.explain.route-authority]
// r[verify authz.explain.agreement]
#[test]
fn a_route_decision_that_does_not_allow_is_explained_as_vouching_for_nothing() {
    let tenant = TenantId::new_v7();
    let claims = token(Some(tenant));
    let writer = [assignment(
        Level::Tenant,
        0,
        vec![policy("user:write", Effect::Allow, false)],
    )];
    let route = tenant_requirements(&["user:manage_data"]);

    let denied = explain(
        &[],
        &tenant_requirements(&["user:write"]),
        Some(&route),
        tenant,
        Some(&claims),
    );
    assert!(!denied.allowed);
    assert_eq!(denied.decision, Some(missing(&["user:write"])));
    let routed = denied.route.as_ref().unwrap();
    assert!(!routed.allowed);
    assert!(routed.vouches.is_empty());
    assert_eq!(
        routed.message,
        "The route decision doesn't allow, so it vouches for nothing."
    );

    // An action held on its own is explained by its own policy.
    let held = explain(
        &writer,
        &tenant_requirements(&["user:write"]),
        Some(&route),
        tenant,
        Some(&claims),
    );
    assert!(held.allowed);
    assert!(
        matches!(
            held.actions[0].reason,
            konklav_authz::Reason::Allowed { .. }
        ),
        "{held:?}"
    );
}
