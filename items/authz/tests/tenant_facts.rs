#![allow(clippy::too_many_lines)]

//! Tenant fact requirements: operations that only tenants with matching
//! facts may use, decided by evaluation and reported by decision
//! explanations.

use std::collections::{BTreeMap, BTreeSet};

use konklav_authz::{
    Assignment, Catalog, Confinements, Decision, DenyReason, Effect, Entitlements, ExplainInput,
    Level, Policy, RegisteredScopes, Requirements, SessionContext, evaluate, explain_decision,
};
use konklav_core::{SessionId, SubjectId, TenantId};
use konklav_token::{AccessClaims, TokenKind};
use serde_json::json;

const NOW: i64 = 10_000;

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|i| (*i).to_owned()).collect()
}

fn claims(kind: TokenKind) -> AccessClaims {
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
        amr: vec!["pwd".into()],
        auth_time: NOW - 3600,
        tid: (kind == TokenKind::Tenant).then(TenantId::new_v7),
        mid: None,
        sfl: Vec::new(),
        fct: BTreeMap::new(),
        act: None,
        cnf: None,
    }
}

/// No confinements; the tenant's portable facts.
fn facts(tenant_facts: serde_json::Value) -> Confinements {
    Confinements {
        flags: BTreeMap::new(),
        tenant_facts: serde_json::from_value(tenant_facts).unwrap(),
    }
}

fn requirements(value: serde_json::Value) -> Requirements {
    serde_json::from_value(value).unwrap()
}

fn decide(requirements: &Requirements, claims: &AccessClaims, facts: &Confinements) -> Decision {
    let entitlements = Entitlements {
        global: set(&["sys:all"]),
        tenant: set(&["tenant:read"]),
        ..Entitlements::default()
    };
    evaluate(
        requirements,
        claims,
        &BTreeSet::new(),
        facts,
        &entitlements,
        &RegisteredScopes::default(),
        NOW,
    )
}

fn failing(fact: &str) -> Decision {
    Decision::Deny {
        reason: DenyReason::TenantFacts { fact: fact.into() },
    }
}

// r[verify authz.decision.tenant-facts]
// r[verify relying.decision.requirements]
#[test]
fn a_decision_needs_a_tenant_whose_facts_match_every_predicate() {
    let required = requirements(json!({
        "tenant": ["tenant:read"],
        "tenant_facts": {"tenant_type": ["client", "clinic"], "tier": [1, 2]},
    }));
    let token = claims(TokenKind::Tenant);
    assert_eq!(
        decide(
            &required,
            &token,
            &facts(json!({"tenant_type": "clinic", "tier": 2, "region": "se"}))
        ),
        Decision::allow()
    );
    assert_eq!(
        decide(
            &required,
            &token,
            &facts(json!({"tenant_type": "personal", "tier": 2}))
        ),
        failing("tenant_type"),
        "a value not listed"
    );
    assert_eq!(
        decide(&required, &token, &facts(json!({"tenant_type": "client"}))),
        failing("tier"),
        "a missing fact matches nothing"
    );
    assert_eq!(
        decide(
            &required,
            &token,
            &facts(json!({"tenant_type": "client", "tier": "1"}))
        ),
        failing("tier"),
        "values match by type as well"
    );
    assert_eq!(
        decide(
            &requirements(json!({"tenant_facts": {}})),
            &token,
            &facts(json!({}))
        ),
        Decision::allow(),
        "an empty object requires nothing"
    );
}

// r[verify authz.decision.tenant-facts]
// r[verify authz.decision.tenant-facts.reason]
#[test]
fn global_actions_and_step_up_dont_lift_it() {
    let required = requirements(json!({
        "global": ["sys:all"],
        "token_kinds": ["identity", "tenant"],
        "tenant_facts": {"tenant_type": ["client"], "region": ["se"]},
        "step_up": {"max_age_seconds": 60},
    }));
    // The tenant fails before the stale authentication is asked to step up.
    assert_eq!(
        decide(
            &required,
            &claims(TokenKind::Tenant),
            &facts(json!({"tenant_type": "personal", "region": "no"}))
        ),
        failing("region"),
        "the first failing predicate by key"
    );
    assert_eq!(
        decide(&required, &claims(TokenKind::Identity), &facts(json!({}))),
        failing("region"),
        "without a tenant, the first predicate"
    );
    let fresh = AccessClaims {
        auth_time: NOW,
        ..claims(TokenKind::Tenant)
    };
    assert_eq!(
        decide(
            &required,
            &fresh,
            &facts(json!({"tenant_type": "client", "region": "se"}))
        ),
        Decision::allow()
    );
}

// r[verify authz.decision.tenant-facts.reason]
#[test]
fn the_deny_reason_names_the_fact() {
    assert_eq!(
        serde_json::to_value(failing("tenant_type")).unwrap(),
        json!({"decision": "deny", "reason": {"tenant_facts": {"fact": "tenant_type"}}})
    );
    let required = requirements(json!({"tenant_facts": {"tenant_type": ["client"]}}));
    assert_eq!(
        serde_json::to_value(&required).unwrap(),
        json!({"tenant_facts": {"tenant_type": ["client"]}})
    );
    assert_eq!(
        serde_json::to_value(Requirements::default()).unwrap(),
        json!({}),
        "left out when empty"
    );
}

// r[verify authz.decision.tenant-facts.shape]
#[test]
fn predicates_are_read_without_the_catalog() {
    for (value, why) in [
        (json!({"tenant_type": []}), "no values"),
        (json!({"tenant_type": [null]}), "null"),
        (json!({"tier": [1.5]}), "a fraction"),
        (json!({"tags": [["a"]]}), "a list"),
        (json!({"tags": [{"a": 1}]}), "an object"),
        (json!({"tenant_type": "client"}), "not a list"),
    ] {
        let read = serde_json::from_value::<Requirements>(json!({"tenant_facts": value}));
        assert!(read.is_err(), "{why} is refused");
    }
    // Any key is read: one the catalog doesn't declare simply never
    // matches.
    let required = requirements(json!({"tenant_facts": {"undeclared": [true, 3, "x"]}}));
    assert_eq!(
        decide(
            &required,
            &claims(TokenKind::Tenant),
            &facts(json!({"tenant_type": "client"}))
        ),
        failing("undeclared")
    );
}

// r[verify authz.explain.tenant-facts]
// r[verify authz.explain.agreement]
#[test]
fn explanations_report_the_tenant_facts_check() {
    let catalog = Catalog::default();
    let assignments = [Assignment {
        label: "reader".into(),
        level: Level::Tenant,
        priority: 0,
        template_policies: vec![],
        role_policies: vec![Policy {
            action: "tenant:read".into(),
            effect: Effect::Allow,
            scope_bound: false,
        }],
    }];
    let required = requirements(json!({
        "tenant": ["tenant:read"],
        "token_kinds": ["identity", "tenant"],
        "tenant_facts": {"tenant_type": ["client"], "region": ["se"]},
    }));
    let explain = |claims: &AccessClaims, facts: &Confinements| {
        let restrictive = BTreeSet::new();
        explain_decision(
            &ExplainInput {
                catalog: &catalog,
                assignments: &assignments,
                shares: &[],
                offered: &[],
                requirements: &required,
                registered: &RegisteredScopes::default(),
                tenant: claims.tid,
                tenant_facts: &facts.tenant_facts,
                session: Some(SessionContext {
                    claims,
                    restrictive_flags: &restrictive,
                    confinements: facts,
                    current: true,
                }),
                route: None,
                now: NOW,
            },
            vec![],
        )
    };
    let check = |explanation: &konklav_authz::DecisionExplanation| {
        explanation
            .checks
            .iter()
            .find(|check| check.check == "tenant_facts")
            .cloned()
            .expect("a tenant_facts check")
    };

    let token = claims(TokenKind::Tenant);
    let denied = explain(&token, &facts(json!({"tenant_type": "personal"})));
    assert!(!denied.allowed);
    assert_eq!(denied.decision, Some(failing("region")));
    let failed = check(&denied);
    assert!(!failed.passed);
    assert_eq!(
        failed.message,
        "The operation needs a tenant where `region` is one of `\"se\"` and `tenant_type` is \
         one of `\"client\"`; the tenant fails on `region` (`region` is not set, `tenant_type` \
         is `\"personal\"`)."
    );

    let allowed = explain(
        &token,
        &facts(json!({"tenant_type": "client", "region": "se"})),
    );
    assert!(allowed.allowed);
    assert_eq!(allowed.decision, Some(Decision::allow()));
    assert!(check(&allowed).passed);

    let no_tenant = explain(&claims(TokenKind::Identity), &facts(json!({})));
    assert!(!no_tenant.allowed);
    assert_eq!(
        check(&no_tenant).message,
        "The operation needs a tenant where `region` is one of `\"se\"` and `tenant_type` is \
         one of `\"client\"`, and the decision is for none."
    );

    let without = Requirements {
        tenant_facts: BTreeMap::new(),
        ..required.clone()
    };
    let restrictive = BTreeSet::new();
    let facts = facts(json!({}));
    let unrequired = explain_decision(
        &ExplainInput {
            catalog: &catalog,
            assignments: &assignments,
            shares: &[],
            offered: &[],
            requirements: &without,
            registered: &RegisteredScopes::default(),
            tenant: token.tid,
            tenant_facts: &facts.tenant_facts,
            session: Some(SessionContext {
                claims: &token,
                restrictive_flags: &restrictive,
                confinements: &facts,
                current: true,
            }),
            route: None,
            now: NOW,
        },
        vec![],
    );
    assert!(
        unrequired.checks.iter().all(|c| c.check != "tenant_facts"),
        "no check without tenant fact requirements"
    );
}
