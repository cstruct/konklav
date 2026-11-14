//! Confinements: a restrictive flag confined to the tenants whose facts
//! match, decided by evaluation and reported by decision explanations.

use std::collections::{BTreeMap, BTreeSet};

use konklav_authz::{
    Assignment, Catalog, Confinement, Confinements, Decision, DenyReason, Effect, EntitlementSet,
    Entitlements, ExplainInput, Level, Policy, RegisteredScopes, Requirements, SessionContext,
    evaluate, explain_decision,
};
use konklav_core::{Cursor, SessionId, SubjectId, TenantId};
use konklav_token::{AccessClaims, TokenKind};
use serde_json::json;

const NOW: i64 = 10_000;

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|i| (*i).to_owned()).collect()
}

fn claims(kind: TokenKind, flags: &[&str]) -> AccessClaims {
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
        auth_time: NOW,
        tid: (kind == TokenKind::Tenant).then(TenantId::new_v7),
        mid: None,
        sfl: flags.iter().map(|f| (*f).to_owned()).collect(),
        fct: BTreeMap::new(),
        act: None,
        cnf: None,
    }
}

fn personal_only() -> Confinement {
    serde_json::from_value(json!({"tenant": {"tenant_type": ["personal"], "region": ["se", "no"]}}))
        .unwrap()
}

/// `personal_only` confined, and the tenant's values of the facts it names.
fn confinements(tenant_facts: serde_json::Value) -> Confinements {
    Confinements {
        flags: BTreeMap::from([("personal_only".to_owned(), personal_only())]),
        tenant_facts: serde_json::from_value(tenant_facts).unwrap(),
    }
}

fn entitlements() -> Entitlements {
    Entitlements {
        global: set(&["me"]),
        tenant: set(&["patient:read"]),
        ..Entitlements::default()
    }
}

fn decide(
    requirements: &Requirements,
    claims: &AccessClaims,
    confinements: &Confinements,
) -> Decision {
    evaluate(
        requirements,
        claims,
        &set(&["personal_only", "passwordless"]),
        confinements,
        &entitlements(),
        &RegisteredScopes::default(),
        NOW,
    )
}

fn confined() -> Decision {
    Decision::Deny {
        reason: DenyReason::ConfinedSession {
            flag: "personal_only".into(),
        },
    }
}

fn admitted(global: &[&str], tenant: &[&str]) -> Requirements {
    Requirements {
        global: set(global),
        tenant: set(tenant),
        admit_flags: set(&["personal_only", "passwordless"]),
        ..Requirements::default()
    }
}

// r[verify session.flags.confine]
#[test]
fn a_tenant_matches_when_every_predicate_holds() {
    let confinement = personal_only();
    let facts = |value: serde_json::Value| -> BTreeMap<String, serde_json::Value> {
        serde_json::from_value(value).unwrap()
    };
    assert_eq!(
        confinement.failing(&facts(json!({"tenant_type": "personal", "region": "no"}))),
        None
    );
    assert_eq!(
        confinement.failing(&facts(json!({"tenant_type": "client", "region": "se"}))),
        Some("tenant_type"),
        "a value not listed"
    );
    assert_eq!(
        confinement.failing(&facts(json!({"tenant_type": "personal"}))),
        Some("region"),
        "a missing fact matches nothing"
    );
    assert_eq!(
        confinement.failing(&facts(json!({"tenant_type": ["personal"], "region": "se"}))),
        Some("tenant_type"),
        "values are compared whole"
    );
    assert_eq!(
        confinement.describe(),
        "`region` is one of `\"se\"`, `\"no\"` and `tenant_type` is one of `\"personal\"`"
    );
}

// r[verify session.flags.confine]
#[test]
fn confinements_refuse_members_they_dont_know() {
    let read = serde_json::from_value::<Confinement>(
        json!({"tenant": {"tenant_type": ["personal"]}, "membership": {"role": ["owner"]}}),
    );
    assert!(read.is_err(), "an ignored member would loosen it");
}

// r[verify session.flags.confine.decision]
#[test]
fn a_confined_session_acts_only_in_a_matching_tenant() {
    let token = claims(TokenKind::Tenant, &["personal_only"]);
    let matching = confinements(json!({"tenant_type": "personal", "region": "se"}));
    let other = confinements(json!({"tenant_type": "client", "region": "se"}));

    assert_eq!(
        decide(&admitted(&[], &["patient:read"]), &token, &matching),
        Decision::allow()
    );
    assert_eq!(
        decide(&admitted(&[], &["patient:read"]), &token, &other),
        confined()
    );
    assert_eq!(
        decide(&admitted(&["me"], &[]), &token, &other),
        confined(),
        "global actions don't lift it"
    );
    assert_eq!(
        decide(&admitted(&["me"], &[]), &token, &matching),
        Decision::allow(),
        "global actions count in a matching tenant"
    );
    assert_eq!(
        decide(
            &admitted(&[], &["patient:read"]),
            &token,
            &confinements(json!({}))
        ),
        confined(),
        "a tenant without the facts matches nothing"
    );

    // Without a tenant there is nothing to match.
    let identity = claims(TokenKind::Identity, &["personal_only"]);
    let global = Requirements {
        token_kinds: Some(BTreeSet::from([TokenKind::Identity])),
        ..admitted(&["me"], &[])
    };
    assert_eq!(decide(&global, &identity, &matching), confined());

    // An unadmitted flag still says so first.
    assert_eq!(
        decide(&Requirements::default(), &token, &other),
        Decision::Deny {
            reason: DenyReason::RestrictedSession {
                flag: "personal_only".into()
            }
        }
    );
    // Sessions without the flag, or with an unconfined one, aren't affected.
    for flags in [&[][..], &["passwordless"][..]] {
        assert_eq!(
            decide(
                &admitted(&[], &["patient:read"]),
                &claims(TokenKind::Tenant, flags),
                &other
            ),
            Decision::allow(),
            "{flags:?}"
        );
    }
}

// r[verify session.flags.confine.decision]
#[test]
fn confined_denies_serialize_with_the_flag() {
    assert_eq!(
        serde_json::to_value(confined()).unwrap(),
        json!({"decision": "deny", "reason": {"confined_session": {"flag": "personal_only"}}})
    );
}

// r[verify authz.compile.confinements]
#[test]
fn entitlement_sets_carry_confinements_only_when_there_are_any() {
    let mut entitlement_set = EntitlementSet {
        subject_id: SubjectId::new_v7(),
        tenant_id: Some(TenantId::new_v7()),
        revision: Cursor::new(1),
        entitlements: entitlements(),
        restrictive_flags: set(&["personal_only"]),
        registered_kinds: BTreeSet::new(),
        confinements: Confinements::default(),
    };
    let plain = serde_json::to_value(&entitlement_set).unwrap();
    assert!(plain.get("confinements").is_none(), "{plain}");

    entitlement_set.confinements = confinements(json!({"tenant_type": "personal"}));
    let sent = serde_json::to_value(&entitlement_set).unwrap();
    assert_eq!(
        sent["confinements"],
        json!({
            "flags": {"personal_only": {"tenant": {"region": ["se", "no"], "tenant_type": ["personal"]}}},
            "tenant_facts": {"tenant_type": "personal"},
        })
    );
    let read: EntitlementSet = serde_json::from_value(sent).unwrap();
    assert_eq!(read, entitlement_set);
}

// r[verify authz.explain.confinement]
// r[verify authz.explain.agreement]
#[test]
fn explanations_name_the_confinement_that_denies() {
    let catalog = Catalog {
        actions: set(&["patient:read"]),
        groups: BTreeMap::new(),
        vouches: BTreeMap::new(),
    };
    let assignments = [Assignment {
        label: "carer".into(),
        level: Level::Tenant,
        priority: 0,
        template_policies: vec![],
        role_policies: vec![Policy {
            action: "patient:read".into(),
            effect: Effect::Allow,
            scope_bound: false,
        }],
    }];
    let requirements = admitted(&[], &["patient:read"]);
    let restrictive = set(&["personal_only"]);
    let explain = |claims: &AccessClaims, confinements: &Confinements| {
        explain_decision(
            &ExplainInput {
                catalog: &catalog,
                assignments: &assignments,
                shares: &[],
                offered: &[],
                requirements: &requirements,
                registered: &RegisteredScopes::default(),
                tenant: claims.tid,
                tenant_facts: &confinements.tenant_facts,
                session: Some(SessionContext {
                    claims,
                    restrictive_flags: &restrictive,
                    confinements,
                    current: true,
                }),
                route: None,
                now: NOW,
            },
            vec![],
        )
    };
    let token = claims(TokenKind::Tenant, &["personal_only"]);

    let denied = explain(
        &token,
        &confinements(json!({"tenant_type": "client", "region": "se"})),
    );
    let check = denied
        .checks
        .iter()
        .find(|check| check.check == "confinement")
        .unwrap();
    assert!(!check.passed);
    assert_eq!(
        check.message,
        "`personal_only` confines the session to tenants where `region` is one of `\"se\"`, \
         `\"no\"` and `tenant_type` is one of `\"personal\"`; the tenant fails on \
         `tenant_type` (`region` is `\"se\"`, `tenant_type` is `\"client\"`)."
    );
    assert!(!denied.allowed);
    assert_eq!(denied.decision, Some(confined()));

    let allowed = explain(
        &token,
        &confinements(json!({"tenant_type": "personal", "region": "no"})),
    );
    let check = allowed
        .checks
        .iter()
        .find(|check| check.check == "confinement")
        .unwrap();
    assert!(check.passed, "{}", check.message);
    assert!(
        check.message.contains("the tenant matches"),
        "{}",
        check.message
    );
    assert!(allowed.allowed);
    assert_eq!(allowed.decision, Some(Decision::allow()));

    let identity = claims(TokenKind::Identity, &["personal_only"]);
    let none = explain(&identity, &confinements(json!({})));
    let check = none
        .checks
        .iter()
        .find(|check| check.check == "confinement")
        .unwrap();
    assert!(!check.passed);
    assert!(
        check.message.ends_with("the decision is for no tenant."),
        "{}",
        check.message
    );

    // No check for sessions without a confined flag.
    let plain = explain(
        &claims(TokenKind::Tenant, &[]),
        &confinements(json!({"tenant_type": "client"})),
    );
    assert!(
        plain
            .checks
            .iter()
            .all(|check| check.check != "confinement")
    );
}
