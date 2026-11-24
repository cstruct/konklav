//! Deciding for a subject in a tenant without a token, from the cached
//! entitlement set, through the evaluator tokens use.

use std::collections::{BTreeMap, BTreeSet};

use konklav_authz::{
    Confinements, Decision, DenyReason, EntitlementSet, Entitlements, Requirements, Scope,
    ScopeRequirement, StepUp,
};
use konklav_core::{Cursor, SubjectId, TenantId};
use konklav_relying::{Config, Key, Need, Outcome, Relying};
use konklav_token::TokenKind;
use serde_json::json;

const T0: u64 = 1_800_000_000_000;

fn set(actions: &[&str]) -> BTreeSet<String> {
    actions.iter().map(|&action| action.to_owned()).collect()
}

fn project(id: &str) -> Scope {
    Scope {
        kind: "project".into(),
        id: id.into(),
    }
}

fn core(trusted: bool) -> Relying {
    let mut core = Relying::new(Config {
        issuer: "https://auth.example".into(),
        audiences: vec!["api".into()],
        ..Config::default()
    });
    if trusted {
        core.on_feed_connected(T0);
    }
    core
}

/// The set of a member holding `doc:read` tenant-wide and `doc:write` at
/// project p-1, in a tenant whose `plan` fact is `pro`.
fn entitlement_set(subject: SubjectId, tenant: TenantId) -> EntitlementSet {
    EntitlementSet {
        subject_id: subject,
        tenant_id: Some(tenant),
        revision: Cursor::new(1),
        entitlements: Entitlements {
            tenant: set(&["doc:read"]),
            scoped: BTreeMap::from([(project("p-1"), set(&["doc:write"]))]),
            ..Entitlements::default()
        },
        restrictive_flags: set(&["read_only"]),
        registered_kinds: BTreeSet::new(),
        confinements: Confinements {
            tenant_facts: BTreeMap::from([("plan".to_owned(), json!("pro"))]),
            ..Confinements::default()
        },
    }
}

/// A trusted core with the subject's set cached.
fn cached() -> (Relying, SubjectId, TenantId) {
    let (subject, tenant) = (SubjectId::new_v7(), TenantId::new_v7());
    let mut core = core(true);
    core.on_entitlements(entitlement_set(subject, tenant), T0);
    (core, subject, tenant)
}

fn tenant_wide(actions: &[&str]) -> Requirements {
    Requirements {
        tenant: set(actions),
        ..Requirements::default()
    }
}

fn at_project(id: &str, actions: &[&str]) -> Requirements {
    Requirements {
        scopes: vec![ScopeRequirement {
            tenant: None,
            kind: "project".into(),
            id: id.into(),
            actions: set(actions),
        }],
        ..Requirements::default()
    }
}

fn decided(outcome: Outcome) -> Decision {
    match outcome {
        Outcome::Decided { decision } => decision,
        Outcome::Need { needs } => panic!("needs {needs:?}"),
    }
}

fn denied(reason: DenyReason) -> Decision {
    Decision::Deny { reason }
}

// r[verify relying.decision.subject]
#[test]
fn a_subject_is_allowed_what_its_cached_set_grants() {
    let (mut core, subject, tenant) = cached();
    let decision =
        decided(core.decide_for_subject(subject, tenant, &tenant_wide(&["doc:read"]), T0));
    assert!(matches!(decision, Decision::Allow { .. }), "{decision:?}");
}

// r[verify relying.decision.subject]
#[test]
fn a_subject_is_denied_the_actions_its_set_lacks() {
    let (mut core, subject, tenant) = cached();
    assert_eq!(
        decided(core.decide_for_subject(
            subject,
            tenant,
            &tenant_wide(&["doc:read", "doc:delete"]),
            T0
        )),
        denied(DenyReason::MissingActions {
            actions: set(&["doc:delete"])
        })
    );
}

// r[verify relying.decision.subject]
#[test]
fn scope_bound_grants_hold_only_at_their_scope() {
    let (mut core, subject, tenant) = cached();
    let at_p1 =
        decided(core.decide_for_subject(subject, tenant, &at_project("p-1", &["doc:write"]), T0));
    assert!(matches!(at_p1, Decision::Allow { .. }), "{at_p1:?}");
    assert_eq!(
        decided(core.decide_for_subject(subject, tenant, &at_project("p-2", &["doc:write"]), T0)),
        denied(DenyReason::MissingActions {
            actions: set(&["doc:write"])
        })
    );
    assert_eq!(
        decided(core.decide_for_subject(subject, tenant, &tenant_wide(&["doc:write"]), T0)),
        denied(DenyReason::MissingActions {
            actions: set(&["doc:write"])
        }),
        "not tenant-wide"
    );
}

// r[verify relying.decision.subject]
#[test]
fn what_only_a_token_carries_is_unmet_and_denied() {
    let (mut core, subject, tenant) = cached();
    let mut decide = |requirements: Requirements| {
        decided(core.decide_for_subject(subject, tenant, &requirements, T0))
    };
    let step_up = Requirements {
        step_up: StepUp {
            min_methods: Some(1),
            ..StepUp::default()
        },
        ..tenant_wide(&["doc:read"])
    };
    assert_eq!(
        decide(step_up),
        denied(DenyReason::NoToken),
        "not a step-up"
    );
    let fresh = Requirements {
        step_up: StepUp {
            max_age_seconds: Some(3600),
            ..StepUp::default()
        },
        ..tenant_wide(&["doc:read"])
    };
    assert_eq!(decide(fresh), denied(DenyReason::NoToken));
    let flagged = Requirements {
        require_flags: set(&["hardware_key"]),
        ..tenant_wide(&["doc:read"])
    };
    assert_eq!(
        decide(flagged),
        denied(DenyReason::MissingFlag {
            flag: "hardware_key".into()
        })
    );
    let identity_only = Requirements {
        token_kinds: Some(BTreeSet::from([TokenKind::Identity])),
        ..Requirements::default()
    };
    assert_eq!(decide(identity_only), denied(DenyReason::TokenKind));
    // No session, so no restrictive flag to admit: admitting one changes
    // nothing.
    let admitting = Requirements {
        admit_flags: set(&["read_only"]),
        ..tenant_wide(&["doc:read"])
    };
    assert!(matches!(decide(admitting), Decision::Allow { .. }));
}

// r[verify relying.decision.subject]
#[test]
fn tenant_facts_are_decided_from_the_cached_set() {
    let (mut core, subject, tenant) = cached();
    let mut decide = |allowed: serde_json::Value| {
        let requirements = Requirements {
            tenant_facts: BTreeMap::from([("plan".to_owned(), vec![allowed])]),
            ..tenant_wide(&["doc:read"])
        };
        decided(core.decide_for_subject(subject, tenant, &requirements, T0))
    };
    assert!(matches!(decide(json!("pro")), Decision::Allow { .. }));
    assert_eq!(
        decide(json!("free")),
        denied(DenyReason::TenantFacts {
            fact: "plan".into()
        })
    );
}

// r[verify relying.decision.subject.fail-closed]
#[test]
fn untrusted_caches_decide_nothing() {
    let (subject, tenant) = (SubjectId::new_v7(), TenantId::new_v7());
    let mut core = core(false);
    core.on_entitlements(entitlement_set(subject, tenant), T0);
    assert_eq!(
        core.decide_for_subject(subject, tenant, &tenant_wide(&["doc:read"]), T0),
        Outcome::Need {
            needs: vec![Need::Check]
        },
        "the host must fail: the check API decides for tokens only"
    );
}

// r[verify relying.decision.subject]
#[test]
fn the_set_is_fetched_once_and_then_reused() {
    let (subject, tenant) = (SubjectId::new_v7(), TenantId::new_v7());
    let mut core = core(true);
    let requirements = tenant_wide(&["doc:read"]);
    let key = Key {
        subject,
        tenant: Some(tenant),
    };
    assert_eq!(
        core.decide_for_subject(subject, tenant, &requirements, T0),
        Outcome::Need {
            needs: vec![Need::Entitlements { key }]
        },
        "the same set tokens of the subject in the tenant use"
    );
    core.on_entitlements(entitlement_set(subject, tenant), T0);
    for later in [T0 + 1, T0 + 60_000] {
        // The feed's heartbeats keep the caches trusted.
        core.on_feed_activity(later);
        let decision = decided(core.decide_for_subject(subject, tenant, &requirements, later));
        assert!(matches!(decision, Decision::Allow { .. }), "{decision:?}");
    }
    // Once it expires, it is fetched again.
    let expired = T0 + Config::default().entitlement_ttl_ms + 1;
    core.on_feed_activity(expired);
    assert_eq!(
        core.decide_for_subject(subject, tenant, &requirements, expired),
        Outcome::Need {
            needs: vec![Need::Entitlements { key }]
        }
    );
}
