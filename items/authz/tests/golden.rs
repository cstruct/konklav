//! Golden cases pinning compilation to the semantics of the authorization
//! model Konklav replaces: a ranked view of role, template and global
//! policies followed by per-level deny subtraction.

use std::collections::{BTreeMap, BTreeSet};

use konklav_authz::{
    Assignment, Catalog, Effect, Entitlements, Group, Level, Policy, Scope, compile,
};

fn catalog() -> Catalog {
    let actions = [
        "project:read",
        "document:write",
        "document:read",
        "role:list",
        "me",
        "sys:tenant:create",
        "sys:user:list",
    ];
    Catalog {
        actions: actions.iter().map(|a| (*a).to_owned()).collect(),
        groups: BTreeMap::from([
            (
                "tenant:all".to_owned(),
                Group::AllExceptPrefixes(vec!["sys:".into()]),
            ),
            ("sys:all".to_owned(), Group::AllExceptPrefixes(vec![])),
        ]),
    }
}

fn allow(action: &str) -> Policy {
    Policy {
        action: action.into(),
        effect: Effect::Allow,
        scope_bound: false,
    }
}

fn deny(action: &str) -> Policy {
    Policy {
        action: action.into(),
        effect: Effect::Deny,
        scope_bound: false,
    }
}

fn scoped(mut policy: Policy) -> Policy {
    policy.scope_bound = true;
    policy
}

fn project(id: &str) -> Scope {
    Scope {
        kind: "project".into(),
        id: id.into(),
    }
}

fn role(level: Level, priority: i32, policies: Vec<Policy>) -> Assignment {
    Assignment {
        label: format!("role at priority {priority}"),
        level,
        priority,
        template_policies: vec![],
        role_policies: policies,
    }
}

fn set(actions: &[&str]) -> BTreeSet<String> {
    actions.iter().map(|a| (*a).to_owned()).collect()
}

// r[verify authz.compile.precedence]
// r[verify authz.compile.reference-semantics]
#[test]
fn at_equal_priority_deny_wins() {
    let compiled = compile(
        &catalog(),
        &[
            role(
                Level::Global,
                0,
                vec![allow("project:read"), allow("document:write")],
            ),
            role(Level::Global, 0, vec![deny("document:write")]),
        ],
    );
    assert_eq!(compiled.global, set(&["project:read"]));
}

#[test]
fn a_higher_priority_allow_beats_a_lower_priority_deny() {
    let compiled = compile(
        &catalog(),
        &[
            role(Level::Tenant, 1, vec![deny("document:write")]),
            role(Level::Tenant, 10, vec![allow("document:write")]),
        ],
    );
    assert_eq!(compiled.tenant, set(&["document:write"]));
}

#[test]
fn a_higher_priority_deny_beats_a_lower_priority_allow() {
    let compiled = compile(
        &catalog(),
        &[
            role(Level::Tenant, 10, vec![deny("document:write")]),
            role(
                Level::Tenant,
                1,
                vec![allow("document:write"), allow("project:read")],
            ),
        ],
    );
    assert_eq!(compiled.tenant, set(&["project:read"]));
}

// r[verify authz.compile.allows-only]
// r[verify authz.compile.deny-level]
#[test]
fn denies_only_cancel_allows_at_their_own_level() {
    let p1 = project("p1");
    let compiled = compile(
        &catalog(),
        &[
            role(Level::Global, 0, vec![deny("project:read")]),
            role(
                Level::Tenant,
                5,
                vec![allow("project:read"), deny("document:write")],
            ),
            role(
                Level::Scope(p1.clone()),
                1,
                vec![scoped(allow("document:write"))],
            ),
        ],
    );
    assert_eq!(
        compiled.global,
        set(&[]),
        "a global deny leaves no global allow"
    );
    assert_eq!(
        compiled.tenant,
        set(&["project:read"]),
        "a global deny doesn't reach the tenant level"
    );
    assert_eq!(
        compiled.scoped.get(&p1),
        Some(&set(&["document:write"])),
        "a tenant-wide deny doesn't reach a scope"
    );
}

// r[verify authz.policy.scope-bound]
#[test]
fn only_scope_bound_policies_stay_at_the_scope() {
    let p1 = project("p1");
    let compiled = compile(
        &catalog(),
        &[role(
            Level::Scope(p1.clone()),
            0,
            vec![scoped(allow("document:read")), allow("role:list")],
        )],
    );
    assert_eq!(compiled.tenant, set(&["role:list"]));
    assert_eq!(compiled.scoped.get(&p1), Some(&set(&["document:read"])));
}

#[test]
fn scope_bound_policies_of_tenant_wide_assignments_apply_tenant_wide() {
    let compiled = compile(
        &catalog(),
        &[role(Level::Tenant, 0, vec![scoped(allow("document:read"))])],
    );
    assert_eq!(compiled.tenant, set(&["document:read"]));
}

// r[verify authz.compile.subsumption]
#[test]
fn higher_levels_subsume_lower_ones() {
    let p1 = project("p1");
    let compiled = compile(
        &catalog(),
        &[
            role(Level::Global, 0, vec![allow("me")]),
            role(Level::Tenant, 0, vec![allow("me"), allow("project:read")]),
            role(
                Level::Scope(p1.clone()),
                0,
                vec![scoped(allow("project:read")), scoped(allow("me"))],
            ),
        ],
    );
    assert_eq!(compiled.global, set(&["me"]));
    assert_eq!(compiled.tenant, set(&["project:read"]));
    assert!(
        !compiled.scoped.contains_key(&p1),
        "nothing left at the scope"
    );
}

// r[verify authz.role.from-template]
#[test]
fn role_policies_replace_template_policies_for_the_same_action() {
    let assignment = Assignment {
        label: String::new(),
        level: Level::Tenant,
        priority: 0,
        template_policies: vec![allow("project:read"), allow("document:write")],
        role_policies: vec![deny("document:write")],
    };
    assert_eq!(
        compile(&catalog(), &[assignment]).tenant,
        set(&["project:read"])
    );
}

#[test]
fn overrides_match_the_unexpanded_name() {
    // A role denying one action doesn't replace the template's group: both
    // apply, and the deny wins only on its action at equal priority.
    let assignment = Assignment {
        label: String::new(),
        level: Level::Tenant,
        priority: 0,
        template_policies: vec![allow("tenant:all")],
        role_policies: vec![deny("document:read")],
    };
    let tenant = compile(&catalog(), &[assignment]).tenant;
    assert!(tenant.contains("project:read"));
    assert!(!tenant.contains("document:read"));
}

// r[verify authz.catalog.groups]
#[test]
fn groups_expand_to_their_members_and_their_own_name() {
    let compiled = compile(
        &catalog(),
        &[
            role(Level::Tenant, 0, vec![allow("tenant:all")]),
            role(Level::Global, 0, vec![allow("sys:all")]),
        ],
    );
    assert!(
        compiled.global.contains("sys:all"),
        "routes may require the group itself"
    );
    assert!(compiled.global.contains("sys:user:list"));
    assert!(compiled.global.contains("tenant:all"));
    assert_eq!(
        compiled.tenant,
        set(&[]),
        "all subsumed by the global sys:all"
    );

    let tenant_only = compile(
        &catalog(),
        &[role(Level::Tenant, 0, vec![allow("tenant:all")])],
    );
    assert!(tenant_only.tenant.contains("document:write"));
    assert!(tenant_only.tenant.contains("tenant:all"));
    assert!(!tenant_only.tenant.iter().any(|a| a.starts_with("sys:")));
}

#[test]
fn no_assignments_mean_no_entitlements() {
    assert_eq!(compile(&catalog(), &[]), Entitlements::default());
}

#[test]
fn entitlements_round_trip_through_json() {
    let compiled = compile(
        &catalog(),
        &[role(
            Level::Scope(project("p1")),
            0,
            vec![scoped(allow("document:read"))],
        )],
    );
    let json = serde_json_like(&compiled);
    assert!(json.contains("\"kind\":\"project\""), "{json}");
}

fn serde_json_like(entitlements: &Entitlements) -> String {
    serde_json::to_string(entitlements).unwrap()
}

// r[verify authz.explain]
#[test]
fn explanations_name_every_contributing_policy() {
    use konklav_authz::explain;
    let p1 = project("p1");
    let assignments = [
        role(Level::Tenant, 1, vec![allow("tenant:all")]),
        role(Level::Tenant, 5, vec![deny("document:read")]),
        role(Level::Scope(p1), 0, vec![scoped(allow("document:read"))]),
    ];
    let explanation = explain(&catalog(), &assignments, "document:read");
    assert_eq!(explanation.contributions.len(), 3);
    assert_eq!(
        explanation.contributions[0].policy, "tenant:all",
        "named as written"
    );
    assert_eq!(explanation.contributions[1].effect, Effect::Deny);
    assert_eq!(explanation.contributions[2].level, "project/p1");
    assert_eq!(
        explanation.granted_at,
        vec!["project/p1"],
        "the tenant-wide deny wins tenant-wide only"
    );
}
