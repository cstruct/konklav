use std::collections::{BTreeMap, BTreeSet};

use crate::{Assignment, Catalog, Effect, Entitlements, Level, Scope, Share, Shared};

/// Where a policy lands once its assignment and scope binding are known.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Placement {
    Global,
    Tenant,
    Scope(Scope),
}

/// Compiles active assignments into an entitlement set.
///
/// 1. A role's own policy replaces its template's policy for the same
///    action (before expansion).
/// 2. Policies land globally (global roles), tenant-wide (tenant-wide
///    assignments, or policies that aren't scope-bound), or at the
///    assignment's scope (scope-bound policies of scoped assignments).
/// 3. Action groups expand to their members and their own name.
/// 4. Per placement and action, the policy from the highest-priority role
///    wins; at equal priority, deny wins.
/// 5. Denies are removed. A deny only cancels allows at its own placement:
///    a tenant-wide deny does not remove an allow at a scope.
/// 6. Actions granted globally are dropped from the tenant level, and
///    actions granted globally or tenant-wide are dropped from scopes.
// r[impl authz.compile.entitlements]
// r[impl authz.compile.reference-semantics]
// r[impl authz.compile.precedence]
// r[impl authz.compile.allows-only]
// r[impl authz.compile.deny-level]
// r[impl authz.compile.subsumption]
// r[impl authz.role.from-template]
// r[impl authz.policy.scope-bound]
#[must_use]
pub fn compile(catalog: &Catalog, assignments: &[Assignment]) -> Entitlements {
    // (placement, action) -> (priority, effect) of the winning policy.
    let mut winners: BTreeMap<(Placement, String), (i32, Effect)> = BTreeMap::new();

    for assignment in assignments {
        let overridden: BTreeSet<&str> = assignment
            .role_policies
            .iter()
            .map(|policy| policy.action.as_str())
            .collect();
        let effective = assignment.role_policies.iter().chain(
            assignment
                .template_policies
                .iter()
                .filter(|policy| !overridden.contains(policy.action.as_str())),
        );
        for policy in effective {
            let placement = match (&assignment.level, policy.scope_bound) {
                (Level::Global, _) => Placement::Global,
                (Level::Scope(scope), true) => Placement::Scope(scope.clone()),
                (Level::Tenant | Level::Scope(_), _) => Placement::Tenant,
            };
            for action in catalog.expand(&policy.action) {
                let candidate = (assignment.priority, policy.effect);
                winners
                    .entry((placement.clone(), action))
                    .and_modify(|winner| {
                        if beats(candidate, *winner) {
                            *winner = candidate;
                        }
                    })
                    .or_insert(candidate);
            }
        }
    }

    let mut entitlements = Entitlements::default();
    for ((placement, action), (_, effect)) in winners {
        if effect == Effect::Deny {
            continue;
        }
        match placement {
            Placement::Global => {
                entitlements.global.insert(action);
            }
            Placement::Tenant => {
                entitlements.tenant.insert(action);
            }
            Placement::Scope(scope) => {
                entitlements.scoped.entry(scope).or_default().insert(action);
            }
        }
    }
    let global = entitlements.global.clone();
    entitlements
        .tenant
        .retain(|action| !global.contains(action));
    let above: BTreeSet<String> = global.union(&entitlements.tenant).cloned().collect();
    for actions in entitlements.scoped.values_mut() {
        actions.retain(|action| !above.contains(action));
    }
    entitlements.scoped.retain(|_, actions| !actions.is_empty());
    entitlements
}

/// What `shares` grant on top of compiled `entitlements`: for each share,
/// its actions (groups expanded) that the subject holds at the recipient,
/// tenant-wide or at the share's recipient scope. Shares granting nothing
/// are left out.
// r[impl authz.share.ceiling]
#[must_use]
pub fn shared(catalog: &Catalog, entitlements: &Entitlements, shares: &[Share]) -> Vec<Shared> {
    shares
        .iter()
        .filter_map(|share| {
            let held = entitlements.actions_at(share.recipient_scope.as_ref());
            let actions: BTreeSet<String> = share
                .actions
                .iter()
                .flat_map(|action| catalog.expand(action))
                .filter(|action| held.contains(action.as_str()))
                .collect();
            (!actions.is_empty()).then(|| Shared {
                share: share.id,
                owner_tenant: share.owner_tenant,
                kind: share.scope.kind.clone(),
                id: share.scope.id.clone(),
                actions,
                attributes: share.attributes.clone(),
                valid_from: share.valid_from,
                valid_until: share.valid_until,
            })
        })
        .collect()
}

/// Higher priority wins; at equal priority, deny wins.
fn beats(candidate: (i32, Effect), current: (i32, Effect)) -> bool {
    candidate.0 > current.0 || (candidate.0 == current.0 && candidate.1 == Effect::Deny)
}

/// One policy that bears on an action, and where it lands.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Contribution {
    pub assignment: String,
    /// `global`, `tenant`, or `<scope kind>/<scope id>`.
    pub level: String,
    /// The policy's action or group, as written.
    pub policy: String,
    pub effect: crate::Effect,
    pub priority: i32,
    pub from_template: bool,
}

/// Why a subject has (or lacks) an action.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Explanation {
    pub action: String,
    pub contributions: Vec<Contribution>,
    /// The levels where the action ends up granted.
    pub granted_at: Vec<String>,
}

fn level_name(placement: &Placement) -> String {
    match placement {
        Placement::Global => "global".into(),
        Placement::Tenant => "tenant".into(),
        Placement::Scope(scope) => format!("{}/{}", scope.kind, scope.id),
    }
}

/// Explains `action`: every effective policy whose expansion includes it,
/// with its placement, and where the compiled set grants it.
// r[impl authz.explain]
#[must_use]
pub fn explain(catalog: &Catalog, assignments: &[Assignment], action: &str) -> Explanation {
    let mut contributions = Vec::new();
    for assignment in assignments {
        let overridden: BTreeSet<&str> = assignment
            .role_policies
            .iter()
            .map(|p| p.action.as_str())
            .collect();
        let role = assignment.role_policies.iter().map(|p| (p, false));
        let template = assignment
            .template_policies
            .iter()
            .filter(|p| !overridden.contains(p.action.as_str()))
            .map(|p| (p, true));
        for (policy, from_template) in role.chain(template) {
            if !catalog.expand(&policy.action).contains(action) {
                continue;
            }
            let placement = match (&assignment.level, policy.scope_bound) {
                (Level::Global, _) => Placement::Global,
                (Level::Scope(scope), true) => Placement::Scope(scope.clone()),
                (Level::Tenant | Level::Scope(_), _) => Placement::Tenant,
            };
            contributions.push(Contribution {
                assignment: assignment.label.clone(),
                level: level_name(&placement),
                policy: policy.action.clone(),
                effect: policy.effect,
                priority: assignment.priority,
                from_template,
            });
        }
    }
    let compiled = compile(catalog, assignments);
    let mut granted_at = Vec::new();
    if compiled.global.contains(action) {
        granted_at.push("global".to_owned());
    }
    if compiled.tenant.contains(action) {
        granted_at.push("tenant".to_owned());
    }
    for (scope, actions) in &compiled.scoped {
        if actions.contains(action) {
            granted_at.push(format!("{}/{}", scope.kind, scope.id));
        }
    }
    Explanation {
        action: action.to_owned(),
        contributions,
        granted_at,
    }
}
