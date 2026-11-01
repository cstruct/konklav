use std::collections::BTreeSet;

use konklav_token::{AccessClaims, TokenKind};
use serde::{Deserialize, Serialize};

use crate::{Entitlements, RegisteredScopes, Registration, Scope};

/// Actions required at one scope. The relying system resolves its own
/// resources into scopes before asking, except registered scopes, which
/// it names alone.
// r[impl authz.resource-context.external]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeRequirement {
    /// The tenant that owns the scope, when it isn't the token's: then only
    /// shares of the scope with the token's tenant satisfy it.
    // r[impl authz.share.requirements]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<konklav_core::TenantId>,
    pub kind: String,
    pub id: String,
    pub actions: BTreeSet<String>,
}

/// Stronger or fresher authentication an operation needs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepUp {
    /// At least this many distinct authentication methods.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_methods: Option<usize>,
    /// Methods that count towards `min_methods`; any method when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_methods: Option<BTreeSet<String>>,
    /// The last authentication must be at most this old.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age_seconds: Option<i64>,
}

impl StepUp {
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// What an operation demands of the caller.
// r[impl relying.decision.requirements]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Requirements {
    /// Accepted token kinds; `tenant` only when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_kinds: Option<BTreeSet<TokenKind>>,
    /// Actions required globally (independent of any tenant).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub global: BTreeSet<String>,
    /// Actions required tenant-wide in the token's tenant.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub tenant: BTreeSet<String>,
    /// Actions required at scopes of the token's tenant.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<ScopeRequirement>,
    /// Restrictive session flags this operation tolerates.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub admit_flags: BTreeSet<String>,
    /// Assertive session flags this operation needs.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub require_flags: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "StepUp::is_empty")]
    pub step_up: StepUp,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    /// The token doesn't verify, or its session has ended or moved on.
    InvalidToken,
    TokenKind,
    /// The session carries a restrictive flag the operation doesn't admit.
    RestrictedSession {
        flag: String,
    },
    /// The session lacks an assertive flag the operation requires.
    MissingFlag {
        flag: String,
    },
    /// Tenant or scope requirements, but the token targets no tenant.
    NoTenant,
    /// A required registered scope was never recorded, has been removed,
    /// or isn't in the tenant the requirement names.
    UnknownScope {
        kind: String,
        id: String,
    },
    MissingActions {
        actions: BTreeSet<String>,
    },
}

/// A share's attributes, for the relying system to apply to an allowed
/// operation: Konklav doesn't interpret them.
// r[impl authz.share.attributes]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Obligation {
    pub share: konklav_core::ShareId,
    /// The owner tenant of the shared scope.
    pub tenant: konklav_core::TenantId,
    pub kind: String,
    pub id: String,
    pub attributes: serde_json::Map<String, serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Decision {
    Allow {
        /// One per share the decision relied on.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        obligations: Vec<Obligation>,
    },
    Deny {
        reason: DenyReason,
    },
    /// The caller may succeed after re-authenticating as described.
    StepUp {
        requirement: StepUp,
    },
}

impl Decision {
    /// An allow without obligations.
    #[must_use]
    pub fn allow() -> Self {
        Self::Allow {
            obligations: Vec::new(),
        }
    }
}

/// Evaluates `requirements` for a verified token whose session is known to
/// be current, given the restrictive flags declared in the catalog, the
/// entitlement set for the token's subject and tenant, and the records of
/// the registered scopes the requirements name.
///
/// `now` is in Unix seconds.
// r[impl session.flags.restrictive]
// r[impl session.flags.assertive]
// r[impl authn.step-up.demand]
// r[impl item.authz.single-evaluator]
#[must_use]
pub fn evaluate(
    requirements: &Requirements,
    claims: &AccessClaims,
    restrictive_flags: &BTreeSet<String>,
    entitlements: &Entitlements,
    registered: &RegisteredScopes,
    now: i64,
) -> Decision {
    let accepted = requirements
        .token_kinds
        .clone()
        .unwrap_or_else(|| BTreeSet::from([TokenKind::Tenant]));
    if !accepted.contains(&claims.knd) {
        return Decision::Deny {
            reason: DenyReason::TokenKind,
        };
    }

    for flag in &claims.sfl {
        if restrictive_flags.contains(flag) && !requirements.admit_flags.contains(flag) {
            return Decision::Deny {
                reason: DenyReason::RestrictedSession { flag: flag.clone() },
            };
        }
    }
    for flag in &requirements.require_flags {
        if !claims.sfl.contains(flag) {
            return Decision::Deny {
                reason: DenyReason::MissingFlag { flag: flag.clone() },
            };
        }
    }

    if !step_up_satisfied(&requirements.step_up, claims, now) {
        return Decision::StepUp {
            requirement: requirements.step_up.clone(),
        };
    }

    let unregistered_scopes = requirements
        .scopes
        .iter()
        .any(|required| !registered.kinds.contains(&required.kind));
    if (!requirements.tenant.is_empty() || unregistered_scopes) && claims.tid.is_none() {
        return Decision::Deny {
            reason: DenyReason::NoTenant,
        };
    }

    let mut missing = BTreeSet::new();
    let global: BTreeSet<&str> = entitlements.global.iter().map(String::as_str).collect();
    missing.extend(
        requirements
            .global
            .iter()
            .filter(|a| !global.contains(a.as_str()))
            .cloned(),
    );
    let tenant = entitlements.actions_at(None);
    missing.extend(
        requirements
            .tenant
            .iter()
            .filter(|a| !tenant.contains(a.as_str()))
            .cloned(),
    );
    let obligations = match scope_actions(requirements, claims, entitlements, registered, now) {
        Ok((absent, obligations)) => {
            missing.extend(absent);
            obligations
        }
        Err(reason) => return Decision::Deny { reason },
    };
    if missing.is_empty() {
        Decision::Allow { obligations }
    } else {
        Decision::Deny {
            reason: DenyReason::MissingActions { actions: missing },
        }
    }
}

/// The actions required at scopes that aren't granted, and the obligations
/// of the shares that grant the others; a deny reason for an unknown
/// registered scope.
fn scope_actions(
    requirements: &Requirements,
    claims: &AccessClaims,
    entitlements: &Entitlements,
    registered: &RegisteredScopes,
    now: i64,
) -> Result<(BTreeSet<String>, Vec<Obligation>), DenyReason> {
    let mut missing = BTreeSet::new();
    let mut obligations = Vec::new();
    for required in &requirements.scopes {
        let scope = Scope {
            kind: required.kind.clone(),
            id: required.id.clone(),
        };
        let (granted, relied) = if let Some(record) = registered.lookup(&scope) {
            let Some(record) = record
                .filter(|record| required.tenant.is_none_or(|tenant| tenant == record.tenant))
            else {
                return Err(DenyReason::UnknownScope {
                    kind: scope.kind,
                    id: scope.id,
                });
            };
            registered_actions(entitlements, claims, record, &required.actions, now)
        } else if let Some(owner) = required.tenant.filter(|owner| Some(*owner) != claims.tid) {
            shared_actions(entitlements, owner, &scope, &required.actions, now)
        } else {
            (entitlements.actions_at(Some(&scope)), Vec::new())
        };
        missing.extend(
            required
                .actions
                .iter()
                .filter(|a| !granted.contains(a.as_str()))
                .cloned(),
        );
        obligations.extend(relied);
    }
    Ok((missing, obligations))
}

/// The actions granted at a registered scope: in its own tenant, the
/// global and tenant-wide actions and those at the scope or any one of its
/// containers; from another tenant, global actions and what shares of the
/// scope or of a container grant at `now`, with their obligations. Without
/// a tenant, only global actions.
// r[impl authz.registered.evaluation]
// r[impl authz.registered.shares]
// r[impl authz.registered.no-tenant]
fn registered_actions<'a>(
    entitlements: &'a Entitlements,
    claims: &AccessClaims,
    record: &Registration,
    required: &BTreeSet<String>,
    now: i64,
) -> (BTreeSet<&'a str>, Vec<Obligation>) {
    let mut granted: BTreeSet<&str> = entitlements.global.iter().map(String::as_str).collect();
    let mut obligations = Vec::new();
    let Some(tenant) = claims.tid else {
        return (granted, obligations);
    };
    let scopes = std::iter::once(record.scope()).chain(record.containers.iter().cloned());
    if tenant == record.tenant {
        for scope in scopes {
            granted.extend(entitlements.actions_at(Some(&scope)));
        }
    } else {
        for scope in scopes {
            let (shared, relied) =
                shared_actions(entitlements, record.tenant, &scope, required, now);
            granted.extend(shared);
            obligations.extend(relied);
        }
    }
    (granted, obligations)
}

/// The actions shares of `owner`'s scope grant at `now`, and an obligation
/// for each share that grants a required action.
fn shared_actions<'a>(
    entitlements: &'a Entitlements,
    owner: konklav_core::TenantId,
    scope: &Scope,
    required: &BTreeSet<String>,
    now: i64,
) -> (BTreeSet<&'a str>, Vec<Obligation>) {
    let mut granted = BTreeSet::new();
    let mut obligations = Vec::new();
    for shared in entitlements.shared.iter().filter(|shared| {
        shared.owner_tenant == owner
            && shared.kind == scope.kind
            && shared.id == scope.id
            && shared.valid_at(now)
    }) {
        granted.extend(shared.actions.iter().map(String::as_str));
        if shared.actions.iter().any(|a| required.contains(a)) {
            obligations.push(Obligation {
                share: shared.share,
                tenant: owner,
                kind: shared.kind.clone(),
                id: shared.id.clone(),
                attributes: shared.attributes.clone(),
            });
        }
    }
    (granted, obligations)
}

pub(crate) fn step_up_satisfied(step_up: &StepUp, claims: &AccessClaims, now: i64) -> bool {
    let counted = claims
        .amr
        .iter()
        .filter(|method| {
            step_up
                .allowed_methods
                .as_ref()
                .is_none_or(|allowed| allowed.contains(*method))
        })
        .collect::<BTreeSet<_>>()
        .len();
    let enough = step_up.min_methods.is_none_or(|min| counted >= min);
    let fresh = step_up
        .max_age_seconds
        .is_none_or(|max_age| now - claims.auth_time <= max_age);
    enough && fresh
}
