use std::collections::BTreeSet;

use conclave_token::{AccessClaims, TokenKind};
use serde::{Deserialize, Serialize};

use crate::{Entitlements, Scope};

/// Actions required at one scope. The relying system resolves its own
/// resources into scopes before asking.
// r[impl authz.resource-context.external]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeRequirement {
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
    MissingActions {
        actions: BTreeSet<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny {
        reason: DenyReason,
    },
    /// The caller may succeed after re-authenticating as described.
    StepUp {
        requirement: StepUp,
    },
}

/// Evaluates `requirements` for a verified token whose session is known to
/// be current, given the restrictive flags declared in the catalog and the
/// entitlement set for the token's subject and tenant.
///
/// `now` is in Unix seconds.
// r[impl session.flags.restrictive]
// r[impl session.flags.assertive]
// r[impl authn.step-up.demand]
#[must_use]
pub fn evaluate(
    requirements: &Requirements,
    claims: &AccessClaims,
    restrictive_flags: &BTreeSet<String>,
    entitlements: &Entitlements,
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

    if (!requirements.tenant.is_empty() || !requirements.scopes.is_empty()) && claims.tid.is_none()
    {
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
    for required in &requirements.scopes {
        let scope = Scope {
            kind: required.kind.clone(),
            id: required.id.clone(),
        };
        let granted = entitlements.actions_at(Some(&scope));
        missing.extend(
            required
                .actions
                .iter()
                .filter(|a| !granted.contains(a.as_str()))
                .cloned(),
        );
    }
    if missing.is_empty() {
        Decision::Allow
    } else {
        Decision::Deny {
            reason: DenyReason::MissingActions { actions: missing },
        }
    }
}

fn step_up_satisfied(step_up: &StepUp, claims: &AccessClaims, now: i64) -> bool {
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
