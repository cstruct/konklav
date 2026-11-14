use std::collections::{BTreeMap, BTreeSet};

use konklav_token::{AccessClaims, TokenKind};
use serde::{Deserialize, Serialize};

use crate::route_authority::vouched_by;
use crate::{
    Confinements, Entitlements, RegisteredScopes, Registration, RouteAuthority, Scope,
    failing_predicate,
};

/// Actions required at one scope. The relying system resolves its own
/// resources into scopes before asking, except registered scopes, which
/// it names alone.
// r[impl authz.resource-context.external]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
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
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
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
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
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
    /// Fact predicates the token's tenant must match: each tenant fact key
    /// with the values the fact may have, such as
    /// `{"tenant_type": ["client"]}`.
    // r[impl authz.decision.tenant-facts]
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "tenant_fact_predicates"
    )]
    pub tenant_facts: BTreeMap<String, Vec<serde_json::Value>>,
}

/// Reads tenant fact predicates, refusing a predicate without values and
/// values a predicate can't match. It doesn't consult the catalog, so the
/// check API and the relying core refuse the same requirements.
// r[impl authz.decision.tenant-facts.shape]
fn tenant_fact_predicates<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, Vec<serde_json::Value>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let predicates = BTreeMap::<String, Vec<serde_json::Value>>::deserialize(deserializer)?;
    for (key, allowed) in &predicates {
        if allowed.is_empty() {
            return Err(D::Error::custom(format!(
                "tenant_facts lists no value for `{key}`"
            )));
        }
        if let Some(value) = allowed.iter().find(|value| !is_matchable(value)) {
            return Err(D::Error::custom(format!(
                "tenant_facts lists `{value}` for `{key}`: only strings, integers and booleans can be matched"
            )));
        }
    }
    Ok(predicates)
}

fn is_matchable(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(_) | serde_json::Value::Bool(_) => true,
        serde_json::Value::Number(number) => number.is_i64() || number.is_u64(),
        _ => false,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    /// The token doesn't verify, or its session has ended or moved on.
    #[cfg_attr(feature = "openapi", schema(title = "DenyReasonInvalidToken"))]
    InvalidToken,
    /// The access token is sender-constrained and its DPoP proof is
    /// missing or invalid, or a bearer token came under the `DPoP` scheme.
    #[cfg_attr(feature = "openapi", schema(title = "DenyReasonInvalidDpopProof"))]
    InvalidDpopProof,
    #[cfg_attr(feature = "openapi", schema(title = "DenyReasonTokenKind"))]
    TokenKind,
    /// The session carries a restrictive flag the operation doesn't admit.
    #[cfg_attr(feature = "openapi", schema(title = "DenyReasonRestrictedSession"))]
    RestrictedSession { flag: String },
    /// The session carries a confined flag, and the token targets no tenant
    /// or one whose facts don't match the flag's confinement.
    #[cfg_attr(feature = "openapi", schema(title = "DenyReasonConfinedSession"))]
    ConfinedSession { flag: String },
    /// The token targets no tenant, or one whose facts fail the operation's
    /// tenant fact predicate on `fact`.
    #[cfg_attr(feature = "openapi", schema(title = "DenyReasonTenantFacts"))]
    TenantFacts { fact: String },
    /// The session lacks an assertive flag the operation requires.
    #[cfg_attr(feature = "openapi", schema(title = "DenyReasonMissingFlag"))]
    MissingFlag { flag: String },
    /// Tenant or scope requirements, but the token targets no tenant.
    #[cfg_attr(feature = "openapi", schema(title = "DenyReasonNoTenant"))]
    NoTenant,
    /// A required registered scope was never recorded, has been removed,
    /// or isn't in the tenant the requirement names.
    #[cfg_attr(feature = "openapi", schema(title = "DenyReasonUnknownScope"))]
    UnknownScope { kind: String, id: String },
    #[cfg_attr(feature = "openapi", schema(title = "DenyReasonMissingActions"))]
    MissingActions { actions: BTreeSet<String> },
}

/// A share's attributes, for the relying system to apply to an allowed
/// operation: Konklav doesn't interpret them.
// r[impl authz.share.attributes]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Obligation {
    pub share: konklav_core::ShareId,
    /// The owner tenant of the shared scope.
    pub tenant: konklav_core::TenantId,
    pub kind: String,
    pub id: String,
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub attributes: serde_json::Map<String, serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Decision {
    #[cfg_attr(feature = "openapi", schema(title = "DecisionAllow"))]
    Allow {
        /// One per share the decision relied on.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        obligations: Vec<Obligation>,
        /// What the allow vouches for, as route authority for the
        /// request's later decisions when it is a route decision. Empty
        /// for an allow made with route authority.
        // r[impl authz.decision.vouches]
        #[serde(default, skip_serializing_if = "RouteAuthority::is_empty")]
        vouches: RouteAuthority,
    },
    #[cfg_attr(feature = "openapi", schema(title = "DecisionDeny"))]
    Deny { reason: DenyReason },
    /// The caller may succeed after re-authenticating as described.
    #[cfg_attr(feature = "openapi", schema(title = "DecisionStepUp"))]
    StepUp { requirement: StepUp },
}

impl Decision {
    /// An allow without obligations.
    #[must_use]
    pub fn allow() -> Self {
        Self::Allow {
            obligations: Vec::new(),
            vouches: RouteAuthority::default(),
        }
    }
}

/// Evaluates `requirements` for a verified token whose session is known to
/// be current, given the restrictive flags declared in the catalog, the
/// confinements with the current facts of the token's tenant, the
/// entitlement set for the token's subject and tenant, and the records of
/// the registered scopes the requirements name.
///
/// `now` is in Unix seconds.
// r[impl session.flags.restrictive]
// r[impl session.flags.assertive]
// r[impl session.flags.confine.decision]
// r[impl authz.decision.tenant-facts]
// r[impl authn.step-up.demand]
// r[impl item.authz.single-evaluator]
#[must_use]
pub fn evaluate(
    requirements: &Requirements,
    claims: &AccessClaims,
    restrictive_flags: &BTreeSet<String>,
    confinements: &Confinements,
    entitlements: &Entitlements,
    registered: &RegisteredScopes,
    now: i64,
) -> Decision {
    evaluate_with_route_authority(
        requirements,
        None,
        claims,
        restrictive_flags,
        confinements,
        entitlements,
        registered,
        now,
    )
}

/// As [`evaluate`], made with `route_authority` when it is given: the
/// vouches of the request's allowed route decision. A required action it
/// covers counts as granted, whatever the entitlement set holds, and every
/// other check is made as without it. An allow made with route authority
/// vouches for nothing.
// r[impl authz.decision.route-authority]
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn evaluate_with_route_authority(
    requirements: &Requirements,
    route_authority: Option<&RouteAuthority>,
    claims: &AccessClaims,
    restrictive_flags: &BTreeSet<String>,
    confinements: &Confinements,
    entitlements: &Entitlements,
    registered: &RegisteredScopes,
    now: i64,
) -> Decision {
    let none = RouteAuthority::default();
    let authority = route_authority.unwrap_or(&none);
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
    // Before any action is considered, so global actions can't lift it.
    if let Some(flag) = confinements.violated(&claims.sfl, claims.tid.is_some()) {
        return Decision::Deny {
            reason: DenyReason::ConfinedSession {
                flag: flag.to_owned(),
            },
        };
    }
    for flag in &requirements.require_flags {
        if !claims.sfl.contains(flag) {
            return Decision::Deny {
                reason: DenyReason::MissingFlag { flag: flag.clone() },
            };
        }
    }

    // Before step-up, which can't help, and before any action is
    // considered, so global actions can't lift it.
    if let Some(fact) = failing_tenant_fact(requirements, confinements, claims) {
        return Decision::Deny {
            reason: DenyReason::TenantFacts {
                fact: fact.to_owned(),
            },
        };
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
            .filter(|a| !global.contains(a.as_str()) && !authority.covers_global(a))
            .cloned(),
    );
    let tenant = entitlements.actions_at(None);
    missing.extend(
        requirements
            .tenant
            .iter()
            .filter(|a| !tenant.contains(a.as_str()) && !authority.covers_tenant(a))
            .cloned(),
    );
    let obligations = match scope_actions(
        requirements,
        authority,
        claims,
        entitlements,
        registered,
        now,
    ) {
        Ok((absent, obligations)) => {
            missing.extend(absent);
            obligations
        }
        Err(reason) => return Decision::Deny { reason },
    };
    if missing.is_empty() {
        let vouches = if route_authority.is_some() {
            RouteAuthority::default()
        } else {
            vouched_by(requirements, claims.tid, entitlements, registered)
        };
        Decision::Allow {
            obligations,
            vouches,
        }
    } else {
        Decision::Deny {
            reason: DenyReason::MissingActions { actions: missing },
        }
    }
}

/// The actions required at scopes that aren't granted or covered by
/// `authority`, and the obligations of the shares that grant the others; a
/// deny reason for an unknown registered scope.
fn scope_actions(
    requirements: &Requirements,
    authority: &RouteAuthority,
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
        let (granted, relied, record, owned) = if let Some(record) = registered.lookup(&scope) {
            let Some(record) = record
                .filter(|record| required.tenant.is_none_or(|tenant| tenant == record.tenant))
            else {
                return Err(DenyReason::UnknownScope {
                    kind: scope.kind,
                    id: scope.id,
                });
            };
            let (granted, relied) =
                registered_actions(entitlements, claims, record, &required.actions, now);
            let owned = claims.tid == Some(record.tenant);
            (granted, relied, Some(record), owned)
        } else if let Some(owner) = required.tenant.filter(|owner| Some(*owner) != claims.tid) {
            let (granted, relied) =
                shared_actions(entitlements, owner, &scope, &required.actions, now);
            (granted, relied, None, false)
        } else {
            let owned = claims.tid.is_some();
            (
                entitlements.actions_at(Some(&scope)),
                Vec::new(),
                None,
                owned,
            )
        };
        missing.extend(
            required
                .actions
                .iter()
                .filter(|a| {
                    !granted.contains(a.as_str())
                        && !authority.covers_scope(a, &scope, record, owned)
                })
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

/// The first tenant fact predicate (by key) the token's tenant fails, given
/// its current facts; the first predicate when the token targets no tenant.
// r[impl authz.decision.tenant-facts.reason]
pub(crate) fn failing_tenant_fact<'a>(
    requirements: &'a Requirements,
    confinements: &Confinements,
    claims: &AccessClaims,
) -> Option<&'a str> {
    if claims.tid.is_none() {
        return requirements.tenant_facts.keys().next().map(String::as_str);
    }
    failing_predicate(&requirements.tenant_facts, &confinements.tenant_facts)
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
