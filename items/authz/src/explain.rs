//! Explaining entitlements and decisions: which policies bear on an action,
//! and why a decision allows or denies, in words and as data.
//!
//! Explaining never decides. [`explain_decision`] reports the decision
//! [`evaluate`] reaches, and its reasons are computed to agree with it.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use konklav_core::{ShareId, TenantId};
use konklav_token::{AccessClaims, TokenKind};
use serde::{Deserialize, Serialize};

use crate::compile::{Placement, beats, effective_policies};
use crate::evaluate::step_up_satisfied;
use crate::{
    Assignment, Catalog, Confinements, Decision, DenyReason, Effect, Entitlements,
    RegisteredScopes, Registration, Requirements, Scope, Share, compile, evaluate, shared,
};

/// One policy that bears on an action, and where it lands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
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

impl Contribution {
    /// Such as "`editor (0193…)` allows `document:*` at project/p1
    /// (priority 5, from its template)".
    fn describe(&self) -> String {
        let verb = match self.effect {
            Effect::Allow => "allows",
            Effect::Deny => "denies",
        };
        let template = if self.from_template {
            ", from its template"
        } else {
            ""
        };
        format!(
            "`{}` {verb} `{}` at {} (priority {}{template})",
            self.assignment, self.policy, self.level, self.priority
        )
    }
}

/// Why a subject has (or lacks) an action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Explanation {
    pub action: String,
    pub contributions: Vec<Contribution>,
    /// The levels where the action ends up granted.
    pub granted_at: Vec<String>,
}

/// Every effective policy whose expansion includes `action`, with where it
/// lands.
fn contributions(
    catalog: &Catalog,
    assignments: &[Assignment],
    action: &str,
) -> Vec<(Placement, Contribution)> {
    let mut found = Vec::new();
    for assignment in assignments {
        for (policy, from_template) in effective_policies(assignment) {
            if !catalog.expand(&policy.action).contains(action) {
                continue;
            }
            let placement = Placement::of(&assignment.level, policy.scope_bound);
            let contribution = Contribution {
                assignment: assignment.label.clone(),
                level: placement.name(),
                policy: policy.action.clone(),
                effect: policy.effect,
                priority: assignment.priority,
                from_template,
            };
            found.push((placement, contribution));
        }
    }
    found
}

/// The levels where the compiled set grants `action`.
fn granted_at(compiled: &Entitlements, action: &str) -> Vec<String> {
    let mut levels = Vec::new();
    if compiled.global.contains(action) {
        levels.push("global".to_owned());
    }
    if compiled.tenant.contains(action) {
        levels.push("tenant".to_owned());
    }
    for (scope, actions) in &compiled.scoped {
        if actions.contains(action) {
            levels.push(format!("{}/{}", scope.kind, scope.id));
        }
    }
    levels
}

/// Explains `action`: every effective policy whose expansion includes it,
/// with its placement, and where the compiled set grants it.
// r[impl authz.explain]
#[must_use]
pub fn explain(catalog: &Catalog, assignments: &[Assignment], action: &str) -> Explanation {
    Explanation {
        action: action.to_owned(),
        contributions: contributions(catalog, assignments, action)
            .into_iter()
            .map(|(_, contribution)| contribution)
            .collect(),
        granted_at: granted_at(&compile(catalog, assignments), action),
    }
}

/// One check a decision makes besides the required actions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Check {
    /// Such as `subject_active`, `token_kind` or `step_up`.
    pub check: String,
    pub passed: bool,
    pub message: String,
}

impl Check {
    #[must_use]
    pub fn new(check: &str, passed: bool, message: impl Into<String>) -> Self {
        Self {
            check: check.to_owned(),
            passed,
            message: message.into(),
        }
    }
}

/// Why a required action is granted or not.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Reason {
    /// A policy allows it at a level that counts, and wins there.
    #[cfg_attr(feature = "openapi", schema(title = "ReasonAllowed"))]
    Allowed {
        by: Contribution,
        /// Denies that don't cancel it: outranked where it wins, or at other
        /// levels.
        ineffective: Vec<Contribution>,
    },
    /// No level that counts grants it, and a deny wins at one of them.
    #[cfg_attr(feature = "openapi", schema(title = "ReasonDenied"))]
    Denied {
        by: Contribution,
        /// The allows at the deny's level that it overrides.
        overrides: Vec<Contribution>,
    },
    /// No level that counts grants it, but these scopes do.
    #[cfg_attr(feature = "openapi", schema(title = "ReasonNotHere"))]
    NotHere { granted_at: Vec<String> },
    /// No policy grants it anywhere.
    #[cfg_attr(feature = "openapi", schema(title = "ReasonNoRule"))]
    NoRule,
    /// The other tenant's scope isn't shared with this tenant.
    #[cfg_attr(feature = "openapi", schema(title = "ReasonNoShare"))]
    NoShare,
    #[cfg_attr(feature = "openapi", schema(title = "ReasonShareNotAccepted"))]
    ShareNotAccepted { share: ShareId },
    #[cfg_attr(feature = "openapi", schema(title = "ReasonShareNotValid"))]
    ShareNotValid {
        share: ShareId,
        valid_from: Option<i64>,
        valid_until: Option<i64>,
    },
    /// The share doesn't allow the action.
    #[cfg_attr(feature = "openapi", schema(title = "ReasonNotShared"))]
    NotShared { share: ShareId },
    /// The share allows it, but the subject doesn't hold it at the
    /// recipient.
    #[cfg_attr(feature = "openapi", schema(title = "ReasonNotHeldAtRecipient"))]
    NotHeldAtRecipient {
        share: ShareId,
        recipient: String,
        #[cfg_attr(feature = "openapi", schema(no_recursion))]
        held: Box<Reason>,
    },
    #[cfg_attr(feature = "openapi", schema(title = "ReasonAllowedByShare"))]
    AllowedByShare {
        share: ShareId,
        recipient: String,
        #[cfg_attr(feature = "openapi", schema(no_recursion))]
        held: Box<Reason>,
    },
}

impl Reason {
    fn granted(&self) -> bool {
        matches!(self, Self::Allowed { .. } | Self::AllowedByShare { .. })
    }

    fn message(&self, action: &str, level: &str) -> String {
        match self {
            Self::Allowed { by, ineffective } => {
                let mut message = format!("Allowed: {}.", by.describe());
                for deny in ineffective {
                    if deny.level == by.level {
                        let _ = write!(message, " It outranks {}.", deny.describe());
                    } else {
                        let _ = write!(
                            message,
                            " {} doesn't cancel it: a deny only cancels allows at its own level.",
                            capitalized(&deny.describe())
                        );
                    }
                }
                message
            }
            Self::Denied { by, overrides } => {
                let mut message = format!("Denied: {}", by.describe());
                for allow in overrides {
                    let why = if by.priority > allow.priority {
                        "with a higher priority"
                    } else {
                        "at the same priority, where a deny wins"
                    };
                    let _ = write!(message, ", which overrides {} {why}", allow.describe());
                }
                message.push('.');
                message
            }
            Self::NotHere { granted_at } => format!(
                "No policy grants `{action}` at {level}; it is granted only at {}.",
                granted_at.join(", ")
            ),
            Self::NoRule => format!("No policy grants `{action}`."),
            Self::NoShare => format!("{level} isn't shared with this tenant."),
            Self::ShareNotAccepted { share } => {
                format!("Share {share} of {level} is offered, but not accepted yet.")
            }
            Self::ShareNotValid {
                share,
                valid_from,
                valid_until,
            } => format!(
                "Share {share} of {level} isn't valid now: it runs from {} until {} (Unix seconds).",
                valid_from.map_or_else(|| "the start".to_owned(), |at| at.to_string()),
                valid_until.map_or_else(|| "no end".to_owned(), |at| at.to_string()),
            ),
            Self::NotShared { share } => {
                format!("Share {share} of {level} doesn't allow `{action}`.")
            }
            Self::NotHeldAtRecipient {
                share,
                recipient,
                held,
            } => format!(
                "Share {share} of {level} allows `{action}`, but the subject doesn't hold it at {recipient}: {}",
                held.message(action, recipient)
            ),
            Self::AllowedByShare {
                share,
                recipient,
                held,
            } => format!(
                "Allowed through share {share} of {level}, since the subject holds `{action}` at {recipient}: {}",
                held.message(action, recipient)
            ),
        }
    }
}

fn capitalized(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

/// Why one required action at one level is granted or not.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ActionExplanation {
    pub action: String,
    /// `global`, `tenant`, or `<scope kind>/<scope id>`.
    pub level: String,
    /// The tenant owning the scope, when it is another tenant's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_tenant: Option<TenantId>,
    pub granted: bool,
    pub message: String,
    pub reason: Reason,
    /// Every policy that bears on the action, wherever it lands.
    pub contributions: Vec<Contribution>,
}

/// Why a decision allows or denies.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DecisionExplanation {
    /// The decision the check API would reach, when explaining for a
    /// session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
    /// Whether every check passes and every required action is granted.
    pub allowed: bool,
    pub checks: Vec<Check>,
    pub actions: Vec<ActionExplanation>,
}

/// The session a decision is explained for.
pub struct SessionContext<'a> {
    /// Claims as an access token for the session would carry them.
    pub claims: &'a AccessClaims,
    /// Restrictive session flags from the catalog.
    pub restrictive_flags: &'a BTreeSet<String>,
    /// The catalog's confinements, with the facts of the session's tenant
    /// they name.
    pub confinements: &'a Confinements,
    /// Whether the session is current; otherwise every decision is
    /// `invalid_token`.
    pub current: bool,
}

/// What a decision is explained from: the same input compilation and
/// evaluation take, plus offered shares, so that "offered but not accepted"
/// can be said.
pub struct ExplainInput<'a> {
    pub catalog: &'a Catalog,
    pub assignments: &'a [Assignment],
    /// Accepted shares with the tenant.
    pub shares: &'a [Share],
    /// Shares with the tenant still waiting to be accepted.
    pub offered: &'a [Share],
    pub requirements: &'a Requirements,
    /// The records of the registered scopes the requirements name.
    pub registered: &'a RegisteredScopes,
    /// The tenant the decision is for; `None` for global-only decisions.
    pub tenant: Option<TenantId>,
    pub session: Option<SessionContext<'a>>,
    /// Unix seconds.
    pub now: i64,
}

/// The reason `action` is granted or not at `scope` (or tenant-wide when
/// `None`, or globally only when `global_only`), with every policy bearing
/// on it.
fn own_reason(
    catalog: &Catalog,
    assignments: &[Assignment],
    compiled: &Entitlements,
    action: &str,
    scope: Option<&Scope>,
    global_only: bool,
) -> (Reason, Vec<Contribution>) {
    let found = contributions(catalog, assignments, action);
    let mut counted = vec![Placement::Global];
    if !global_only {
        counted.push(Placement::Tenant);
        if let Some(scope) = scope {
            counted.push(Placement::Scope(scope.clone()));
        }
    }
    let winner_at = |placement: &Placement| {
        found
            .iter()
            .filter(|(at, _)| at == placement)
            .map(|(_, contribution)| contribution)
            .fold(None::<&Contribution>, |best, candidate| match best {
                Some(best)
                    if !beats(
                        (candidate.priority, candidate.effect),
                        (best.priority, best.effect),
                    ) =>
                {
                    Some(best)
                }
                _ => Some(candidate),
            })
    };
    let all: Vec<Contribution> = found.iter().map(|(_, c)| c.clone()).collect();
    let counted_denies = || {
        found
            .iter()
            .filter(|(at, c)| counted.contains(at) && c.effect == Effect::Deny)
            .map(|(_, c)| c.clone())
    };
    for placement in &counted {
        if let Some(winner) = winner_at(placement)
            && winner.effect == Effect::Allow
        {
            let ineffective = counted_denies().collect();
            return (
                Reason::Allowed {
                    by: winner.clone(),
                    ineffective,
                },
                all,
            );
        }
    }
    // The most specific level's winning deny explains best.
    if let Some(deny) = counted
        .iter()
        .rev()
        .filter_map(winner_at)
        .find(|winner| winner.effect == Effect::Deny)
    {
        let overrides = found
            .iter()
            .filter(|(_, c)| c.level == deny.level && c.effect == Effect::Allow)
            .map(|(_, c)| c.clone())
            .collect();
        return (
            Reason::Denied {
                by: deny.clone(),
                overrides,
            },
            all,
        );
    }
    let elsewhere = granted_at(compiled, action);
    if elsewhere.is_empty() {
        (Reason::NoRule, all)
    } else {
        (
            Reason::NotHere {
                granted_at: elsewhere,
            },
            all,
        )
    }
}

/// The reason `action` is granted or not at another tenant's scope, through
/// the shares of it with this tenant.
fn shared_reason(
    input: &ExplainInput<'_>,
    compiled: &Entitlements,
    owner: TenantId,
    scope: &Scope,
    action: &str,
) -> (Reason, Vec<Contribution>) {
    let matches = |share: &&Share| share.owner_tenant == owner && share.scope == *scope;
    let mut failures = Vec::new();
    for share in input.shares.iter().filter(matches) {
        let recipient = share
            .recipient_scope
            .as_ref()
            .map_or_else(|| "tenant".to_owned(), |s| format!("{}/{}", s.kind, s.id));
        let in_force = share.valid_from.is_none_or(|from| input.now >= from)
            && share.valid_until.is_none_or(|until| input.now < until);
        if !in_force {
            failures.push((
                Reason::ShareNotValid {
                    share: share.id,
                    valid_from: share.valid_from,
                    valid_until: share.valid_until,
                },
                Vec::new(),
            ));
            continue;
        }
        let allows = share
            .actions
            .iter()
            .any(|name| input.catalog.expand(name).contains(action));
        if !allows {
            failures.push((Reason::NotShared { share: share.id }, Vec::new()));
            continue;
        }
        let (held, contributions) = own_reason(
            input.catalog,
            input.assignments,
            compiled,
            action,
            share.recipient_scope.as_ref(),
            false,
        );
        if held.granted() {
            return (
                Reason::AllowedByShare {
                    share: share.id,
                    recipient,
                    held: Box::new(held),
                },
                contributions,
            );
        }
        failures.push((
            Reason::NotHeldAtRecipient {
                share: share.id,
                recipient,
                held: Box::new(held),
            },
            contributions,
        ));
    }
    if let Some(failure) = failures.into_iter().next() {
        return failure;
    }
    match input.offered.iter().find(matches) {
        Some(share) => (Reason::ShareNotAccepted { share: share.id }, Vec::new()),
        None => (Reason::NoShare, Vec::new()),
    }
}

fn kind_name(kind: TokenKind) -> &'static str {
    match kind {
        TokenKind::Partial => "partial",
        TokenKind::Identity => "identity",
        TokenKind::Tenant => "tenant",
        TokenKind::ResetPassword => "reset_password",
        TokenKind::Invite => "invite",
    }
}

/// The session checks [`evaluate`] makes, in its order.
fn session_checks(
    requirements: &Requirements,
    session: &SessionContext<'_>,
    now: i64,
) -> Vec<Check> {
    let claims = session.claims;
    let mut checks = Vec::new();
    let accepted = requirements
        .token_kinds
        .clone()
        .unwrap_or_else(|| BTreeSet::from([TokenKind::Tenant]));
    let names: Vec<&str> = accepted.iter().map(|kind| kind_name(*kind)).collect();
    checks.push(Check::new(
        "token_kind",
        accepted.contains(&claims.knd),
        format!(
            "The session's tokens are `{}` tokens; the operation accepts {}.",
            kind_name(claims.knd),
            names.join(", ")
        ),
    ));
    let unadmitted: Vec<&String> = claims
        .sfl
        .iter()
        .filter(|flag| {
            session.restrictive_flags.contains(*flag) && !requirements.admit_flags.contains(*flag)
        })
        .collect();
    checks.push(Check::new(
        "restrictive_flags",
        unadmitted.is_empty(),
        if unadmitted.is_empty() {
            "The session carries no restrictive flag the operation doesn't admit.".to_owned()
        } else {
            format!(
                "The session carries restrictive flags the operation doesn't admit: {}.",
                unadmitted
                    .iter()
                    .map(|f| format!("`{f}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        },
    ));
    if let Some(check) = confinement_check(session) {
        checks.push(check);
    }
    let missing: Vec<&String> = requirements
        .require_flags
        .iter()
        .filter(|flag| !claims.sfl.contains(*flag))
        .collect();
    checks.push(Check::new(
        "assertive_flags",
        missing.is_empty(),
        if missing.is_empty() {
            "The session carries every flag the operation requires.".to_owned()
        } else {
            format!(
                "The session lacks flags the operation requires: {}.",
                missing
                    .iter()
                    .map(|f| format!("`{f}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        },
    ));
    let step_up = &requirements.step_up;
    let satisfied = step_up_satisfied(step_up, claims, now);
    checks.push(Check::new(
        "step_up",
        satisfied,
        if satisfied {
            "The session's authentication is strong and fresh enough.".to_owned()
        } else {
            format!(
                "The operation needs {}{}; the session used {} and authenticated {} seconds ago.",
                step_up
                    .min_methods
                    .map_or_else(String::new, |min| format!("at least {min} methods")),
                step_up
                    .max_age_seconds
                    .map_or_else(String::new, |age| format!(", within {age} seconds")),
                claims.amr.join(", "),
                now - claims.auth_time
            )
        },
    ));
    checks
}

/// Whether the session's tenant matches the confinement of each confined
/// flag it carries, naming each confinement and the tenant's facts; `None`
/// when it carries no confined flag.
// r[impl authz.explain.confinement]
fn confinement_check(session: &SessionContext<'_>) -> Option<Check> {
    let claims = session.claims;
    let confinements = session.confinements;
    let confined: Vec<_> = confinements.of(&claims.sfl).collect();
    if confined.is_empty() {
        return None;
    }
    let mut message = String::new();
    let mut passed = true;
    for (flag, confinement) in confined {
        if !message.is_empty() {
            message.push(' ');
        }
        let rule = confinement.describe();
        if claims.tid.is_none() {
            passed = false;
            let _ = write!(
                message,
                "`{flag}` confines the session to tenants where {rule}, and the decision is for no tenant."
            );
            continue;
        }
        let facts: Vec<String> = confinement
            .tenant
            .keys()
            .map(|key| match confinements.tenant_facts.get(key) {
                Some(value) => format!("`{key}` is `{value}`"),
                None => format!("`{key}` is not set"),
            })
            .collect();
        let facts = facts.join(", ");
        match confinement.failing(&confinements.tenant_facts) {
            Some(key) => {
                passed = false;
                let _ = write!(
                    message,
                    "`{flag}` confines the session to tenants where {rule}; the tenant fails on `{key}` ({facts})."
                );
            }
            None => {
                let _ = write!(
                    message,
                    "`{flag}` confines the session to tenants where {rule}, and the tenant matches ({facts})."
                );
            }
        }
    }
    Some(Check::new("confinement", passed, message))
}

/// The session and tenant checks a decision makes, after `checks`.
fn decision_checks(
    input: &ExplainInput<'_>,
    tenant: Option<TenantId>,
    mut checks: Vec<Check>,
) -> Vec<Check> {
    let requirements = input.requirements;
    if let Some(session) = &input.session {
        checks.push(Check::new(
            "session_current",
            session.current,
            if session.current {
                "The session is current."
            } else {
                "The session has ended, so its tokens are invalid."
            },
        ));
        checks.extend(session_checks(requirements, session, input.now));
    }
    let unregistered_scopes = requirements
        .scopes
        .iter()
        .any(|required| !input.registered.kinds.contains(&required.kind));
    if !requirements.tenant.is_empty() || unregistered_scopes {
        checks.push(Check::new(
            "tenant",
            tenant.is_some(),
            if tenant.is_some() {
                "The decision is for a tenant."
            } else {
                "The operation needs a tenant, and the decision is for none."
            },
        ));
    }
    for required in &requirements.scopes {
        let scope = Scope {
            kind: required.kind.clone(),
            id: required.id.clone(),
        };
        if let Some(record) = input.registered.lookup(&scope) {
            checks.push(registered_check(&scope, record, required.tenant));
        }
    }
    checks
}

/// Whether a required registered scope is recorded, in the tenant the
/// requirement names if it names one.
// r[impl authz.registered.unknown-denies]
fn registered_check(
    scope: &Scope,
    record: Option<&Registration>,
    named: Option<TenantId>,
) -> Check {
    let level = format!("{}/{}", scope.kind, scope.id);
    match record {
        None => Check::new(
            "registered_scope",
            false,
            format!("{level} isn't a registered scope, or has been removed."),
        ),
        Some(record) if named.is_some_and(|named| named != record.tenant) => Check::new(
            "registered_scope",
            false,
            format!(
                "{level} is registered in tenant {}, not the tenant the requirement names.",
                record.tenant
            ),
        ),
        Some(record) => {
            let mut message = format!("{level} is registered in tenant {}", record.tenant);
            if !record.containers.is_empty() {
                let containers: Vec<String> = record
                    .containers
                    .iter()
                    .map(|c| format!("{}/{}", c.kind, c.id))
                    .collect();
                let _ = write!(message, ", inside {}", containers.join(", "));
            }
            message.push('.');
            Check::new("registered_scope", true, message)
        }
    }
}

/// Every required action at every level, explained.
fn action_explanations(
    input: &ExplainInput<'_>,
    compiled: &Entitlements,
    tenant: Option<TenantId>,
) -> Vec<ActionExplanation> {
    let requirements = input.requirements;
    let mut actions = Vec::new();
    let explain_own = |action: &str, scope: Option<&Scope>, global_only: bool| {
        let (reason, contributions) = own_reason(
            input.catalog,
            input.assignments,
            compiled,
            action,
            scope,
            global_only,
        );
        let level = match (global_only, scope) {
            (true, _) => "global".to_owned(),
            (false, None) => "tenant".to_owned(),
            (false, Some(scope)) => format!("{}/{}", scope.kind, scope.id),
        };
        ActionExplanation {
            action: action.to_owned(),
            message: reason.message(action, &level),
            granted: reason.granted(),
            level,
            owner_tenant: None,
            reason,
            contributions,
        }
    };
    for action in &requirements.global {
        actions.push(explain_own(action, None, true));
    }
    for action in &requirements.tenant {
        actions.push(explain_own(action, None, false));
    }
    for required in &requirements.scopes {
        let scope = Scope {
            kind: required.kind.clone(),
            id: required.id.clone(),
        };
        if let Some(record) = input.registered.lookup(&scope) {
            // An unknown scope fails its check; there is nothing to say per
            // action.
            if let Some(record) = record {
                for action in &required.actions {
                    actions.push(registered_explanation(
                        input, compiled, tenant, record, action,
                    ));
                }
            }
            continue;
        }
        let Some(owner) = required.tenant.filter(|owner| Some(*owner) != tenant) else {
            for action in &required.actions {
                actions.push(explain_own(action, Some(&scope), false));
            }
            continue;
        };
        for action in &required.actions {
            let level = format!("{}/{} of tenant {owner}", scope.kind, scope.id);
            let (reason, contributions) = shared_reason(input, compiled, owner, &scope, action);
            actions.push(ActionExplanation {
                action: action.clone(),
                message: reason.message(action, &level),
                granted: reason.granted(),
                level: format!("{}/{}", scope.kind, scope.id),
                owner_tenant: Some(owner),
                reason,
                contributions,
            });
        }
    }
    actions
}

/// Why `action` is granted or not at a registered scope: globally, then at
/// the scope itself or at each container, in its own tenant directly and
/// from another tenant through shares. The first that grants it explains
/// it; otherwise the first that doesn't.
fn registered_explanation(
    input: &ExplainInput<'_>,
    compiled: &Entitlements,
    tenant: Option<TenantId>,
    record: &Registration,
    action: &str,
) -> ActionExplanation {
    let scope = record.scope();
    let level = format!("{}/{}", scope.kind, scope.id);
    let own_tenant = tenant == Some(record.tenant);
    let mut candidates = vec![(
        "global".to_owned(),
        own_reason(
            input.catalog,
            input.assignments,
            compiled,
            action,
            None,
            true,
        ),
    )];
    if tenant.is_some() {
        for candidate in std::iter::once(&scope).chain(&record.containers) {
            let name = if *candidate == scope {
                level.clone()
            } else {
                format!("{}/{} (containing {level})", candidate.kind, candidate.id)
            };
            let explained = if own_tenant {
                own_reason(
                    input.catalog,
                    input.assignments,
                    compiled,
                    action,
                    Some(candidate),
                    false,
                )
            } else {
                shared_reason(input, compiled, record.tenant, candidate, action)
            };
            candidates.push((name, explained));
        }
    }
    let first_granted = candidates
        .iter()
        .position(|(_, (reason, _))| reason.granted());
    // Without a grant, the most specific candidate explains best.
    let chosen = first_granted.unwrap_or(candidates.len().min(2) - 1);
    let (name, (reason, contributions)) = candidates.swap_remove(chosen);
    ActionExplanation {
        action: action.to_owned(),
        message: reason.message(action, &name),
        granted: reason.granted(),
        level,
        owner_tenant: (!own_tenant).then_some(record.tenant),
        reason,
        contributions,
    }
}

/// Explains the decision for `input.requirements`, adding `checks` the
/// caller made (such as whether the subject is active).
// r[impl authz.explain.decision]
// r[impl authz.explain.checks]
// r[impl authz.explain.agreement]
#[must_use]
pub fn explain_decision(input: &ExplainInput<'_>, checks: Vec<Check>) -> DecisionExplanation {
    let requirements = input.requirements;
    let mut compiled = compile(input.catalog, input.assignments);
    compiled.shared = shared(input.catalog, &compiled, input.shares);
    let tenant = input
        .session
        .as_ref()
        .map_or(input.tenant, |session| session.claims.tid);
    let checks = decision_checks(input, tenant, checks);
    let actions = action_explanations(input, &compiled, tenant);

    let decision = input.session.as_ref().map(|session| {
        if session.current {
            evaluate(
                requirements,
                session.claims,
                session.restrictive_flags,
                session.confinements,
                &compiled,
                input.registered,
                input.now,
            )
        } else {
            Decision::Deny {
                reason: DenyReason::InvalidToken,
            }
        }
    });
    let allowed =
        checks.iter().all(|check| check.passed) && actions.iter().all(|action| action.granted);
    DecisionExplanation {
        decision,
        allowed,
        checks,
        actions,
    }
}
