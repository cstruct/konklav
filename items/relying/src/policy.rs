//! Route policies: an operation's requirements, declared once per route or
//! router, merged across the layers around it and resolved per request.
//!
//! A [`Policy`] states everything [`Requirements`] expresses, with the ids of
//! the scopes it names left for the request to supply:
//!
//! ```
//! use std::collections::BTreeMap;
//! use konklav_relying::policy::{Policy, ResolvedScope};
//!
//! let read = Policy::new()
//!     .tenant_actions(["project:read"])
//!     .scope_actions("project", ["document:read"]);
//! let scopes = BTreeMap::from([("project".to_owned(), ResolvedScope::new("p-1"))]);
//! let requirements = read.requirements(&scopes).unwrap();
//! assert_eq!(requirements.scopes[0].id, "p-1");
//! ```
//!
//! Policies declared on nested layers merge outermost first
//! ([`Policy::merge`]). Actions accumulate, allowed sets intersect, the
//! strictest step-up wins, and an unset field leaves it to the other
//! policies. [`Policy::overriding`] replaces only the fields it sets, and
//! [`Policy::public`] admits anyone.
//!
//! Nothing here decides: the requirements go to the relying core, which
//! decides them. The rules are those of the Python binding's
//! `konklav_relying.policy.Policy`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use konklav_authz::{Requirements, ScopeRequirement, StepUp};
use konklav_core::TenantId;
use konklav_token::TokenKind;

/// A value a tenant fact predicate can match.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FactValue {
    Bool(bool),
    Integer(i64),
    String(String),
}

impl From<&str> for FactValue {
    fn from(value: &str) -> Self {
        Self::String(value.to_owned())
    }
}

impl From<String> for FactValue {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<i64> for FactValue {
    fn from(value: i64) -> Self {
        Self::Integer(value)
    }
}

impl From<bool> for FactValue {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<&FactValue> for serde_json::Value {
    fn from(value: &FactValue) -> Self {
        match value {
            FactValue::Bool(value) => Self::Bool(*value),
            FactValue::Integer(value) => Self::from(*value),
            FactValue::String(value) => Self::String(value.clone()),
        }
    }
}

/// A route policy, or a merge of route policies, that can't resolve to
/// requirements.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyError {
    /// A public policy that also constrains.
    PublicConstrains,
    /// A public policy merged with one that constrains, not an override.
    PublicMerged,
    /// Requirements asked of a public policy, which needs no decision.
    PublicRequirements,
    /// A tenant fact listed with no values.
    FactWithoutValues { fact: String },
    /// The merged policies allow no value of a tenant fact.
    FactContradiction { fact: String },
    /// The merged policies admit no token kind.
    NoTokenKind,
    /// The merged policies allow no step-up method.
    NoStepUpMethod,
    /// A scope kind the policy requires has no resolved scope.
    MissingScopeId { kind: String },
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicConstrains => f.write_str("a public policy can't also constrain"),
            Self::PublicMerged => {
                f.write_str("a public policy can't be merged with constraints; override it instead")
            }
            Self::PublicRequirements => f.write_str("a public policy needs no decision"),
            Self::FactWithoutValues { fact } => {
                write!(f, "tenant_facts lists no value for `{fact}`")
            }
            Self::FactContradiction { fact } => write!(
                f,
                "the merged policies allow no value of the tenant fact `{fact}`"
            ),
            Self::NoTokenKind => f.write_str("the merged policies admit no token kind"),
            Self::NoStepUpMethod => f.write_str("the merged policies allow no step-up method"),
            Self::MissingScopeId { kind } => {
                write!(f, "no id for the required scope kind `{kind}`")
            }
        }
    }
}

impl std::error::Error for PolicyError {}

/// A scope a request resolved for one scope kind of its route policy: its
/// `id`, optionally the scope `kind` the decision uses, when the policy's
/// kind stands for several, and the scope's owner `tenant`, when it is
/// another tenant's (then only shares allow it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedScope {
    pub id: String,
    pub kind: Option<String>,
    pub tenant: Option<TenantId>,
}

impl ResolvedScope {
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            kind: None,
            tenant: None,
        }
    }

    /// The scope kind the decision uses instead of the policy's.
    #[must_use]
    pub fn of_kind(mut self, kind: impl Into<String>) -> Self {
        self.kind = Some(kind.into());
        self
    }

    /// The tenant that owns the scope, when it isn't the token's.
    #[must_use]
    pub fn owned_by(mut self, tenant: TenantId) -> Self {
        self.tenant = Some(tenant);
        self
    }
}

impl From<String> for ResolvedScope {
    fn from(id: String) -> Self {
        Self::new(id)
    }
}

impl From<&str> for ResolvedScope {
    fn from(id: &str) -> Self {
        Self::new(id)
    }
}

/// An operation's requirements with scope ids unresolved. Every field left
/// unset leaves its part unconstrained, so Konklav's default applies: only
/// `tenant` tokens, no restrictive flag admitted.
// r[impl item.relying.policy.fields]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    global_actions: Option<BTreeSet<String>>,
    tenant_actions: Option<BTreeSet<String>>,
    scope_actions: Option<BTreeMap<String, BTreeSet<String>>>,
    token_kinds: Option<BTreeSet<TokenKind>>,
    admit_flags: Option<BTreeSet<String>>,
    require_flags: Option<BTreeSet<String>>,
    step_up: Option<StepUp>,
    tenant_facts: Option<BTreeMap<String, BTreeSet<FactValue>>>,
    public: bool,
    is_override: bool,
}

fn extend<T: Ord>(field: &mut Option<BTreeSet<T>>, values: impl IntoIterator<Item = T>) {
    field.get_or_insert_with(BTreeSet::new).extend(values);
}

fn combine<T>(a: Option<T>, b: Option<T>, how: impl FnOnce(T, T) -> T) -> Option<T> {
    match (a, b) {
        (Some(a), Some(b)) => Some(how(a, b)),
        (a, b) => a.or(b),
    }
}

fn union<T: Ord>(mut a: BTreeSet<T>, b: BTreeSet<T>) -> BTreeSet<T> {
    a.extend(b);
    a
}

// By value, to fit `combine`.
#[allow(clippy::needless_pass_by_value)]
fn intersection<T: Ord>(a: BTreeSet<T>, b: BTreeSet<T>) -> BTreeSet<T> {
    a.into_iter().filter(|value| b.contains(value)).collect()
}

/// The stricter of both: more methods, from fewer allowed, more recently.
fn stricter(a: StepUp, b: StepUp) -> StepUp {
    StepUp {
        min_methods: combine(a.min_methods, b.min_methods, std::cmp::max),
        allowed_methods: combine(a.allowed_methods, b.allowed_methods, intersection),
        max_age_seconds: combine(a.max_age_seconds, b.max_age_seconds, std::cmp::min),
    }
}

impl Policy {
    /// A policy that constrains nothing yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Admits anyone, without a token. It can't be merged with constraints,
    /// only replaced by an override.
    // r[impl item.relying.policy.public]
    #[must_use]
    pub fn public() -> Self {
        Self {
            public: true,
            ..Self::default()
        }
    }

    /// A policy that, merged after others, replaces the values of the
    /// fields it sets and keeps the others.
    // r[impl item.relying.policy.override]
    #[must_use]
    pub fn overriding() -> Self {
        Self {
            is_override: true,
            ..Self::default()
        }
    }

    /// An override that makes the merged policy public, whatever came
    /// before.
    #[must_use]
    pub fn override_public() -> Self {
        Self {
            is_override: true,
            public: true,
            ..Self::default()
        }
    }

    /// Actions required globally, whatever the tenant.
    #[must_use]
    pub fn global_actions<I: IntoIterator<Item = S>, S: Into<String>>(
        mut self,
        actions: I,
    ) -> Self {
        extend(
            &mut self.global_actions,
            actions.into_iter().map(Into::into),
        );
        self
    }

    /// Actions required tenant-wide in the token's tenant.
    #[must_use]
    pub fn tenant_actions<I: IntoIterator<Item = S>, S: Into<String>>(
        mut self,
        actions: I,
    ) -> Self {
        extend(
            &mut self.tenant_actions,
            actions.into_iter().map(Into::into),
        );
        self
    }

    /// Actions required at the scope of `kind`; its id comes with each
    /// request.
    #[must_use]
    pub fn scope_actions<I: IntoIterator<Item = S>, S: Into<String>>(
        mut self,
        kind: impl Into<String>,
        actions: I,
    ) -> Self {
        self.scope_actions
            .get_or_insert_with(BTreeMap::new)
            .entry(kind.into())
            .or_default()
            .extend(actions.into_iter().map(Into::into));
        self
    }

    /// Accepted token kinds.
    #[must_use]
    pub fn token_kinds(mut self, kinds: impl IntoIterator<Item = TokenKind>) -> Self {
        extend(&mut self.token_kinds, kinds);
        self
    }

    /// Restrictive session flags the operation tolerates.
    #[must_use]
    pub fn admit_flags<I: IntoIterator<Item = S>, S: Into<String>>(mut self, flags: I) -> Self {
        extend(&mut self.admit_flags, flags.into_iter().map(Into::into));
        self
    }

    /// Assertive session flags the operation needs.
    #[must_use]
    pub fn require_flags<I: IntoIterator<Item = S>, S: Into<String>>(mut self, flags: I) -> Self {
        extend(&mut self.require_flags, flags.into_iter().map(Into::into));
        self
    }

    /// Stronger or fresher authentication the operation needs.
    #[must_use]
    pub fn step_up(mut self, step_up: StepUp) -> Self {
        self.step_up = Some(step_up);
        self
    }

    /// The values the tenant fact `key` of the token's tenant may have.
    #[must_use]
    pub fn tenant_fact<I: IntoIterator<Item = V>, V: Into<FactValue>>(
        mut self,
        key: impl Into<String>,
        values: I,
    ) -> Self {
        self.tenant_facts
            .get_or_insert_with(BTreeMap::new)
            .entry(key.into())
            .or_default()
            .extend(values.into_iter().map(Into::into));
        self
    }

    /// Whether it admits anyone without a token.
    #[must_use]
    pub fn is_public(&self) -> bool {
        self.public
    }

    /// Whether it replaces the fields it sets when merged.
    #[must_use]
    pub fn is_override(&self) -> bool {
        self.is_override
    }

    /// Whether any constraint is set.
    #[must_use]
    pub fn constrains(&self) -> bool {
        self.global_actions.is_some()
            || self.tenant_actions.is_some()
            || self.scope_actions.is_some()
            || self.token_kinds.is_some()
            || self.admit_flags.is_some()
            || self.require_flags.is_some()
            || self.step_up.is_some()
            || self.tenant_facts.is_some()
    }

    /// The scope kinds a request must resolve scopes for.
    pub fn scope_kinds(&self) -> impl Iterator<Item = &str> {
        self.scope_actions
            .iter()
            .flat_map(|scopes| scopes.keys().map(String::as_str))
    }

    /// The admitted restrictive flags, if set.
    #[must_use]
    pub fn admitted_flags(&self) -> Option<&BTreeSet<String>> {
        self.admit_flags.as_ref()
    }

    /// The token kinds a request may present: `None` when public, only
    /// `tenant` when unset, as Konklav decides.
    #[must_use]
    pub fn admitted_token_kinds(&self) -> Option<BTreeSet<TokenKind>> {
        if self.public {
            return None;
        }
        Some(
            self.token_kinds
                .clone()
                .unwrap_or_else(|| BTreeSet::from([TokenKind::Tenant])),
        )
    }

    /// Refuses what no merge can repair: a public policy that constrains,
    /// and a tenant fact with no values.
    fn check_shape(&self) -> Result<(), PolicyError> {
        if self.public && self.constrains() {
            return Err(PolicyError::PublicConstrains);
        }
        if let Some((fact, _)) = self
            .tenant_facts
            .iter()
            .flatten()
            .find(|(_, values)| values.is_empty())
        {
            return Err(PolicyError::FactWithoutValues { fact: fact.clone() });
        }
        Ok(())
    }

    /// One policy from those declared on nested layers, outermost first.
    // r[impl item.relying.policy.merge]
    pub fn merge<'a>(
        policies: impl IntoIterator<Item = &'a Policy>,
    ) -> Result<Policy, PolicyError> {
        let mut merged = Policy::default();
        for policy in policies {
            policy.check_shape()?;
            if policy.is_override && policy.public {
                merged = Policy::public();
            } else if policy.is_override {
                if policy.constrains() {
                    merged.public = false;
                }
                let set = policy.clone();
                merged.global_actions = set.global_actions.or(merged.global_actions);
                merged.tenant_actions = set.tenant_actions.or(merged.tenant_actions);
                merged.scope_actions = set.scope_actions.or(merged.scope_actions);
                merged.token_kinds = set.token_kinds.or(merged.token_kinds);
                merged.admit_flags = set.admit_flags.or(merged.admit_flags);
                merged.require_flags = set.require_flags.or(merged.require_flags);
                merged.step_up = set.step_up.or(merged.step_up);
                merged.tenant_facts = set.tenant_facts.or(merged.tenant_facts);
            } else {
                merged = merge_two(merged, policy.clone())?;
            }
        }
        Ok(merged)
    }

    /// Refuses a policy that would deny every request: one admitting no
    /// token kind, or allowing no step-up method.
    // r[impl item.relying.policy.check]
    pub fn check(&self) -> Result<(), PolicyError> {
        self.check_shape()?;
        if self.public {
            return Ok(());
        }
        if self.token_kinds.as_ref().is_some_and(BTreeSet::is_empty) {
            return Err(PolicyError::NoTokenKind);
        }
        if self
            .step_up
            .as_ref()
            .and_then(|step_up| step_up.allowed_methods.as_ref())
            .is_some_and(BTreeSet::is_empty)
        {
            return Err(PolicyError::NoStepUpMethod);
        }
        Ok(())
    }

    /// The requirements for one request, with each required scope kind's
    /// scope from `scopes`. Scopes of kinds the policy doesn't require are
    /// ignored.
    // r[impl item.relying.policy.requirements]
    pub fn requirements(
        &self,
        scopes: &BTreeMap<String, ResolvedScope>,
    ) -> Result<Requirements, PolicyError> {
        if self.public {
            return Err(PolicyError::PublicRequirements);
        }
        let mut required = Vec::new();
        for (kind, actions) in self.scope_actions.iter().flatten() {
            let resolved = scopes
                .get(kind)
                .ok_or_else(|| PolicyError::MissingScopeId { kind: kind.clone() })?;
            required.push(ScopeRequirement {
                tenant: resolved.tenant,
                kind: resolved.kind.clone().unwrap_or_else(|| kind.clone()),
                id: resolved.id.clone(),
                actions: actions.clone(),
            });
        }
        Ok(Requirements {
            token_kinds: self.token_kinds.clone(),
            global: self.global_actions.clone().unwrap_or_default(),
            tenant: self.tenant_actions.clone().unwrap_or_default(),
            scopes: required,
            admit_flags: self.admit_flags.clone().unwrap_or_default(),
            require_flags: self.require_flags.clone().unwrap_or_default(),
            step_up: self.step_up.clone().unwrap_or_default(),
            tenant_facts: self
                .tenant_facts
                .iter()
                .flatten()
                .map(|(key, values)| (key.clone(), values.iter().map(Into::into).collect()))
                .collect(),
        })
    }
}

fn merge_two(a: Policy, b: Policy) -> Result<Policy, PolicyError> {
    if a.public || b.public {
        if a.constrains() || b.constrains() {
            return Err(PolicyError::PublicMerged);
        }
        return Ok(Policy::public());
    }
    let scopes = |mut x: BTreeMap<String, BTreeSet<String>>,
                  y: BTreeMap<String, BTreeSet<String>>| {
        for (kind, actions) in y {
            x.entry(kind).or_default().extend(actions);
        }
        x
    };
    let tenant_facts = match (a.tenant_facts, b.tenant_facts) {
        (Some(mut x), Some(y)) => {
            for (fact, allowed) in y {
                let values = match x.remove(&fact) {
                    Some(existing) => {
                        let both = intersection(existing, allowed);
                        if both.is_empty() {
                            // r[impl item.relying.policy.merge-contradiction]
                            return Err(PolicyError::FactContradiction { fact });
                        }
                        both
                    }
                    None => allowed,
                };
                x.insert(fact, values);
            }
            Some(x)
        }
        (x, y) => x.or(y),
    };
    Ok(Policy {
        global_actions: combine(a.global_actions, b.global_actions, union),
        tenant_actions: combine(a.tenant_actions, b.tenant_actions, union),
        scope_actions: combine(a.scope_actions, b.scope_actions, scopes),
        token_kinds: combine(a.token_kinds, b.token_kinds, intersection),
        admit_flags: combine(a.admit_flags, b.admit_flags, intersection),
        require_flags: combine(a.require_flags, b.require_flags, union),
        step_up: combine(a.step_up, b.step_up, stricter),
        tenant_facts,
        public: false,
        is_override: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn none() -> BTreeMap<String, ResolvedScope> {
        BTreeMap::new()
    }

    // r[verify item.relying.policy.merge]
    #[test]
    fn nested_policies_accumulate_actions_and_intersect_allowed_sets() {
        let router = Policy::new()
            .tenant_actions(["project:read"])
            .token_kinds([TokenKind::Identity, TokenKind::Tenant])
            .admit_flags(["personal_only", "kiosk"])
            .step_up(StepUp {
                max_age_seconds: Some(3600),
                ..StepUp::default()
            });
        let route = Policy::new()
            .tenant_actions(["project:write"])
            .token_kinds([TokenKind::Tenant])
            .admit_flags(["personal_only"])
            .require_flags(["mfa"])
            .step_up(StepUp {
                min_methods: Some(2),
                max_age_seconds: Some(300),
                ..StepUp::default()
            })
            .tenant_fact("tenant_type", ["client"]);
        let merged = Policy::merge([&router, &route]).unwrap();
        let requirements = merged.requirements(&none()).unwrap();
        assert_eq!(requirements.tenant, set(&["project:read", "project:write"]));
        assert_eq!(
            requirements.token_kinds,
            Some(BTreeSet::from([TokenKind::Tenant]))
        );
        assert_eq!(requirements.admit_flags, set(&["personal_only"]));
        assert_eq!(requirements.require_flags, set(&["mfa"]));
        assert_eq!(
            requirements.step_up,
            StepUp {
                min_methods: Some(2),
                allowed_methods: None,
                max_age_seconds: Some(300),
            }
        );
        assert_eq!(
            requirements.tenant_facts["tenant_type"],
            vec![serde_json::json!("client")]
        );
    }

    #[test]
    fn scope_actions_accumulate_per_kind_and_step_up_allowed_methods_intersect() {
        let a = Policy::new()
            .scope_actions("project", ["a"])
            .step_up(StepUp {
                min_methods: Some(1),
                allowed_methods: Some(set(&["pwd", "otp", "hwk"])),
                max_age_seconds: Some(600),
            });
        let b = Policy::new()
            .scope_actions("project", ["b"])
            .scope_actions("document", ["c"])
            .step_up(StepUp {
                min_methods: Some(2),
                allowed_methods: Some(set(&["otp", "hwk"])),
                max_age_seconds: Some(3600),
            });
        let merged = Policy::merge([&a, &b]).unwrap();
        assert_eq!(
            merged.scope_kinds().collect::<Vec<_>>(),
            ["document", "project"]
        );
        let scopes = BTreeMap::from([
            ("project".to_owned(), ResolvedScope::new("p-1")),
            ("document".to_owned(), ResolvedScope::new("d-1")),
        ]);
        let requirements = merged.requirements(&scopes).unwrap();
        let project = requirements
            .scopes
            .iter()
            .find(|scope| scope.kind == "project")
            .unwrap();
        assert_eq!(project.actions, set(&["a", "b"]));
        assert_eq!(
            requirements.step_up,
            StepUp {
                min_methods: Some(2),
                allowed_methods: Some(set(&["hwk", "otp"])),
                max_age_seconds: Some(600),
            }
        );
    }

    #[test]
    fn tenant_facts_intersect_per_fact_and_accumulate_facts() {
        let a = Policy::new().tenant_fact("tier", [1_i64, 2]);
        let b = Policy::new()
            .tenant_fact("tier", [2_i64, 3])
            .tenant_fact("region", ["se"]);
        let requirements = Policy::merge([&a, &b])
            .unwrap()
            .requirements(&none())
            .unwrap();
        assert_eq!(
            requirements.tenant_facts["tier"],
            vec![serde_json::json!(2)]
        );
        assert_eq!(
            requirements.tenant_facts["region"],
            vec![serde_json::json!("se")]
        );
    }

    // r[verify item.relying.policy.merge-contradiction]
    #[test]
    fn contradicting_or_empty_tenant_facts_are_refused() {
        let a = Policy::new().tenant_fact("tier", [1_i64]);
        let b = Policy::new().tenant_fact("tier", [2_i64]);
        assert_eq!(
            Policy::merge([&a, &b]),
            Err(PolicyError::FactContradiction {
                fact: "tier".into()
            })
        );
        let empty = Policy::new().tenant_fact("tier", Vec::<i64>::new());
        assert_eq!(
            Policy::merge([&empty]),
            Err(PolicyError::FactWithoutValues {
                fact: "tier".into()
            })
        );
    }

    // r[verify item.relying.policy.override]
    #[test]
    fn overrides_replace_only_the_fields_they_set() {
        let base = Policy::new()
            .tenant_actions(["a"])
            .admit_flags(["personal_only"])
            .step_up(StepUp {
                min_methods: Some(2),
                ..StepUp::default()
            });
        let relaxed = Policy::overriding()
            .admit_flags(Vec::<String>::new())
            .step_up(StepUp::default());
        let merged = Policy::merge([&base, &relaxed]).unwrap();
        assert_eq!(merged.admitted_flags(), Some(&BTreeSet::new()));
        let requirements = merged.requirements(&none()).unwrap();
        assert_eq!(requirements.tenant, set(&["a"]));
        assert_eq!(requirements.step_up, StepUp::default());
        assert!(requirements.admit_flags.is_empty());
    }

    // r[verify item.relying.policy.public]
    #[test]
    fn public_policies_admit_anyone_and_only_overrides_change_them() {
        let public = Policy::public();
        assert!(Policy::merge([&public]).unwrap().is_public());
        assert!(
            Policy::merge([&public, &Policy::public()])
                .unwrap()
                .is_public()
        );
        assert_eq!(
            Policy::merge([&public, &Policy::new().tenant_actions(["a"])]),
            Err(PolicyError::PublicMerged)
        );
        assert_eq!(
            Policy::merge([&Policy::public().tenant_actions(["a"])]),
            Err(PolicyError::PublicConstrains)
        );
        let overridden =
            Policy::merge([&public, &Policy::overriding().tenant_actions(["a"])]).unwrap();
        assert!(!overridden.is_public());
        let again = Policy::merge([
            &Policy::new().tenant_actions(["a"]),
            &Policy::override_public(),
        ])
        .unwrap();
        assert!(again.is_public());
        assert_eq!(again.admitted_token_kinds(), None);
        assert_eq!(
            again.requirements(&none()),
            Err(PolicyError::PublicRequirements)
        );
    }

    // r[verify item.relying.policy.check]
    #[test]
    fn checks_refuse_empty_allowed_sets() {
        let identity = Policy::new().token_kinds([TokenKind::Identity]);
        let tenant = Policy::new().token_kinds([TokenKind::Tenant]);
        assert_eq!(
            Policy::merge([&identity, &tenant]).unwrap().check(),
            Err(PolicyError::NoTokenKind)
        );
        let pwd = Policy::new().step_up(StepUp {
            allowed_methods: Some(set(&["pwd"])),
            ..StepUp::default()
        });
        let otp = Policy::new().step_up(StepUp {
            allowed_methods: Some(set(&["otp"])),
            ..StepUp::default()
        });
        assert_eq!(
            Policy::merge([&pwd, &otp]).unwrap().check(),
            Err(PolicyError::NoStepUpMethod)
        );
        assert_eq!(Policy::new().check(), Ok(()));
    }

    // r[verify item.relying.policy.requirements]
    // r[verify item.relying.policy.fields]
    #[test]
    fn requirements_take_resolved_scopes_and_leave_unset_fields_out() {
        let policy = Policy::new()
            .global_actions(["audit:read"])
            .scope_actions("workspace", ["read"]);
        assert_eq!(
            policy.requirements(&none()),
            Err(PolicyError::MissingScopeId {
                kind: "workspace".into()
            })
        );
        let owner: TenantId = "01900000-0000-7000-8000-000000000001".parse().unwrap();
        let scopes = BTreeMap::from([
            (
                "workspace".to_owned(),
                ResolvedScope::new("w-1")
                    .of_kind("shared_workspace")
                    .owned_by(owner),
            ),
            ("ignored".to_owned(), ResolvedScope::new("x")),
        ]);
        let requirements = policy.requirements(&scopes).unwrap();
        assert_eq!(
            requirements.scopes,
            vec![ScopeRequirement {
                tenant: Some(owner),
                kind: "shared_workspace".into(),
                id: "w-1".into(),
                actions: set(&["read"]),
            }]
        );
        let json = serde_json::to_value(&requirements).unwrap();
        assert_eq!(
            json.as_object().unwrap().keys().collect::<Vec<_>>(),
            ["global", "scopes"],
            "unset fields stay out, so Konklav's defaults apply"
        );
        assert_eq!(
            Policy::new().admitted_token_kinds(),
            Some(BTreeSet::from([TokenKind::Tenant]))
        );
    }
}
