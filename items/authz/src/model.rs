use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Allow,
    Deny,
}

/// One rule of a role or template.
// r[impl authz.policy.shape]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Policy {
    /// An action or action group.
    pub action: String,
    pub effect: Effect,
    /// Applies only at the assignment's scope; otherwise tenant-wide.
    #[serde(default)]
    pub scope_bound: bool,
}

/// A resource inside a tenant. Konklav treats the id as opaque.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Scope {
    pub kind: String,
    pub id: String,
}

/// Konklav's record of an active registered scope: the tenant it belongs
/// to and the scopes that contain it.
// r[impl authz.registered.shape]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registration {
    pub kind: String,
    pub id: String,
    pub tenant: konklav_core::TenantId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub containers: Vec<Scope>,
}

impl Registration {
    #[must_use]
    pub fn scope(&self) -> Scope {
        Scope {
            kind: self.kind.clone(),
            id: self.id.clone(),
        }
    }
}

/// What evaluation knows about registered scopes: the catalog's registered
/// kinds, and the records of the registered scopes a decision names. A
/// scope of a registered kind with no record here, or a `None` record, is
/// unknown.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RegisteredScopes {
    pub kinds: BTreeSet<String>,
    pub records: BTreeMap<Scope, Option<Registration>>,
}

impl RegisteredScopes {
    /// The active record for `scope`, if its kind is registered: `Some(None)`
    /// when it is unknown or removed, `None` when the kind isn't registered.
    #[must_use]
    pub fn lookup(&self, scope: &Scope) -> Option<Option<&Registration>> {
        self.kinds
            .contains(&scope.kind)
            .then(|| self.records.get(scope).and_then(Option::as_ref))
    }
}

/// A restrictive flag's confinement: the tenants a session carrying the
/// flag may act in, as fact predicates that must all hold.
// r[impl session.flags.confine]
///
/// Unknown members are refused rather than ignored, since ignoring one
/// would loosen the confinement.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(from = "StrictConfinement")]
pub struct Confinement {
    /// Tenant fact keys, each with the values the fact may have.
    #[serde(default)]
    pub tenant: BTreeMap<String, Vec<serde_json::Value>>,
}

/// [`Confinement`] as read, refusing unknown members.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictConfinement {
    #[serde(default)]
    tenant: BTreeMap<String, Vec<serde_json::Value>>,
}

impl From<StrictConfinement> for Confinement {
    fn from(read: StrictConfinement) -> Self {
        Self {
            tenant: read.tenant,
        }
    }
}

impl Confinement {
    /// The first predicate (by fact key) that `tenant_facts` fails, if any:
    /// the fact is missing, or its value isn't one of those allowed.
    #[must_use]
    pub fn failing(&self, tenant_facts: &BTreeMap<String, serde_json::Value>) -> Option<&str> {
        failing_predicate(&self.tenant, tenant_facts)
    }

    /// Such as "`tenant_type` is one of `\"personal\"`".
    #[must_use]
    pub fn describe(&self) -> String {
        describe_predicates(&self.tenant)
    }
}

/// The first of `predicates` (by fact key) that `facts` fails, if any: the
/// fact is missing, or its value isn't one of those allowed. Confinements
/// and tenant fact requirements match the same way.
#[must_use]
pub fn failing_predicate<'a>(
    predicates: &'a BTreeMap<String, Vec<serde_json::Value>>,
    facts: &BTreeMap<String, serde_json::Value>,
) -> Option<&'a str> {
    predicates
        .iter()
        .find(|(key, allowed)| facts.get(*key).is_none_or(|value| !allowed.contains(value)))
        .map(|(key, _)| key.as_str())
}

/// Fact predicates in words, such as "`tenant_type` is one of
/// `\"personal\"`".
#[must_use]
pub fn describe_predicates(predicates: &BTreeMap<String, Vec<serde_json::Value>>) -> String {
    predicates
        .iter()
        .map(|(key, allowed)| {
            let values: Vec<String> = allowed.iter().map(|v| format!("`{v}`")).collect();
            format!("`{key}` is one of {}", values.join(", "))
        })
        .collect::<Vec<_>>()
        .join(" and ")
}

/// What deciding confinements and tenant fact requirements needs: the
/// catalog's confinements by flag, and the current values of the tenant's
/// portable facts.
// r[impl authz.compile.confinements]
// r[impl authz.compile.tenant-facts]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Confinements {
    /// Confinements by the restrictive flag they belong to.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub flags: BTreeMap<String, Confinement>,
    /// The tenant's portable facts, which confinements and tenant fact
    /// requirements are decided from; empty without a tenant.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub tenant_facts: BTreeMap<String, serde_json::Value>,
}

impl Confinements {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.flags.is_empty() && self.tenant_facts.is_empty()
    }

    /// The confined flags among `flags`, with their confinements.
    pub fn of<'a>(
        &'a self,
        flags: &'a [String],
    ) -> impl Iterator<Item = (&'a str, &'a Confinement)> + 'a {
        flags.iter().filter_map(|flag| {
            self.flags
                .get(flag)
                .map(|confinement| (flag.as_str(), confinement))
        })
    }

    /// The first of `flags` whose confinement a session acting in the
    /// tenant (or in none, when `has_tenant` is false) violates.
    #[must_use]
    pub fn violated<'a>(&'a self, flags: &'a [String], has_tenant: bool) -> Option<&'a str> {
        self.of(flags)
            .find(|(_, confinement)| {
                !has_tenant || confinement.failing(&self.tenant_facts).is_some()
            })
            .map(|(flag, _)| flag)
    }
}

/// How an action group expands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum Group {
    /// Exactly these actions.
    #[cfg_attr(feature = "openapi", schema(title = "GroupActions"))]
    Actions(BTreeSet<String>),
    /// Every catalog name (actions and groups) not starting with one of
    /// these prefixes.
    #[cfg_attr(feature = "openapi", schema(title = "GroupAllExceptPrefixes"))]
    AllExceptPrefixes(Vec<String>),
}

/// The names a deployment declares.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Catalog {
    pub actions: BTreeSet<String>,
    pub groups: BTreeMap<String, Group>,
    /// What each vouching action or group vouches for, as declared.
    pub vouches: BTreeMap<String, BTreeSet<String>>,
}

impl Catalog {
    /// What granting `name` grants. A group grants its members and its own
    /// name, so operations can require the group itself.
    // r[impl authz.catalog.groups]
    #[must_use]
    pub fn expand(&self, name: &str) -> BTreeSet<String> {
        let Some(group) = self.groups.get(name) else {
            return BTreeSet::from([name.to_owned()]);
        };
        let mut expanded: BTreeSet<String> = match group {
            Group::Actions(actions) => actions.clone(),
            Group::AllExceptPrefixes(prefixes) => self
                .actions
                .iter()
                .chain(self.groups.keys())
                .filter(|name| {
                    !prefixes
                        .iter()
                        .any(|prefix| name.starts_with(prefix.as_str()))
                })
                .cloned()
                .collect(),
        };
        expanded.insert(name.to_owned());
        expanded
    }
}

/// Where an assignment applies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Level {
    /// A global role assigned to the subject: applies in every tenant.
    Global,
    /// A tenant role assigned tenant-wide.
    Tenant,
    /// A tenant role assigned at one scope.
    Scope(Scope),
}

/// One active role assignment with its role's policies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assignment {
    /// Names the assignment in explanations, such as the role key and
    /// assignment id. Not used for compilation.
    pub label: String,
    pub level: Level,
    pub priority: i32,
    /// The policies of the role's template, if any.
    pub template_policies: Vec<Policy>,
    /// The role's own policies, which replace template policies for the
    /// same action.
    pub role_policies: Vec<Policy>,
}

/// An accepted share of another tenant's scope with the tenant an
/// entitlement set is compiled for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Share {
    pub id: konklav_core::ShareId,
    pub owner_tenant: konklav_core::TenantId,
    /// The owner's scope.
    pub scope: Scope,
    /// The recipient tenant's scope the share is for; tenant-wide when
    /// `None`.
    pub recipient_scope: Option<Scope>,
    /// Actions or action groups.
    pub actions: BTreeSet<String>,
    pub attributes: serde_json::Map<String, serde_json::Value>,
    /// Unix seconds.
    pub valid_from: Option<i64>,
    pub valid_until: Option<i64>,
}

/// What a share grants one subject: the share's actions that the subject
/// holds at the recipient.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Shared {
    pub share: konklav_core::ShareId,
    pub owner_tenant: konklav_core::TenantId,
    pub kind: String,
    pub id: String,
    pub actions: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub attributes: serde_json::Map<String, serde_json::Value>,
    /// Unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<i64>,
}

impl Shared {
    /// Whether the share is in force at `now` (Unix seconds).
    // r[impl authz.share.validity]
    #[must_use]
    pub fn valid_at(&self, now: i64) -> bool {
        self.valid_from.is_none_or(|from| now >= from)
            && self.valid_until.is_none_or(|until| now < until)
    }
}

/// Effective allows for one subject in one tenant. Denies are already
/// resolved, and an action granted at a higher level is not repeated below.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Entitlements {
    pub global: BTreeSet<String>,
    pub tenant: BTreeSet<String>,
    /// Actions granted at one scope each, as a list.
    #[serde(with = "scoped_entries")]
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<scoped_entries::ScopedActions>))]
    pub scoped: BTreeMap<Scope, BTreeSet<String>>,
    /// Other tenants' scopes shared with this tenant.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shared: Vec<Shared>,
    /// For each vouching action the set grants at any level, the actions
    /// it vouches for, with groups expanded.
    // r[impl authz.compile.vouches]
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub vouches: BTreeMap<String, BTreeSet<String>>,
}

impl Entitlements {
    /// Whether `action` is granted at any level of this set: globally,
    /// tenant-wide or at some scope.
    #[must_use]
    pub fn grants_anywhere(&self, action: &str) -> bool {
        self.global.contains(action)
            || self.tenant.contains(action)
            || self.scoped.values().any(|actions| actions.contains(action))
    }

    /// Everything granted at `scope` (or tenant-wide when `None`): global,
    /// tenant-wide and the scope's own actions.
    #[must_use]
    pub fn actions_at(&self, scope: Option<&Scope>) -> BTreeSet<&str> {
        let mut actions: BTreeSet<&str> = self.global.iter().map(String::as_str).collect();
        actions.extend(self.tenant.iter().map(String::as_str));
        if let Some(scoped) = scope.and_then(|scope| self.scoped.get(scope)) {
            actions.extend(scoped.iter().map(String::as_str));
        }
        actions
    }
}

/// An entitlement set as the relying surface serves it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntitlementSet {
    pub subject_id: konklav_core::SubjectId,
    /// `None` for global-only sets (tokens without a tenant).
    pub tenant_id: Option<konklav_core::TenantId>,
    /// The change-feed cursor the set was compiled at.
    pub revision: konklav_core::Cursor,
    #[serde(flatten)]
    pub entitlements: Entitlements,
    /// Restrictive session flags from the catalog, so the set can be
    /// evaluated without another lookup.
    pub restrictive_flags: BTreeSet<String>,
    /// The catalog's registered scope kinds, so a relying core knows which
    /// requirements need a registered scope's record.
    // r[impl authz.compile.registered-kinds]
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub registered_kinds: BTreeSet<String>,
    /// The catalog's confinements and the tenant's portable facts, so
    /// confinements and tenant fact requirements can be decided without
    /// another lookup.
    #[serde(default, skip_serializing_if = "Confinements::is_empty")]
    pub confinements: Confinements,
}

/// Scoped entitlements serialize as a list, since JSON keys must be strings.
mod scoped_entries {
    use std::collections::{BTreeMap, BTreeSet};

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::Scope;

    /// The actions granted at one scope.
    #[derive(Serialize, Deserialize)]
    #[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
    pub(super) struct ScopedActions {
        kind: String,
        id: String,
        actions: BTreeSet<String>,
    }

    pub fn serialize<S: Serializer>(
        scoped: &BTreeMap<Scope, BTreeSet<String>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(scoped.iter().map(|(scope, actions)| ScopedActions {
            kind: scope.kind.clone(),
            id: scope.id.clone(),
            actions: actions.clone(),
        }))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<BTreeMap<Scope, BTreeSet<String>>, D::Error> {
        Ok(Vec::<ScopedActions>::deserialize(deserializer)?
            .into_iter()
            .map(|entry| {
                (
                    Scope {
                        kind: entry.kind,
                        id: entry.id,
                    },
                    entry.actions,
                )
            })
            .collect())
    }
}
