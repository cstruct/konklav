use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Allow,
    Deny,
}

/// One rule of a role or template.
// r[impl authz.policy.shape]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
pub struct Scope {
    pub kind: String,
    pub id: String,
}

/// How an action group expands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Group {
    /// Exactly these actions.
    Actions(BTreeSet<String>),
    /// Every catalog name (actions and groups) not starting with one of
    /// these prefixes.
    AllExceptPrefixes(Vec<String>),
}

/// The names a deployment declares.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Catalog {
    pub actions: BTreeSet<String>,
    pub groups: BTreeMap<String, Group>,
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

/// Effective allows for one subject in one tenant. Denies are already
/// resolved, and an action granted at a higher level is not repeated below.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entitlements {
    pub global: BTreeSet<String>,
    pub tenant: BTreeSet<String>,
    #[serde(with = "scoped_entries")]
    pub scoped: BTreeMap<Scope, BTreeSet<String>>,
}

impl Entitlements {
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
}

/// Scoped entitlements serialize as a list, since JSON keys must be strings.
mod scoped_entries {
    use std::collections::{BTreeMap, BTreeSet};

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::Scope;

    #[derive(Serialize, Deserialize)]
    struct Entry {
        kind: String,
        id: String,
        actions: BTreeSet<String>,
    }

    pub fn serialize<S: Serializer>(
        scoped: &BTreeMap<Scope, BTreeSet<String>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(scoped.iter().map(|(scope, actions)| Entry {
            kind: scope.kind.clone(),
            id: scope.id.clone(),
            actions: actions.clone(),
        }))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<BTreeMap<Scope, BTreeSet<String>>, D::Error> {
        Ok(Vec::<Entry>::deserialize(deserializer)?
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
