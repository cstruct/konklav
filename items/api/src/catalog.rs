use konklav_authz::Group;
use serde::{Deserialize, Serialize};

/// A declared action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ActionEntry {
    pub name: String,
    #[serde(default)]
    pub description: String,
}

/// A declared action group and how it expands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct GroupEntry {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(flatten)]
    pub definition: Group,
}

/// A declared scope kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ScopeKindEntry {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Scopes of this kind are registered scopes: requirements at them are
    /// decided from Konklav's record of each scope.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub registered: bool,
}

/// What a fact is attached to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FactTarget {
    Tenant,
    Membership,
    /// A share's attributes.
    Share,
}

/// The type of a fact's value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FactType {
    String,
    Integer,
    Boolean,
    StringList,
    /// `{"from": "YYYY-MM-DD", "until": "YYYY-MM-DD"}`, `from` not after
    /// `until`.
    DateRange,
}

/// A declared fact key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct FactEntry {
    pub key: String,
    pub target: FactTarget,
    #[serde(rename = "type")]
    pub value_type: FactType,
    /// Whether the fact may be copied into tokens.
    #[serde(default)]
    pub portable: bool,
    #[serde(default)]
    pub description: String,
}

/// A restrictive flag denies the session everywhere except operations that
/// admit it; an assertive flag is a statement operations can require.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FlagKind {
    Restrictive,
    Assertive,
}

/// A declared session flag.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SessionFlagEntry {
    pub name: String,
    pub kind: FlagKind,
    /// Restrictive flags only: whether a login request may ask for it.
    #[serde(default)]
    pub requestable: bool,
    #[serde(default)]
    pub description: String,
}

/// The whole action catalog.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CatalogDocument {
    #[serde(default)]
    pub actions: Vec<ActionEntry>,
    #[serde(default)]
    pub groups: Vec<GroupEntry>,
    #[serde(default)]
    pub scope_kinds: Vec<ScopeKindEntry>,
    #[serde(default)]
    pub facts: Vec<FactEntry>,
    #[serde(default)]
    pub session_flags: Vec<SessionFlagEntry>,
}
