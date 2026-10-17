//! The action catalog: actions, action groups, scope kinds, fact keys and
//! session flags. Relying systems supply it as one document.

use std::collections::{BTreeMap, BTreeSet};

use conclave_authz::Group;
use diesel::prelude::*;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use serde::{Deserialize, Serialize};

use crate::schema::{catalog_action, catalog_fact, catalog_scope_kind, catalog_session_flag};
use crate::{StoreError, StoreResult};

/// The most portable facts, in bytes of JSON, that one tenant or one
/// membership may carry into tokens.
pub const MAX_PORTABLE_FACT_BYTES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionEntry {
    pub name: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupEntry {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(flatten)]
    pub definition: Group,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeKindEntry {
    pub name: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactTarget {
    Tenant,
    Membership,
}

impl FactTarget {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tenant => "tenant",
            Self::Membership => "membership",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactType {
    String,
    Integer,
    Boolean,
    StringList,
}

impl FactType {
    fn as_str(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Integer => "integer",
            Self::Boolean => "boolean",
            Self::StringList => "string_list",
        }
    }

    fn parse(value: &str) -> Self {
        match value {
            "integer" => Self::Integer,
            "boolean" => Self::Boolean,
            "string_list" => Self::StringList,
            _ => Self::String,
        }
    }

    /// Whether `value` has this type.
    // r[impl fact.typed]
    #[must_use]
    pub fn matches(self, value: &serde_json::Value) -> bool {
        match self {
            Self::String => value.is_string(),
            Self::Integer => value.is_i64() || value.is_u64(),
            Self::Boolean => value.is_boolean(),
            Self::StringList => value
                .as_array()
                .is_some_and(|items| items.iter().all(serde_json::Value::is_string)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactEntry {
    pub key: String,
    pub target: FactTarget,
    #[serde(rename = "type")]
    pub value_type: FactType,
    // r[impl fact.portability]
    #[serde(default)]
    pub portable: bool,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlagKind {
    Restrictive,
    Assertive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionFlagEntry {
    pub name: String,
    pub kind: FlagKind,
    /// Restrictive flags only: whether a login request may ask for it.
    #[serde(default)]
    pub requestable: bool,
    #[serde(default)]
    pub description: String,
}

/// The whole catalog.
// r[impl authz.catalog.data]
// r[impl session.flags.catalog]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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

impl CatalogDocument {
    /// The catalog as the compiler needs it.
    #[must_use]
    pub fn compile_catalog(&self) -> conclave_authz::Catalog {
        conclave_authz::Catalog {
            actions: self.actions.iter().map(|a| a.name.clone()).collect(),
            groups: self
                .groups
                .iter()
                .map(|g| (g.name.clone(), g.definition.clone()))
                .collect(),
        }
    }

    #[must_use]
    pub fn restrictive_flags(&self) -> BTreeSet<String> {
        self.session_flags
            .iter()
            .filter(|flag| flag.kind == FlagKind::Restrictive)
            .map(|flag| flag.name.clone())
            .collect()
    }

    #[must_use]
    pub fn fact(&self, target: FactTarget, key: &str) -> Option<&FactEntry> {
        self.facts
            .iter()
            .find(|fact| fact.target == target && fact.key == key)
    }

    /// Checks facts written for `target` against their declarations.
    pub fn validate_facts(
        &self,
        target: FactTarget,
        facts: &serde_json::Value,
    ) -> Result<(), String> {
        let Some(facts) = facts.as_object() else {
            return Err("facts must be an object".into());
        };
        for (key, value) in facts {
            let Some(entry) = self.fact(target, key) else {
                return Err(format!(
                    "{} fact `{key}` is not declared in the catalog",
                    target.as_str()
                ));
            };
            if !entry.value_type.matches(value) {
                return Err(format!(
                    "fact `{key}` must be a {}",
                    entry.value_type.as_str()
                ));
            }
        }
        // r[impl fact.bounded]
        let portable = serde_json::Value::Object(
            portable_facts(self, target, &serde_json::Value::Object(facts.clone()))
                .into_iter()
                .collect(),
        );
        if portable.to_string().len() > MAX_PORTABLE_FACT_BYTES {
            return Err(format!(
                "portable {} facts exceed {MAX_PORTABLE_FACT_BYTES} bytes",
                target.as_str()
            ));
        }
        Ok(())
    }

    /// Checks the document for problems the database can't express.
    pub fn validate(&self) -> Result<(), String> {
        let mut names = BTreeSet::new();
        for name in self
            .actions
            .iter()
            .map(|a| &a.name)
            .chain(self.groups.iter().map(|g| &g.name))
        {
            // r[impl authz.catalog.names]
            if name.starts_with("conclave:") {
                return Err(format!("`{name}` is in the reserved conclave: namespace"));
            }
            if !names.insert(name) {
                return Err(format!("`{name}` is declared more than once"));
            }
        }
        let mut fact_keys = BTreeSet::new();
        for fact in &self.facts {
            // r[impl fact.unique-keys]
            // Tokens carry tenant and membership facts side by side, so keys
            // must be unique across targets.
            if !fact_keys.insert(&fact.key) {
                return Err(format!("fact `{}` is declared more than once", fact.key));
            }
        }
        for flag in &self.session_flags {
            if flag.requestable && flag.kind != FlagKind::Restrictive {
                return Err(format!(
                    "only restrictive flags can be requestable (`{}`)",
                    flag.name
                ));
            }
        }
        for group in &self.groups {
            if let Group::Actions(members) = &group.definition
                && let Some(unknown) = members
                    .iter()
                    .find(|m| !self.actions.iter().any(|a| &a.name == *m))
            {
                return Err(format!(
                    "group `{}` lists unknown action `{unknown}`",
                    group.name
                ));
            }
        }
        Ok(())
    }
}

#[derive(Queryable)]
struct ActionRow {
    name: String,
    description: String,
    group_definition: Option<serde_json::Value>,
}

pub async fn load(conn: &mut AsyncPgConnection) -> StoreResult<CatalogDocument> {
    let mut document = CatalogDocument::default();
    let rows = catalog_action::table
        .order(catalog_action::name.asc())
        .select((
            catalog_action::name,
            catalog_action::description,
            catalog_action::group_definition,
        ))
        .load::<ActionRow>(conn)
        .await?;
    for row in rows {
        match row.group_definition {
            None => document.actions.push(ActionEntry {
                name: row.name,
                description: row.description,
            }),
            Some(definition) => document.groups.push(GroupEntry {
                name: row.name,
                description: row.description,
                definition: serde_json::from_value(definition)
                    .map_err(|e| diesel::result::Error::DeserializationError(Box::new(e)))?,
            }),
        }
    }
    document.scope_kinds = catalog_scope_kind::table
        .order(catalog_scope_kind::name.asc())
        .select((catalog_scope_kind::name, catalog_scope_kind::description))
        .load::<(String, String)>(conn)
        .await?
        .into_iter()
        .map(|(name, description)| ScopeKindEntry { name, description })
        .collect();
    document.facts = catalog_fact::table
        .order((catalog_fact::target.asc(), catalog_fact::key.asc()))
        .select((
            catalog_fact::key,
            catalog_fact::target,
            catalog_fact::value_type,
            catalog_fact::portable,
            catalog_fact::description,
        ))
        .load::<(String, String, String, bool, String)>(conn)
        .await?
        .into_iter()
        .map(
            |(key, target, value_type, portable, description)| FactEntry {
                key,
                target: if target == "membership" {
                    FactTarget::Membership
                } else {
                    FactTarget::Tenant
                },
                value_type: FactType::parse(&value_type),
                portable,
                description,
            },
        )
        .collect();
    document.session_flags = catalog_session_flag::table
        .order(catalog_session_flag::name.asc())
        .select((
            catalog_session_flag::name,
            catalog_session_flag::kind,
            catalog_session_flag::requestable,
            catalog_session_flag::description,
        ))
        .load::<(String, String, bool, String)>(conn)
        .await?
        .into_iter()
        .map(|(name, kind, requestable, description)| SessionFlagEntry {
            name,
            kind: if kind == "assertive" {
                FlagKind::Assertive
            } else {
                FlagKind::Restrictive
            },
            requestable,
            description,
        })
        .collect();
    Ok(document)
}

/// Replaces the catalog with `document`. Entries still referenced (by
/// policies, assignments) cannot be removed; that fails as a conflict and
/// nothing changes.
// r[impl authz.catalog.removal]
// r[impl authz.catalog.revision]
pub async fn replace(conn: &mut AsyncPgConnection, document: &CatalogDocument) -> StoreResult<()> {
    document.validate().map_err(StoreError::Conflict)?;
    conn.transaction::<_, StoreError, _>(async |conn| {
        replace_actions(conn, document).await?;
        replace_scope_kinds(conn, document).await?;
        replace_facts(conn, document).await?;
        replace_session_flags(conn, document).await?;
        Ok(())
    })
    .await
}

async fn replace_actions(
    conn: &mut AsyncPgConnection,
    document: &CatalogDocument,
) -> StoreResult<()> {
    let names: Vec<&str> = document
        .actions
        .iter()
        .map(|a| a.name.as_str())
        .chain(document.groups.iter().map(|g| g.name.as_str()))
        .collect();
    diesel::delete(catalog_action::table.filter(catalog_action::name.ne_all(&names)))
        .execute(conn)
        .await
        .map_err(StoreError::from_constraint)?;
    for action in &document.actions {
        diesel::insert_into(catalog_action::table)
            .values((
                catalog_action::name.eq(&action.name),
                catalog_action::description.eq(&action.description),
                catalog_action::group_definition.eq(None::<serde_json::Value>),
            ))
            .on_conflict(catalog_action::name)
            .do_update()
            .set((
                catalog_action::description.eq(&action.description),
                catalog_action::group_definition.eq(None::<serde_json::Value>),
            ))
            .execute(conn)
            .await
            .map_err(StoreError::from_constraint)?;
    }
    for group in &document.groups {
        let definition = serde_json::to_value(&group.definition)
            .map_err(|e| StoreError::Conflict(e.to_string()))?;
        diesel::insert_into(catalog_action::table)
            .values((
                catalog_action::name.eq(&group.name),
                catalog_action::description.eq(&group.description),
                catalog_action::group_definition.eq(&definition),
            ))
            .on_conflict(catalog_action::name)
            .do_update()
            .set((
                catalog_action::description.eq(&group.description),
                catalog_action::group_definition.eq(&definition),
            ))
            .execute(conn)
            .await
            .map_err(StoreError::from_constraint)?;
    }
    Ok(())
}

async fn replace_scope_kinds(
    conn: &mut AsyncPgConnection,
    document: &CatalogDocument,
) -> StoreResult<()> {
    let kinds: Vec<&str> = document
        .scope_kinds
        .iter()
        .map(|k| k.name.as_str())
        .collect();
    diesel::delete(catalog_scope_kind::table.filter(catalog_scope_kind::name.ne_all(&kinds)))
        .execute(conn)
        .await
        .map_err(StoreError::from_constraint)?;
    for kind in &document.scope_kinds {
        diesel::insert_into(catalog_scope_kind::table)
            .values((
                catalog_scope_kind::name.eq(&kind.name),
                catalog_scope_kind::description.eq(&kind.description),
            ))
            .on_conflict(catalog_scope_kind::name)
            .do_update()
            .set(catalog_scope_kind::description.eq(&kind.description))
            .execute(conn)
            .await
            .map_err(StoreError::from_constraint)?;
    }
    Ok(())
}

async fn replace_facts(
    conn: &mut AsyncPgConnection,
    document: &CatalogDocument,
) -> StoreResult<()> {
    diesel::delete(catalog_fact::table).execute(conn).await?;
    for fact in &document.facts {
        diesel::insert_into(catalog_fact::table)
            .values((
                catalog_fact::key.eq(&fact.key),
                catalog_fact::target.eq(fact.target.as_str()),
                catalog_fact::value_type.eq(fact.value_type.as_str()),
                catalog_fact::portable.eq(fact.portable),
                catalog_fact::description.eq(&fact.description),
            ))
            .execute(conn)
            .await
            .map_err(StoreError::from_constraint)?;
    }
    Ok(())
}

async fn replace_session_flags(
    conn: &mut AsyncPgConnection,
    document: &CatalogDocument,
) -> StoreResult<()> {
    diesel::delete(catalog_session_flag::table)
        .execute(conn)
        .await?;
    for flag in &document.session_flags {
        diesel::insert_into(catalog_session_flag::table)
            .values((
                catalog_session_flag::name.eq(&flag.name),
                catalog_session_flag::kind.eq(match flag.kind {
                    FlagKind::Restrictive => "restrictive",
                    FlagKind::Assertive => "assertive",
                }),
                catalog_session_flag::requestable.eq(flag.requestable),
                catalog_session_flag::description.eq(&flag.description),
            ))
            .execute(conn)
            .await
            .map_err(StoreError::from_constraint)?;
    }
    Ok(())
}

/// Facts of `target` keyed by name, keeping only the portable ones.
#[must_use]
pub fn portable_facts(
    document: &CatalogDocument,
    target: FactTarget,
    facts: &serde_json::Value,
) -> BTreeMap<String, serde_json::Value> {
    facts
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(key, _)| {
            document
                .fact(target, key)
                .is_some_and(|entry| entry.portable)
        })
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}
