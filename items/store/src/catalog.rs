//! The action catalog: actions, action groups, scope kinds, fact keys and
//! session flags. Relying systems supply it as one document.

use std::collections::{BTreeMap, BTreeSet};

use diesel::prelude::*;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use konklav_authz::{Confinement, Confinements, Group};
use serde::{Deserialize, Serialize};

use crate::schema::{
    catalog_action, catalog_fact, catalog_scope_kind, catalog_session_flag, catalog_vouch,
};
use crate::{StoreError, StoreResult};

/// Built-in control-plane capabilities share this prefix.
pub const CAPABILITY_PREFIX: &str = "konklav:";

/// The most portable facts, in bytes of JSON, that one tenant or one
/// membership may carry into tokens.
pub const MAX_PORTABLE_FACT_BYTES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionEntry {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// The actions and groups a route decision requiring this one vouches
    /// for.
    // r[impl authz.catalog.vouches]
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub vouches: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupEntry {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(flatten)]
    pub definition: Group,
    /// As [`ActionEntry::vouches`].
    // r[impl authz.catalog.vouches]
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub vouches: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeKindEntry {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Scopes of this kind are registered scopes: requirements at them are
    /// decided from Konklav's record of each scope.
    // r[impl authz.registered.catalog]
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub registered: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactTarget {
    Tenant,
    Membership,
    /// A share's attributes.
    Share,
}

impl FactTarget {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tenant => "tenant",
            Self::Membership => "membership",
            Self::Share => "share",
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
    /// `{"from": "YYYY-MM-DD", "until": "YYYY-MM-DD"}`, `from` not after
    /// `until`.
    DateRange,
}

impl FactType {
    fn as_str(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Integer => "integer",
            Self::Boolean => "boolean",
            Self::StringList => "string_list",
            Self::DateRange => "date_range",
        }
    }

    fn parse(value: &str) -> Self {
        match value {
            "integer" => Self::Integer,
            "boolean" => Self::Boolean,
            "string_list" => Self::StringList,
            "date_range" => Self::DateRange,
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
            Self::DateRange => {
                let date = |key: &str| {
                    value
                        .get(key)?
                        .as_str()
                        .and_then(|day| chrono::NaiveDate::parse_from_str(day, "%Y-%m-%d").ok())
                };
                value.as_object().is_some_and(|range| range.len() == 2)
                    && date("from")
                        .zip(date("until"))
                        .is_some_and(|(from, until)| from <= until)
            }
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
    /// Restrictive flags only: the tenants a session carrying it may act
    /// in.
    // r[impl authz.catalog.flag-confinement]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confine: Option<Confinement>,
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
    pub fn compile_catalog(&self) -> konklav_authz::Catalog {
        konklav_authz::Catalog {
            actions: self.actions.iter().map(|a| a.name.clone()).collect(),
            groups: self
                .groups
                .iter()
                .map(|g| (g.name.clone(), g.definition.clone()))
                .collect(),
            vouches: self
                .actions
                .iter()
                .map(|a| (&a.name, &a.vouches))
                .chain(self.groups.iter().map(|g| (&g.name, &g.vouches)))
                .filter(|(_, vouches)| !vouches.is_empty())
                .map(|(name, vouches)| (name.clone(), vouches.clone()))
                .collect(),
        }
    }

    /// The registered scope kinds.
    #[must_use]
    pub fn registered_kinds(&self) -> BTreeSet<String> {
        self.scope_kinds
            .iter()
            .filter(|kind| kind.registered)
            .map(|kind| kind.name.clone())
            .collect()
    }

    #[must_use]
    pub fn restrictive_flags(&self) -> BTreeSet<String> {
        self.session_flags
            .iter()
            .filter(|flag| flag.kind == FlagKind::Restrictive)
            .map(|flag| flag.name.clone())
            .collect()
    }

    /// The confinements by flag, with every portable fact in
    /// `tenant_facts`, which confinements and tenant fact requirements are
    /// decided from.
    // r[impl authz.compile.tenant-facts]
    #[must_use]
    pub fn confinements(&self, tenant_facts: &serde_json::Value) -> Confinements {
        let flags: BTreeMap<String, Confinement> = self
            .session_flags
            .iter()
            .filter_map(|flag| Some((flag.name.clone(), flag.confine.clone()?)))
            .collect();
        Confinements {
            flags,
            tenant_facts: portable_facts(self, FactTarget::Tenant, tenant_facts),
        }
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

    /// Checks a flag's confinement: restrictive flags only, and every
    /// predicate on a declared, portable, scalar tenant fact with values of
    /// its type.
    // r[impl session.flags.confine.facts]
    fn validate_confinement(
        &self,
        flag: &SessionFlagEntry,
        confinement: &Confinement,
    ) -> Result<(), String> {
        let name = &flag.name;
        if flag.kind != FlagKind::Restrictive {
            return Err(format!("only restrictive flags can be confined (`{name}`)"));
        }
        if confinement.tenant.is_empty() {
            return Err(format!("the confinement of `{name}` names no fact"));
        }
        for (key, allowed) in &confinement.tenant {
            let Some(fact) = self.fact(FactTarget::Tenant, key) else {
                return Err(format!(
                    "the confinement of `{name}` names `{key}`, which is not a declared tenant fact"
                ));
            };
            if !fact.portable {
                return Err(format!(
                    "the confinement of `{name}` names `{key}`, which is not portable"
                ));
            }
            if !matches!(
                fact.value_type,
                FactType::String | FactType::Integer | FactType::Boolean
            ) {
                return Err(format!(
                    "the confinement of `{name}` names `{key}`, a {}: only string, integer and boolean facts can be matched",
                    fact.value_type.as_str()
                ));
            }
            if allowed.is_empty() {
                return Err(format!(
                    "the confinement of `{name}` lists no value for `{key}`"
                ));
            }
            if let Some(value) = allowed.iter().find(|v| !fact.value_type.matches(v)) {
                return Err(format!(
                    "the confinement of `{name}` lists `{value}` for `{key}`, which must be a {}",
                    fact.value_type.as_str()
                ));
            }
        }
        Ok(())
    }

    /// Every declared vouch, as (vouching action, vouched action) pairs.
    pub fn vouch_pairs(&self) -> impl Iterator<Item = (&str, &str)> {
        self.actions
            .iter()
            .map(|a| (&a.name, &a.vouches))
            .chain(self.groups.iter().map(|g| (&g.name, &g.vouches)))
            .flat_map(|(name, vouches)| {
                vouches
                    .iter()
                    .map(move |vouched| (name.as_str(), vouched.as_str()))
            })
    }

    /// Checks that every vouch names another declared action or group,
    /// and never a control-plane capability.
    // r[impl authz.catalog.vouches]
    // r[impl authz.catalog.removal]
    fn validate_vouches(&self) -> Result<(), String> {
        let declared = |name: &str| {
            self.actions.iter().any(|a| a.name == name)
                || self.groups.iter().any(|g| g.name == name)
        };
        for (name, vouched) in self.vouch_pairs() {
            if vouched.starts_with(CAPABILITY_PREFIX) {
                return Err(format!(
                    "`{name}` vouches for `{vouched}`, a control-plane capability"
                ));
            }
            if vouched == name {
                return Err(format!("`{name}` vouches for itself"));
            }
            if !declared(vouched) {
                return Err(format!(
                    "`{name}` vouches for `{vouched}`, which is not declared"
                ));
            }
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
            if name.starts_with(CAPABILITY_PREFIX) {
                return Err(format!("`{name}` is in the reserved konklav: namespace"));
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
            if fact.target == FactTarget::Share && fact.portable {
                return Err(format!(
                    "share fact `{}` can't be portable: shares never reach tokens",
                    fact.key
                ));
            }
        }
        for flag in &self.session_flags {
            if flag.requestable && flag.kind != FlagKind::Restrictive {
                return Err(format!(
                    "only restrictive flags can be requestable (`{}`)",
                    flag.name
                ));
            }
            if let Some(confinement) = &flag.confine {
                self.validate_confinement(flag, confinement)?;
            }
        }
        self.validate_vouches()?;
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

/// The declared actions and groups, with their vouches.
async fn load_actions(
    conn: &mut AsyncPgConnection,
    document: &mut CatalogDocument,
) -> StoreResult<()> {
    let mut vouches: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (action, vouched) in catalog_vouch::table
        .select((catalog_vouch::action, catalog_vouch::vouched))
        .load::<(String, String)>(conn)
        .await?
    {
        vouches.entry(action).or_default().insert(vouched);
    }
    let rows = catalog_action::table
        .filter(catalog_action::builtin.eq(false))
        .order(catalog_action::name.asc())
        .select((
            catalog_action::name,
            catalog_action::description,
            catalog_action::group_definition,
        ))
        .load::<ActionRow>(conn)
        .await?;
    for row in rows {
        let entry_vouches = vouches.remove(&row.name).unwrap_or_default();
        match row.group_definition {
            None => document.actions.push(ActionEntry {
                name: row.name,
                description: row.description,
                vouches: entry_vouches,
            }),
            Some(definition) => document.groups.push(GroupEntry {
                name: row.name,
                description: row.description,
                definition: serde_json::from_value(definition)
                    .map_err(|e| diesel::result::Error::DeserializationError(Box::new(e)))?,
                vouches: entry_vouches,
            }),
        }
    }
    Ok(())
}

pub async fn load(conn: &mut AsyncPgConnection) -> StoreResult<CatalogDocument> {
    let mut document = CatalogDocument::default();
    load_actions(conn, &mut document).await?;
    document.scope_kinds = catalog_scope_kind::table
        .order(catalog_scope_kind::name.asc())
        .select((
            catalog_scope_kind::name,
            catalog_scope_kind::description,
            catalog_scope_kind::registered,
        ))
        .load::<(String, String, bool)>(conn)
        .await?
        .into_iter()
        .map(|(name, description, registered)| ScopeKindEntry {
            name,
            description,
            registered,
        })
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
                target: match target.as_str() {
                    "membership" => FactTarget::Membership,
                    "share" => FactTarget::Share,
                    _ => FactTarget::Tenant,
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
            catalog_session_flag::confine,
        ))
        .load::<(String, String, bool, String, Option<serde_json::Value>)>(conn)
        .await?
        .into_iter()
        .map(|(name, kind, requestable, description, confine)| {
            Ok(SessionFlagEntry {
                name,
                kind: if kind == "assertive" {
                    FlagKind::Assertive
                } else {
                    FlagKind::Restrictive
                },
                requestable,
                description,
                confine: confine
                    .map(serde_json::from_value)
                    .transpose()
                    .map_err(|e| diesel::result::Error::DeserializationError(Box::new(e)))?,
            })
        })
        .collect::<Result<_, diesel::result::Error>>()?;
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
        let vouches = remove_stale_vouches(conn, document).await?;
        replace_actions(conn, document).await?;
        add_vouches(conn, document, &vouches).await?;
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
    diesel::delete(
        catalog_action::table
            .filter(catalog_action::builtin.eq(false))
            .filter(catalog_action::name.ne_all(&names)),
    )
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

/// Removes the vouches `document` no longer declares, before its actions
/// are replaced, so that removing an action they name isn't refused for
/// them. Returns the vouches kept.
async fn remove_stale_vouches(
    conn: &mut AsyncPgConnection,
    document: &CatalogDocument,
) -> StoreResult<BTreeSet<(String, String)>> {
    let wanted: BTreeSet<(&str, &str)> = document.vouch_pairs().collect();
    let mut kept = BTreeSet::new();
    for (action, vouched) in catalog_vouch::table
        .select((catalog_vouch::action, catalog_vouch::vouched))
        .load::<(String, String)>(conn)
        .await?
    {
        if wanted.contains(&(action.as_str(), vouched.as_str())) {
            kept.insert((action, vouched));
            continue;
        }
        diesel::delete(
            catalog_vouch::table
                .filter(catalog_vouch::action.eq(&action))
                .filter(catalog_vouch::vouched.eq(&vouched)),
        )
        .execute(conn)
        .await?;
    }
    Ok(kept)
}

/// Adds the vouches `document` declares that aren't stored yet.
// r[impl authz.catalog.vouches]
async fn add_vouches(
    conn: &mut AsyncPgConnection,
    document: &CatalogDocument,
    kept: &BTreeSet<(String, String)>,
) -> StoreResult<()> {
    for (action, vouched) in document.vouch_pairs() {
        if kept.contains(&(action.to_owned(), vouched.to_owned())) {
            continue;
        }
        diesel::insert_into(catalog_vouch::table)
            .values((
                catalog_vouch::action.eq(action),
                catalog_vouch::vouched.eq(vouched),
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
                catalog_scope_kind::registered.eq(kind.registered),
            ))
            .on_conflict(catalog_scope_kind::name)
            .do_update()
            .set((
                catalog_scope_kind::description.eq(&kind.description),
                catalog_scope_kind::registered.eq(kind.registered),
            ))
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
        let confine = flag
            .confine
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|e| StoreError::Conflict(e.to_string()))?;
        diesel::insert_into(catalog_session_flag::table)
            .values((
                catalog_session_flag::name.eq(&flag.name),
                catalog_session_flag::kind.eq(match flag.kind {
                    FlagKind::Restrictive => "restrictive",
                    FlagKind::Assertive => "assertive",
                }),
                catalog_session_flag::requestable.eq(flag.requestable),
                catalog_session_flag::description.eq(&flag.description),
                catalog_session_flag::confine.eq(confine),
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
