//! Merging a bootstrap set's catalog into the stored one, and reading facts
//! written as text by the catalog's declared types.

use konklav_bootstrap::{FactValue, Facts};
use konklav_store::catalog::{CatalogDocument, FactTarget, FactType};

/// The stored catalog with `set`'s entries added. An entry the set names
/// identically is kept; one it names differently is a conflict, since
/// bootstrap never changes what exists.
// r[impl bootstrap.idempotent]
pub(super) fn merge(
    stored: &CatalogDocument,
    set: &CatalogDocument,
) -> Result<CatalogDocument, String> {
    let mut merged = stored.clone();
    merge_section(
        &mut merged.actions,
        &set.actions,
        |e| e.name.clone(),
        "action",
    )?;
    merge_section(
        &mut merged.groups,
        &set.groups,
        |e| e.name.clone(),
        "action group",
    )?;
    merge_section(
        &mut merged.scope_kinds,
        &set.scope_kinds,
        |e| e.name.clone(),
        "scope kind",
    )?;
    merge_section(
        &mut merged.facts,
        &set.facts,
        |e| format!("{}:{}", e.target.as_str(), e.key),
        "fact",
    )?;
    merge_section(
        &mut merged.session_flags,
        &set.session_flags,
        |e| e.name.clone(),
        "session flag",
    )?;
    Ok(merged)
}

fn merge_section<T: Clone + PartialEq>(
    stored: &mut Vec<T>,
    set: &[T],
    name: impl Fn(&T) -> String,
    what: &str,
) -> Result<(), String> {
    for entry in set {
        match stored.iter().find(|existing| name(existing) == name(entry)) {
            Some(existing) if existing == entry => {}
            Some(_) => {
                return Err(format!(
                    "the catalog already declares {what} `{}` differently",
                    name(entry)
                ));
            }
            None => stored.push(entry.clone()),
        }
    }
    Ok(())
}

/// Facts as the catalog types them: integers and booleans parsed from
/// text, and string lists from `|`-separated text or a list. Undeclared
/// facts stay text, for fact validation to report.
pub(super) fn typed_facts(
    catalog: &CatalogDocument,
    target: FactTarget,
    facts: &Facts,
) -> Result<serde_json::Value, String> {
    let mut out = serde_json::Map::new();
    for (key, value) in facts {
        let declared = catalog
            .facts
            .iter()
            .find(|f| f.target == target && f.key == *key)
            .map(|f| f.value_type);
        let typed = match (declared, value) {
            (Some(FactType::StringList), FactValue::List(items)) => serde_json::json!(items),
            (Some(FactType::StringList), FactValue::Text(text)) => serde_json::json!(
                text.split('|')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
            ),
            (_, FactValue::List(_)) => return Err(format!("fact `{key}` is not a list")),
            (Some(FactType::Integer), FactValue::Text(text)) => {
                let number: i64 = text
                    .trim()
                    .parse()
                    .map_err(|_| format!("fact `{key}` must be a whole number, not `{text}`"))?;
                serde_json::json!(number)
            }
            (Some(FactType::Boolean), FactValue::Text(text)) => match text.trim() {
                "true" => serde_json::json!(true),
                "false" => serde_json::json!(false),
                _ => return Err(format!("fact `{key}` must be true or false, not `{text}`")),
            },
            (_, FactValue::Text(text)) => serde_json::json!(text),
        };
        out.insert(key.clone(), typed);
    }
    Ok(serde_json::Value::Object(out))
}
