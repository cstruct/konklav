//! The action catalog, in both directions: it is read and replaced whole.

use konklav_api as api;
use konklav_store::catalog::{
    ActionEntry, CatalogDocument, FactEntry, FactTarget, FactType, FlagKind, GroupEntry,
    ScopeKindEntry, SessionFlagEntry,
};

pub(crate) fn catalog(document: CatalogDocument) -> api::CatalogDocument {
    api::CatalogDocument {
        actions: document
            .actions
            .into_iter()
            .map(|action| api::ActionEntry {
                name: action.name,
                description: action.description,
            })
            .collect(),
        groups: document
            .groups
            .into_iter()
            .map(|group| api::GroupEntry {
                name: group.name,
                description: group.description,
                definition: group.definition,
            })
            .collect(),
        scope_kinds: document
            .scope_kinds
            .into_iter()
            .map(|kind| api::ScopeKindEntry {
                name: kind.name,
                description: kind.description,
                registered: kind.registered,
            })
            .collect(),
        facts: document
            .facts
            .into_iter()
            .map(|fact| api::FactEntry {
                key: fact.key,
                target: fact_target(fact.target),
                value_type: fact_type(fact.value_type),
                portable: fact.portable,
                description: fact.description,
            })
            .collect(),
        session_flags: document
            .session_flags
            .into_iter()
            .map(|flag| api::SessionFlagEntry {
                name: flag.name,
                kind: match flag.kind {
                    FlagKind::Restrictive => api::FlagKind::Restrictive,
                    FlagKind::Assertive => api::FlagKind::Assertive,
                },
                requestable: flag.requestable,
                description: flag.description,
                confine: flag.confine,
            })
            .collect(),
    }
}

pub(crate) fn store_catalog(document: api::CatalogDocument) -> CatalogDocument {
    CatalogDocument {
        actions: document
            .actions
            .into_iter()
            .map(|action| ActionEntry {
                name: action.name,
                description: action.description,
            })
            .collect(),
        groups: document
            .groups
            .into_iter()
            .map(|group| GroupEntry {
                name: group.name,
                description: group.description,
                definition: group.definition,
            })
            .collect(),
        scope_kinds: document
            .scope_kinds
            .into_iter()
            .map(|kind| ScopeKindEntry {
                name: kind.name,
                description: kind.description,
                registered: kind.registered,
            })
            .collect(),
        facts: document
            .facts
            .into_iter()
            .map(|fact| FactEntry {
                key: fact.key,
                target: store_fact_target(fact.target),
                value_type: store_fact_type(fact.value_type),
                portable: fact.portable,
                description: fact.description,
            })
            .collect(),
        session_flags: document
            .session_flags
            .into_iter()
            .map(|flag| SessionFlagEntry {
                name: flag.name,
                kind: match flag.kind {
                    api::FlagKind::Restrictive => FlagKind::Restrictive,
                    api::FlagKind::Assertive => FlagKind::Assertive,
                },
                requestable: flag.requestable,
                description: flag.description,
                confine: flag.confine,
            })
            .collect(),
    }
}

fn fact_target(target: FactTarget) -> api::FactTarget {
    match target {
        FactTarget::Tenant => api::FactTarget::Tenant,
        FactTarget::Membership => api::FactTarget::Membership,
        FactTarget::Share => api::FactTarget::Share,
    }
}

fn store_fact_target(target: api::FactTarget) -> FactTarget {
    match target {
        api::FactTarget::Tenant => FactTarget::Tenant,
        api::FactTarget::Membership => FactTarget::Membership,
        api::FactTarget::Share => FactTarget::Share,
    }
}

fn fact_type(value_type: FactType) -> api::FactType {
    match value_type {
        FactType::String => api::FactType::String,
        FactType::Integer => api::FactType::Integer,
        FactType::Boolean => api::FactType::Boolean,
        FactType::StringList => api::FactType::StringList,
        FactType::DateRange => api::FactType::DateRange,
    }
}

fn store_fact_type(value_type: api::FactType) -> FactType {
    match value_type {
        api::FactType::String => FactType::String,
        api::FactType::Integer => FactType::Integer,
        api::FactType::Boolean => FactType::Boolean,
        api::FactType::StringList => FactType::StringList,
        api::FactType::DateRange => FactType::DateRange,
    }
}

#[cfg(test)]
mod tests {
    use konklav_store::catalog::CatalogDocument;
    use serde_json::json;

    /// The transport type writes and reads the storage model's JSON.
    #[test]
    fn catalogs_keep_the_storage_models_shape() {
        let document: CatalogDocument = serde_json::from_value(json!({
            "actions": [{"name": "project:read"}, {"name": "document:read", "description": "Read"}],
            "groups": [
                {"name": "tenant:all", "all_except_prefixes": ["sys:"]},
                {"name": "readers", "actions": ["document:read"]},
            ],
            "scope_kinds": [{"name": "project"}, {"name": "document", "registered": true}],
            "facts": [
                {"key": "period", "target": "share", "type": "date_range"},
                {"key": "tenant_type", "target": "tenant", "type": "string", "portable": true},
            ],
            "session_flags": [{
                "name": "personal_only", "kind": "restrictive", "requestable": true,
                "confine": {"tenant": {"tenant_type": ["personal"]}},
            }],
        }))
        .unwrap();
        let stored = serde_json::to_value(&document).unwrap();
        let sent = serde_json::to_value(super::catalog(document.clone())).unwrap();
        assert_eq!(sent, stored);
        let read: konklav_api::CatalogDocument = serde_json::from_value(stored).unwrap();
        assert_eq!(super::store_catalog(read), document);
    }
}
