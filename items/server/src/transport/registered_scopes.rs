//! Registered scopes and the changes that record and remove them.

use konklav_api as api;
use konklav_store::registered_scopes::{Change, RegisteredScope, RegisteredState};

pub(crate) fn registered_scope(scope: RegisteredScope) -> api::RegisteredScope {
    api::RegisteredScope {
        kind: scope.kind,
        id: scope.id,
        tenant: scope.tenant,
        containers: scope.containers,
        state: match scope.state {
            RegisteredState::Active => api::RegisteredScopeState::Active,
            RegisteredState::Removed => api::RegisteredScopeState::Removed,
        },
        created_at: scope.created_at,
        updated_at: scope.updated_at,
    }
}

pub(crate) fn registered_scope_change(change: api::RegisteredScopeChange) -> Change {
    match change {
        api::RegisteredScopeChange::Record {
            kind,
            id,
            tenant,
            containers,
        } => Change::Record {
            kind,
            id,
            tenant,
            containers,
        },
        api::RegisteredScopeChange::Remove { kind, id } => Change::Remove { kind, id },
    }
}

#[cfg(test)]
mod tests {
    use konklav_store::registered_scopes::{Change, RegisteredScope, RegisteredState};
    use serde_json::json;

    /// The transport types write and read the storage models' JSON.
    #[test]
    fn registered_scopes_keep_the_storage_models_shape() {
        let changes = json!([
            {"op": "record", "kind": "document", "id": "d1",
             "tenant": "0195e0a0-0000-7000-8000-000000000001",
             "containers": [{"kind": "project", "id": "p1"}]},
            {"op": "record", "kind": "document", "id": "d2",
             "tenant": "0195e0a0-0000-7000-8000-000000000001"},
            {"op": "remove", "kind": "document", "id": "d3"},
        ]);
        let stored: Vec<Change> = serde_json::from_value(changes.clone()).unwrap();
        let read: Vec<konklav_api::RegisteredScopeChange> =
            serde_json::from_value(changes).unwrap();
        let converted: Vec<Change> = read
            .into_iter()
            .map(super::registered_scope_change)
            .collect();
        assert_eq!(converted, stored);
        let scope = RegisteredScope {
            kind: "document".into(),
            id: "d1".into(),
            tenant: uuid::Uuid::now_v7().into(),
            containers: vec![konklav_authz::Scope {
                kind: "project".into(),
                id: "p1".into(),
            }],
            state: RegisteredState::Removed,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        assert_eq!(
            serde_json::to_value(super::registered_scope(scope.clone())).unwrap(),
            serde_json::to_value(&scope).unwrap()
        );
    }
}
