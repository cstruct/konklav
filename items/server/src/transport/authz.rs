//! Roles and templates.

use konklav_api as api;
use konklav_store::roles::{Role, RoleDefinition};
use konklav_store::templates::Template;

pub(crate) fn role(role: Role) -> api::Role {
    api::Role {
        id: role.id,
        tenant_id: role.tenant_id,
        key: role.key,
        template: role.template,
        priority: role.priority,
        metadata_etag: crate::metadata::etag(&role.metadata),
        metadata: role.metadata,
        policies: role.policies,
        builtin: role.builtin,
        created_at: role.created_at,
        updated_at: role.updated_at,
    }
}

pub(crate) fn role_definition(body: api::PutRole) -> RoleDefinition {
    RoleDefinition {
        template: body.template,
        priority: body.priority,
        metadata: body.metadata,
        policies: body.policies,
    }
}

pub(crate) fn template(template: Template) -> api::Template {
    api::Template {
        id: template.id,
        key: template.key,
        description: template.description,
        metadata_etag: crate::metadata::etag(&template.metadata),
        metadata: template.metadata,
        policies: template.policies,
        created_at: template.created_at,
        updated_at: template.updated_at,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use chrono::Utc;
    use konklav_authz::{Effect, Policy};
    use konklav_store::roles::Role;
    use konklav_store::templates::Template;
    use serde_json::json;

    fn policies() -> Vec<Policy> {
        vec![Policy {
            action: "document:read".into(),
            effect: Effect::Deny,
            scope_bound: true,
        }]
    }

    /// The transport types write the storage models' JSON.
    #[test]
    fn roles_and_templates_keep_the_storage_models_shape() {
        let role = Role {
            id: uuid::Uuid::nil(),
            tenant_id: konklav_store::tenants::ROOT,
            key: "editor".into(),
            template: None,
            priority: 5,
            metadata: json!({"label": "Editor"}),
            policies: policies(),
            builtin: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert_eq!(
            without_etag(serde_json::to_value(super::role(role.clone())).unwrap()),
            serde_json::to_value(role).unwrap()
        );
        let template = Template {
            id: uuid::Uuid::nil(),
            key: "reader".into(),
            description: String::new(),
            metadata: json!({}),
            policies: policies(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert_eq!(
            without_etag(serde_json::to_value(super::template(template.clone())).unwrap()),
            serde_json::to_value(template).unwrap()
        );
    }

    /// The transport JSON without the entity tag, which only it has.
    pub(crate) fn without_etag(mut value: serde_json::Value) -> serde_json::Value {
        value.as_object_mut().unwrap().remove("metadata_etag");
        value
    }
}
