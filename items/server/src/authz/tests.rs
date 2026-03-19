use conclave_managed_config::ManagedConfig;

use crate::tenants::compile_managed_tenants;

use super::{compile_managed_authz, normalize_managed_authz};

// r[verify config.managed.authz-template-resources]
// r[verify config.managed.authz-intent-not-revisions]
#[test]
fn parses_authz_bundle_without_authored_revisions() {
    let config = ManagedConfig::load_from_str(
        r#"
catalog {
    actions (
        {name "tenant:user:read"}
        {name "tenant:user:write"}
        {name "sys:audit:read"}
    )
}
templates (
    {
        tenant "root",
        key "doctor",
        policies (
            {effect allow, action "tenant:user:read"}
        )
    }
)
roles (
    {
        tenant "root",
        key "support"
        policies (
            {effect allow, action "sys:audit:read"}
        )
    }
)
"#,
    )
    .expect("authz bundle should parse");

    assert_eq!(config.catalog.actions.len(), 3);
    assert_eq!(config.templates.len(), 1);
    assert_eq!(config.roles.len(), 1);
}

// r[verify config.managed.authz-recompile-before-issuance]
// r[verify authz.role.template.recompute-lineage]
// r[verify authz.role.template.managed-config-reconcile]
// r[verify authz.role.template.overlay]
// r[verify config.managed.authz-selector-overrides]
#[test]
fn compiles_template_lineage_and_selector_overrides() {
    let config = ManagedConfig::load_from_str(
        r#"
catalog {
    actions (
        {name "tenant:user:read"}
        {name "tenant:user:write"}
        {name "tenant:clinic:read"}
        {name "sys:audit:read"}
    )
}
templates (
    {
        tenant "root",
        key "doctor",
        policies (
            {effect allow, action "tenant:user:read"}
            {effect allow, action "tenant:clinic:read", scope_kind "clinic"}
        )
    }
    {
        tenant "tenant-a",
        key "doctor",
        source {tenant "root", key "doctor", mode "tracking"}
        policies (
            {effect deny, action "tenant:user:read"}
            {effect allow, action "tenant:user:write"}
        )
    }
)
roles (
    {
        tenant "tenant-a",
        key "doctor"
        template "doctor"
    }
)
"#,
    )
    .expect("bundle should parse");

    let compiled = compile_managed_authz(&config).expect("bundle should compile");
    let tenant_a_template = compiled
        .templates
        .iter()
        .find(|template| template.tenant == "tenant-a")
        .expect("tenant-a template should exist");
    let tenant_a_role = compiled
        .roles
        .iter()
        .find(|role| role.tenant == "tenant-a" && role.key == "doctor")
        .expect("tenant-a role should exist");

    assert_eq!(
        tenant_a_template.lineage,
        vec!["root:doctor", "tenant-a:doctor"]
    );
    assert_eq!(tenant_a_template.sync_mode, "tracking");
    assert_eq!(tenant_a_template.tenant_allow_bits_hex, "2");
    assert_eq!(tenant_a_template.tenant_deny_bits_hex, "1");
    assert_eq!(tenant_a_template.scoped_entries.len(), 1);
    assert_eq!(tenant_a_role.tenant_allow_bits_hex, "2");
    assert_eq!(tenant_a_role.tenant_deny_bits_hex, "1");
}

// r[verify authz.role.assignable.local]
// r[verify authz.role.template.non-assignable]
// r[verify authz.role.template.derive-local]
#[test]
fn compiles_local_roles_separately_from_export_templates() {
    let config = ManagedConfig::load_from_str(
        r#"
catalog {
    actions (
        {name "tenant:user:read"}
        {name "sys:audit:read"}
    )
}
templates (
    {
        tenant "root",
        key "doctor",
        policies (
            {effect allow, action "tenant:user:read"}
        )
    }
)
roles (
    {
        tenant "root",
        key "support"
        policies (
            {effect allow, action "sys:audit:read"}
        )
    }
    {
        tenant "root",
        key "doctor"
        template "doctor"
    }
)
"#,
    )
    .expect("bundle should parse");

    let compiled = compile_managed_authz(&config).expect("bundle should compile");
    let support_role = compiled
        .find_role("root", "support")
        .expect("support role should exist");
    let doctor_role = compiled
        .find_role("root", "doctor")
        .expect("doctor role should exist");

    assert_eq!(compiled.templates.len(), 1);
    assert_eq!(compiled.roles.len(), 2);
    assert_eq!(support_role.template, None);
    assert_eq!(doctor_role.template.as_deref(), Some("doctor"));
}

// r[verify authz.action.catalog.versioned]
// r[verify authz.action.namespace.reserved]
// r[verify config.managed.authz-system-revisions]
#[test]
fn assigns_stable_action_bits_and_catalog_revision_from_catalog_content() {
    let config = ManagedConfig::load_from_str(
        r#"
catalog {
    actions (
        {name "tenant:user:read"}
        {name "tenant:user:write"}
        {name "sys:audit:read"}
    )
}
templates ()
roles ()
"#,
    )
    .expect("bundle should parse");
    let updated = ManagedConfig::load_from_str(
        r#"
catalog {
    actions (
        {name "tenant:user:read"}
        {name "tenant:user:write"}
        {name "tenant:clinic:read"}
        {name "sys:audit:read"}
    )
}
templates ()
roles ()
"#,
    )
    .expect("updated bundle should parse");

    let compiled = compile_managed_authz(&config).expect("bundle should compile");
    let updated = compile_managed_authz(&updated).expect("bundle should compile");

    assert_ne!(compiled.catalog_revision, 0);
    assert_eq!(compiled.actions[0].bit, 0);
    assert_eq!(compiled.actions[1].bit, 1);
    assert_eq!(compiled.actions[2].bit, 2);
    assert_ne!(compiled.catalog_revision, updated.catalog_revision);
}

// r[verify authz.action.namespace.conclave-internal]
// r[verify config.managed.exclude-conclave-capabilities]
#[test]
fn rejects_authored_conclave_namespace_actions() {
    let config = ManagedConfig::load_from_str(
        r#"
catalog {
    actions (
        {name "tenant:user:read"}
        {name "conclave:tenant:assume"}
    )
}
templates ()
roles ()
"#,
    )
    .expect("bundle should parse");
    let result = compile_managed_authz(&config);

    assert!(result.is_err());
}

// r[verify authz.role.template.sync-modes]
// r[verify authz.role.template.versioned]
// r[verify config.managed.authz-pinned-template-normalization]
#[test]
fn normalizes_pinned_latest_templates_to_concrete_source_revisions() {
    let config = ManagedConfig::load_from_str(
        r#"
catalog {
    actions (
        {name "tenant:user:read"}
    )
}
templates (
    {
        tenant "root",
        key "doctor",
        policies (
            {effect allow, action "tenant:user:read"}
        )
    }
    {
        tenant "tenant-a",
        key "doctor",
        source {tenant "root", key "doctor", mode "pinned", pin "latest"}
    }
)
roles ()
"#,
    )
    .expect("bundle should parse");

    let normalized = normalize_managed_authz(&config).expect("bundle should normalize");
    let compiled = compile_managed_authz(&config).expect("bundle should compile");
    let root = compiled
        .templates
        .iter()
        .find(|template| template.tenant == "root" && template.key == "doctor")
        .expect("root template should exist");
    let derived = compiled
        .templates
        .iter()
        .find(|template| template.tenant == "tenant-a" && template.key == "doctor")
        .expect("derived template should exist");
    let normalized_source = normalized
        .templates
        .iter()
        .find(|template| template.tenant == "tenant-a" && template.key == "doctor")
        .and_then(|template| template.source.as_ref())
        .expect("normalized source should exist");
    let root_revision = root.revision.to_string();

    assert_eq!(
        normalized_source.pin.as_deref(),
        Some(root_revision.as_str())
    );
    assert_eq!(derived.source_revision, Some(root.revision));
    assert_eq!(
        derived
            .source
            .as_ref()
            .and_then(|source| source.pin.as_deref()),
        Some(root_revision.as_str())
    );
}

// r[verify authz.role.inheritance.dag]
// r[verify authz.role.inheritance.priority]
#[test]
fn compiles_ordered_role_inheritance() {
    let config = ManagedConfig::load_from_str(
        r#"
catalog {
    actions (
        {name "tenant:user:read"}
    )
}
templates ()
roles (
    {
        tenant "tenant-a",
        key "reader"
        policies (
            {effect allow, action "tenant:user:read"}
        )
    }
    {
        tenant "tenant-a",
        key "blocker"
        policies (
            {effect deny, action "tenant:user:read"}
        )
    }
    {
        tenant "tenant-a",
        key "doctor"
        inherits ("reader" "blocker")
    }
)
"#,
    )
    .expect("bundle should parse");

    let compiled = compile_managed_authz(&config).expect("bundle should compile");
    let role = compiled
        .find_role("tenant-a", "doctor")
        .expect("doctor role should exist");

    assert_eq!(role.inherits, vec!["reader", "blocker"]);
    assert_eq!(role.tenant_allow_bits_hex, "0");
    assert_eq!(role.tenant_deny_bits_hex, "1");
}

#[test]
fn emits_feldera_sql_program() {
    let config = ManagedConfig::load_from_str(
        r#"
catalog {
    actions (
        {name "tenant:user:read"}
        {name "sys:audit:read"}
    )
}
templates (
    {
        tenant "root",
        key "doctor",
        policies (
            {effect allow, action "tenant:user:read"}
        )
    }
)
roles (
    {
        tenant "root",
        key "doctor"
        template "doctor"
    }
)
"#,
    )
    .expect("bundle should parse");

    let compiled = compile_managed_authz(&config).expect("bundle should compile");
    let tenants = compile_managed_tenants(&config, &compiled).expect("tenants should compile");
    let sql = compiled.feldera_sql("conclave", &tenants);

    assert!(sql.contains("CREATE TABLE action_catalog"));
    assert!(sql.contains("CREATE TABLE compiled_authz_metadata"));
    assert!(sql.contains("INSERT INTO managed_role_templates"));
    assert!(sql.contains("INSERT INTO managed_roles"));
    assert!(sql.contains("CREATE TABLE effective_grant_identity"));
    assert!(sql.contains("CREATE TABLE effective_grant_role_assignment"));
    assert!(sql.contains("CREATE MATERIALIZED VIEW effective_grants"));
    assert!(sql.contains("CREATE MATERIALIZED VIEW effective_grant_actions"));
    assert!(sql.contains("CREATE TABLE compiled_role_action_effects"));
    assert!(sql.contains("source_revision BIGINT"));
    assert!(sql.contains("inherits_json STRING NOT NULL"));
    assert!(sql.contains("compiled_role_policies"));
}
