use serde_json::Value;

use conclave_managed_config::ManagedConfig;
use conclave_relying_auth::JwtSigner;

use crate::authz::{compile_managed_authz, CompiledAuthzModel};
use crate::config::JwtConfig;

use super::{
    compile_managed_tenants, AssumeAccessTokenRequest, CompiledTenantModel,
    DirectAccessTokenRequest, ValidateAccessTokenRequest,
};

fn authz_model() -> CompiledAuthzModel {
    let config = ManagedConfig::load_from_str(
        r#"
catalog {
    actions (
        {name "tenant:user:read"}
        {name "tenant:user:write"}
        {name "tenant:clinic:read"}
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
    .expect("managed authz config should parse");

    compile_managed_authz(&config).expect("authz bundle should compile")
}

fn tenant_model(input: &str, authz: &CompiledAuthzModel) -> CompiledTenantModel {
    let config = ManagedConfig::load_from_str(&format!("catalog {{ actions () }}\n{input}"))
        .expect("managed tenant config should parse");

    compile_managed_tenants(&config, authz).expect("tenant bundle should compile")
}

fn default_tenant_model(authz: &CompiledAuthzModel) -> CompiledTenantModel {
    tenant_model(
        r#"
tenants (
    {id "tenant-a", display_name "Tenant A"}
    {id "tenant-b", display_name "Tenant B", parent "tenant-a"}
)
subjects (
    {id "operator-1", display_name "Op One"}
    {id "doctor-1", display_name "Doctor One"}
)
memberships (
    {
        subject "operator-1"
        tenant "root"
        roles ()
        facts (
            {key "authn_level", integer 2}
        )
    }
    {
        subject "doctor-1"
        tenant "tenant-a"
        roles ("doctor")
        facts (
            {key "department", string "general"}
        )
    }
)
assumption_grants (
    {
        subject "operator-1"
        source_tenant "root"
        target_tenant "tenant-a"
        target_roles ("doctor")
        ttl_seconds 600
    }
)
"#,
        authz,
    )
}

fn jwt_config() -> JwtConfig {
    JwtConfig {
        issuer: "https://conclave.test".to_owned(),
        default_audience: "conclave-api".to_owned(),
        signing_key_id: "test-key".to_owned(),
        signing_seed: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20".to_owned(),
        ttl_seconds: 900,
    }
}

fn signer() -> JwtSigner {
    let jwt = jwt_config();
    JwtSigner::from_seed(
        jwt.signing_key_id.clone(),
        jwt.signing_seed_bytes().expect("seed should decode"),
    )
}

// r[verify tenant.root.bootstrap]
// r[verify tenant.tree.parent-reference]
// r[verify tenant.tree.root-default-parent]
#[test]
fn compiles_root_and_parent_relationships() {
    let authz = authz_model();
    let tenants = default_tenant_model(&authz);

    assert_eq!(tenants.root_tenant, "root");
    let root = tenants
        .tenants
        .iter()
        .find(|tenant| tenant.id == "root")
        .expect("root tenant should exist");
    let tenant_a = tenants
        .tenants
        .iter()
        .find(|tenant| tenant.id == "tenant-a")
        .expect("tenant-a should exist");
    let tenant_b = tenants
        .tenants
        .iter()
        .find(|tenant| tenant.id == "tenant-b")
        .expect("tenant-b should exist");

    assert_eq!(root.parent, None);
    assert_eq!(tenant_a.parent.as_deref(), Some("root"));
    assert_eq!(tenant_b.parent.as_deref(), Some("tenant-a"));
    assert_eq!(tenant_b.lineage, vec!["root", "tenant-a", "tenant-b"]);
}

// r[verify tenant.root.managed-entry]
#[test]
fn includes_root_entry_as_bootstrap_root_configuration() {
    let authz = authz_model();
    let tenants = tenant_model(
        r#"
tenants (
    {id "root", display_name "Root", state "suspended"}
)
"#,
        &authz,
    );

    let root = tenants
        .tenants
        .iter()
        .find(|tenant| tenant.id == "root")
        .expect("root tenant should exist");

    assert_eq!(tenants.root_tenant, "root");
    assert_eq!(root.display_name.as_deref(), Some("Root"));
    assert_eq!(root.parent, None);
    assert_eq!(root.state, "suspended");
}

#[test]
fn rejects_parent_on_root_entry() {
    let authz = authz_model();
    let config = ManagedConfig::load_from_str(
        r#"
catalog {
    actions ()
}
tenants (
    {id "root", parent "tenant-a"}
    {id "tenant-a"}
)
"#,
    )
    .expect("managed tenant config should parse");
    let result = compile_managed_tenants(&config, &authz);

    assert!(result.is_err());
}

// r[verify tenant.namespace.isolation]
// r[verify user.membership.tenant-binding]
// r[verify authz.role.tenant-scoped]
// r[verify authz.role.runtime.tenant-local]
// r[verify authz.compile.effective-grants]
// r[verify authz.query.no-recursive-expansion]
#[test]
fn compiles_memberships_and_assumption_grants() {
    let authz = authz_model();
    let tenants = default_tenant_model(&authz);

    let membership = tenants
        .find_membership("doctor-1", "tenant-a")
        .expect("tenant membership should exist");
    let grant = tenants
        .find_assumption_grant("operator-1", "root", "tenant-a")
        .expect("assumption grant should exist");
    let operator_membership = tenants
        .find_membership("operator-1", "root")
        .expect("operator membership should exist");

    assert_eq!(membership.tenant, "tenant-a");
    assert_eq!(membership.role_keys, vec!["doctor"]);
    assert_eq!(membership.tenant_bits_hex, "3");
    assert!(operator_membership.role_keys.is_empty());
    assert_eq!(grant.target_role_keys, vec!["doctor"]);
}

// r[verify authz.assignment.multiple]
// r[verify authz.assignment.priority]
#[test]
fn later_role_assignments_override_earlier_assignments() {
    let authz = compile_managed_authz(
        &ManagedConfig::load_from_str(
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
)
"#,
        )
        .expect("managed authz config should parse"),
    )
    .expect("authz bundle should compile");

    let denied = tenant_model(
        r#"
tenants (
    {id "tenant-a"}
)
subjects (
    {id "doctor-1"}
)
memberships (
    {
        subject "doctor-1"
        tenant "tenant-a"
        roles ("reader" "blocker")
    }
)
"#,
        &authz,
    );
    let allowed = tenant_model(
        r#"
tenants (
    {id "tenant-a"}
)
subjects (
    {id "doctor-1"}
)
memberships (
    {
        subject "doctor-1"
        tenant "tenant-a"
        roles ("blocker" "reader")
    }
)
"#,
        &authz,
    );

    assert_eq!(
        denied
            .find_membership("doctor-1", "tenant-a")
            .expect("denied membership should exist")
            .tenant_bits_hex,
        "0"
    );
    assert_eq!(
        allowed
            .find_membership("doctor-1", "tenant-a")
            .expect("allowed membership should exist")
            .tenant_bits_hex,
        "1"
    );
}

// r[verify authz.role.inheritance.dag]
// r[verify authz.compile.effective-grants]
#[test]
fn flattens_inherited_role_order_into_membership_entitlements() {
    let authz = compile_managed_authz(
        &ManagedConfig::load_from_str(
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
        .expect("managed authz config should parse"),
    )
    .expect("authz bundle should compile");
    let tenants = tenant_model(
        r#"
tenants (
    {id "tenant-a"}
)
subjects (
    {id "doctor-1"}
)
memberships (
    {
        subject "doctor-1"
        tenant "tenant-a"
        roles ("doctor")
    }
)
"#,
        &authz,
    );

    assert_eq!(
        tenants
            .find_membership("doctor-1", "tenant-a")
            .expect("membership should exist")
            .tenant_bits_hex,
        "0"
    );
}

// r[verify tenant.lifecycle.state-machine]
#[test]
fn blocks_tokens_for_suspended_tenants() {
    let authz = authz_model();
    let tenants = tenant_model(
        r#"
tenants (
    {id "tenant-a", state "suspended"}
)
subjects (
    {id "doctor-1"}
)
memberships (
    {
        subject "doctor-1"
        tenant "tenant-a"
        roles ("doctor")
    }
)
"#,
        &authz,
    );

    let result = tenants.issue_direct_token(
        &authz,
        &jwt_config(),
        &signer(),
        &DirectAccessTokenRequest {
            subject: "doctor-1".to_owned(),
            tenant: "tenant-a".to_owned(),
            audience: None,
            ttl_seconds: None,
        },
    );

    assert!(result.is_err());
}

// r[verify tenant.admin.no-implicit-child-access]
// r[verify authn.assumption.conclave-action]
// r[verify authz.control-plane.capability.assumption-separate]
#[test]
fn rejects_assumed_access_without_explicit_grant() {
    let authz = compile_managed_authz(
        &ManagedConfig::load_from_str(
            r#"
catalog {
    actions (
        {name "tenant:user:read"}
    )
}
templates (
    {
        tenant "tenant-a",
        key "doctor",
        policies (
            {effect allow, action "tenant:user:read"}
        )
    }
)
roles ()
"#,
        )
        .expect("managed authz config should parse"),
    )
    .expect("authz bundle should compile");
    let tenants = tenant_model(
        r#"
tenants (
    {id "tenant-a"}
)
subjects (
    {id "operator-1"}
)
memberships (
    {
        subject "operator-1"
        tenant "root"
        roles ()
    }
)
"#,
        &authz,
    );

    let result = tenants.issue_assumed_token(
        &authz,
        &jwt_config(),
        &signer(),
        &AssumeAccessTokenRequest {
            subject: "operator-1".to_owned(),
            source_tenant: "root".to_owned(),
            target_tenant: "tenant-a".to_owned(),
            audience: None,
        },
    );

    assert!(result.is_err());
}

// r[verify token.access.jwt.standard-claims]
// r[verify token.access.authz.catalog-revision]
// r[verify token.access.authz.no-arbitrary-dsl]
// r[verify token.access.authz.policy-revision]
// r[verify token.access.authz.tenant-bits]
// r[verify token.access.authz.snapshot-claim]
#[test]
fn issues_direct_access_token() {
    let authz = authz_model();
    let tenants = default_tenant_model(&authz);
    let jwt = jwt_config();

    let token = tenants
        .issue_direct_token(
            &authz,
            &jwt,
            &signer(),
            &DirectAccessTokenRequest {
                subject: "doctor-1".to_owned(),
                tenant: "tenant-a".to_owned(),
                audience: Some("clinic-api".to_owned()),
                ttl_seconds: Some(300),
            },
        )
        .expect("token should issue");

    assert_eq!(token.claims.sub, "doctor-1");
    assert_eq!(token.claims.tid, "tenant-a");
    assert_eq!(token.claims.aud, "clinic-api");
    assert_eq!(token.claims.az.catalog_rev, authz.catalog_revision);
    assert_eq!(token.claims.az.policy_rev, tenants.policy_revision);
    assert!(token.claims.az.tenant_bits != "0");
    let snapshot = serde_json::to_value(&token.claims.az).expect("snapshot should serialize");
    let snapshot = snapshot.as_object().expect("snapshot should be an object");
    assert_eq!(snapshot.len(), 5);
    assert!(snapshot.contains_key("catalog_rev"));
    assert!(!snapshot.contains_key("policies"));
    assert!(!snapshot.contains_key("roles"));
    assert!(token.token.split('.').count() == 3);
}

// r[verify authn.session.explicit-assumption]
// r[verify authn.session.tenant-awareness]
// r[verify authn.assumption.time-bounded]
// r[verify authn.assumption.target-context]
// r[verify user.assumption.delegated-principal]
// r[verify token.access.context.actor-chain]
// r[verify token.access.authz.portable-facts]
// r[verify authz.token.self-contained-claims]
#[test]
fn issues_assumed_access_token_with_actor_context() {
    let authz = authz_model();
    let tenants = default_tenant_model(&authz);
    let jwt = jwt_config();

    let token = tenants
        .issue_assumed_token(
            &authz,
            &jwt,
            &signer(),
            &AssumeAccessTokenRequest {
                subject: "operator-1".to_owned(),
                source_tenant: "root".to_owned(),
                target_tenant: "tenant-a".to_owned(),
                audience: None,
            },
        )
        .expect("assumed token should issue");

    assert_eq!(token.claims.tid, "tenant-a");
    assert_eq!(
        token.claims.act.as_ref().map(|act| act.tid.as_str()),
        Some("root")
    );
    assert_eq!(token.claims.exp - token.claims.iat, 600);
    assert_eq!(
        token.claims.az.facts.get("authn_level"),
        Some(&Value::Number(2.into()))
    );
}

// r[verify token.access.use.offline-evaluation]
// r[verify token.access.use.staleness-bounds]
// r[verify token.access.authz.scoped-bits]
#[test]
fn validates_token_signature_scope_and_revisions() {
    let authz = authz_model();
    let tenants = default_tenant_model(&authz);
    let jwt = jwt_config();
    let token = tenants
        .issue_assumed_token(
            &authz,
            &jwt,
            &signer(),
            &AssumeAccessTokenRequest {
                subject: "operator-1".to_owned(),
                source_tenant: "root".to_owned(),
                target_tenant: "tenant-a".to_owned(),
                audience: Some("clinic-api".to_owned()),
            },
        )
        .expect("assumed token should issue");

    let validation = tenants
        .validate_access_token(
            &authz,
            &jwt,
            &signer().verifier(),
            &ValidateAccessTokenRequest {
                token: token.token,
                expected_tenant: "tenant-a".to_owned(),
                audience: Some("clinic-api".to_owned()),
                action: Some("tenant:clinic:read".to_owned()),
                scope_kind: Some("clinic".to_owned()),
                scope_id: Some("clinic-1".to_owned()),
                require_current_revisions: Some(true),
            },
        )
        .expect("validation should complete");

    assert!(validation.valid);
    assert_eq!(
        validation
            .decision
            .as_ref()
            .map(|decision| decision.matched_scope.as_deref()),
        Some(Some("clinic:*"))
    );
}
