use conclave_managed_config::ManagedConfig;
use conclave_relying_auth::{AccessTokenClaims, ActionCatalogEntry};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedMutationCounts {
    pub created: usize,
    pub updated: usize,
    pub deleted: usize,
}

// r[impl item.controlplane-api.shared-dto-boundary]
// r[impl item.controlplane-api.managed-ops-payloads]
// r[depends item.managed-config.root-bundle]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ManagedValidateRequest {
    pub managed: ManagedConfig,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedValidateResponse {
    pub valid: bool,
    pub issues: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ManagedPlanRequest {
    pub managed: ManagedConfig,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedPlanResponse {
    pub noop: bool,
    pub summary: ManagedMutationCounts,
    pub changes: Vec<String>,
    pub catalog_revision: u32,
    pub policy_revision: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ManagedApplyRequest {
    pub managed: ManagedConfig,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedApplyResponse {
    pub applied: bool,
    pub apply_id: String,
    pub summary: ManagedMutationCounts,
    pub catalog_revision: u32,
    pub policy_revision: u64,
}

// r[impl item.controlplane-api.subject-and-relying-dtos]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteCreateRequest {
    pub subject: String,
    pub expires_in_seconds: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteCreateResponse {
    pub invite_id: String,
    pub subject: String,
    pub redeem_code: String,
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedeemInviteRequest {
    pub redeem_code: String,
    pub password: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedeemInviteResponse {
    pub subject: String,
    pub linked: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginRequest {
    pub subject: String,
    pub password: String,
    pub tenant: String,
    pub audience: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LoginResponse {
    pub session_id: String,
    pub token: String,
    pub claims: AccessTokenClaims,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CurrentRevisionsResponse {
    pub catalog_revision: u32,
    pub policy_revision: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionCatalogResponse {
    pub revision: u32,
    pub actions: Vec<ActionCatalogEntry>,
}

#[cfg(test)]
mod tests {
    use conclave_relying_auth::{ActionCatalogEntry, AuthorizationSnapshotClaim};
    use conclave_managed_config::ManagedConfig;
    use serde_json::Map;

    use super::{
        ActionCatalogResponse, CurrentRevisionsResponse, LoginResponse, ManagedMutationCounts,
        ManagedPlanRequest, ManagedValidateResponse,
    };

    // r[verify item.controlplane-api.shared-dto-boundary]
    // r[verify item.controlplane-api.managed-ops-payloads]
    #[test]
    fn api_types_round_trip_with_managed_config() {
        let managed = ManagedConfig::load_from_str(
            r#"
catalog {
    actions (
        {name "tenant:user:read"}
    )
}
tenants (
    {id "root"}
)
"#,
        )
        .expect("managed config should parse");

        let plan = ManagedPlanRequest {
            managed: managed.clone(),
        };
        let encoded = serde_json::to_string(&plan).expect("plan should serialize");
        let decoded: ManagedPlanRequest =
            serde_json::from_str(&encoded).expect("plan should deserialize");
        assert_eq!(decoded, plan);

        let validate = ManagedValidateResponse {
            valid: true,
            issues: Vec::new(),
        };
        assert!(serde_json::to_string(&validate).is_ok());

        let counts = ManagedMutationCounts {
            created: 1,
            updated: 0,
            deleted: 0,
        };
        assert_eq!(counts.created, 1);
    }

    // r[verify item.controlplane-api.subject-and-relying-dtos]
    #[test]
    fn subject_and_relying_dtos_serialize_cleanly() {
        let login = LoginResponse {
            session_id: "session-1".to_owned(),
            token: "token-1".to_owned(),
            claims: conclave_relying_auth::AccessTokenClaims {
                iss: "https://conclave.test".to_owned(),
                sub: "subject-1".to_owned(),
                aud: "clinic-api".to_owned(),
                jti: "jti-1".to_owned(),
                iat: 10,
                exp: 20,
                tid: "tenant-a".to_owned(),
                act: None,
                az: AuthorizationSnapshotClaim {
                    catalog_rev: 4,
                    policy_rev: 9,
                    tenant_bits: "01".to_owned(),
                    scopes: Vec::new(),
                    facts: Map::new(),
                },
            },
        };
        let encoded = serde_json::to_string(&login).expect("login should serialize");
        let decoded: LoginResponse =
            serde_json::from_str(&encoded).expect("login should deserialize");
        assert_eq!(decoded.session_id, "session-1");
        assert_eq!(decoded.claims.tid, "tenant-a");

        let revisions = CurrentRevisionsResponse {
            catalog_revision: 4,
            policy_revision: 9,
        };
        assert!(serde_json::to_string(&revisions).is_ok());

        let catalog = ActionCatalogResponse {
            revision: 4,
            actions: vec![ActionCatalogEntry {
                name: "tenant:user:read".to_owned(),
                bit: 0,
            }],
        };
        let encoded = serde_json::to_string(&catalog).expect("catalog should serialize");
        let decoded: ActionCatalogResponse =
            serde_json::from_str(&encoded).expect("catalog should deserialize");
        assert_eq!(decoded.actions[0].name, "tenant:user:read");
    }
}
