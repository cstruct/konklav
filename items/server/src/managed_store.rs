use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use conclave_controlplane_api::ManagedMutationCounts;
use conclave_managed_config::{
    ActionSpec, AssumptionGrantConfig, ManagedConfig, MembershipConfig, PolicySpec,
    PortableFactConfig, RoleConfig, SubjectConfig, TemplateConfig, TemplateSourceConfig,
    TenantConfig,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::config::FelderaConfig;
use crate::feldera::{DesiredPipeline, FelderaClient, PipelineProgramConfig};
use crate::state::{
    digest_hex, now_unix_seconds, ControlPlaneState, CredentialRecord, InviteRecord, SessionRecord,
};
use crate::types::DynError;

#[derive(Clone, Debug)]
pub struct FelderaManagedStore {
    client: FelderaClient,
    pipeline_name: String,
    config: FelderaConfig,
}

#[derive(Clone, Copy)]
struct TemporalViewSpec {
    table_name: &'static str,
    versioned_view: &'static str,
    current_view: &'static str,
    commit_table: &'static str,
    provenance_column: &'static str,
    key_columns: &'static [&'static str],
}

const MANAGED_VIEW_SPECS: &[TemporalViewSpec] = &[
    TemporalViewSpec {
        table_name: "tenant",
        versioned_view: "versioned_tenant",
        current_view: "current_tenant",
        commit_table: "apply_commit",
        provenance_column: "apply_id",
        key_columns: &["tenant_id"],
    },
    TemporalViewSpec {
        table_name: "subject",
        versioned_view: "versioned_subject",
        current_view: "current_subject",
        commit_table: "apply_commit",
        provenance_column: "apply_id",
        key_columns: &["subject_id"],
    },
    TemporalViewSpec {
        table_name: "membership",
        versioned_view: "versioned_membership",
        current_view: "current_membership",
        commit_table: "apply_commit",
        provenance_column: "apply_id",
        key_columns: &["tenant_id", "subject_id"],
    },
    TemporalViewSpec {
        table_name: "assumption_grant",
        versioned_view: "versioned_assumption_grant",
        current_view: "current_assumption_grant",
        commit_table: "apply_commit",
        provenance_column: "apply_id",
        key_columns: &["subject_id", "source_tenant_id", "target_tenant_id"],
    },
    TemporalViewSpec {
        table_name: "action",
        versioned_view: "versioned_action",
        current_view: "current_action",
        commit_table: "apply_commit",
        provenance_column: "apply_id",
        key_columns: &["action_name"],
    },
    TemporalViewSpec {
        table_name: "template",
        versioned_view: "versioned_template",
        current_view: "current_template",
        commit_table: "apply_commit",
        provenance_column: "apply_id",
        key_columns: &["tenant_id", "template_key"],
    },
    TemporalViewSpec {
        table_name: "role",
        versioned_view: "versioned_role",
        current_view: "current_role",
        commit_table: "apply_commit",
        provenance_column: "apply_id",
        key_columns: &["tenant_id", "role_key"],
    },
    TemporalViewSpec {
        table_name: "managed_ownership",
        versioned_view: "versioned_managed_ownership",
        current_view: "current_managed_ownership",
        commit_table: "apply_commit",
        provenance_column: "apply_id",
        key_columns: &["entity_kind", "entity_key"],
    },
];

const RUNTIME_VIEW_SPECS: &[TemporalViewSpec] = &[
    TemporalViewSpec {
        table_name: "invite",
        versioned_view: "versioned_invite",
        current_view: "current_invite",
        commit_table: "auth_runtime_commit",
        provenance_column: "change_id",
        key_columns: &["invite_id"],
    },
    TemporalViewSpec {
        table_name: "subject_credential",
        versioned_view: "versioned_subject_credential",
        current_view: "current_subject_credential",
        commit_table: "auth_runtime_commit",
        provenance_column: "change_id",
        key_columns: &["subject_id"],
    },
    TemporalViewSpec {
        table_name: "session_state",
        versioned_view: "versioned_session",
        current_view: "current_session",
        commit_table: "auth_runtime_commit",
        provenance_column: "change_id",
        key_columns: &["session_id"],
    },
];

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ApplyCommitRow {
    #[serde(alias = "APPLY_ID")]
    apply_id: String,
    #[serde(alias = "COMMITTED_AT")]
    committed_at: u64,
    #[serde(alias = "COMMITTED")]
    committed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AuthRuntimeCommitRow {
    #[serde(alias = "CHANGE_ID")]
    change_id: String,
    #[serde(alias = "COMMITTED_AT")]
    committed_at: u64,
    #[serde(alias = "COMMITTED")]
    committed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CountRow {
    #[serde(alias = "COUNT")]
    count: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LatestApplyRow {
    #[serde(alias = "APPLY_ID")]
    apply_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ManagedApplyRow {
    #[serde(alias = "APPLY_ID")]
    apply_id: String,
    #[serde(alias = "APPLIED_AT")]
    applied_at: u64,
    #[serde(alias = "BUNDLE_JSON")]
    bundle_json: String,
    #[serde(alias = "BUNDLE_FINGERPRINT")]
    bundle_fingerprint: String,
    #[serde(alias = "CREATED_COUNT")]
    created_count: u64,
    #[serde(alias = "UPDATED_COUNT")]
    updated_count: u64,
    #[serde(alias = "DELETED_COUNT")]
    deleted_count: u64,
    #[serde(alias = "NOOP")]
    noop: bool,
}

impl ManagedApplyRow {
    fn into_record(self) -> Result<StoredManagedApply, DynError> {
        Ok(StoredManagedApply {
            apply_id: self.apply_id,
            applied_at: self.applied_at,
            bundle_fingerprint: self.bundle_fingerprint,
            summary: ManagedMutationCounts {
                created: self.created_count as usize,
                updated: self.updated_count as usize,
                deleted: self.deleted_count as usize,
            },
            noop: self.noop,
            managed: serde_json::from_str(&self.bundle_json)?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ManagedOwnershipRow {
    #[serde(alias = "ENTITY_KIND")]
    entity_kind: String,
    #[serde(alias = "ENTITY_KEY")]
    entity_key: String,
    #[serde(alias = "DESIRED_FINGERPRINT")]
    desired_fingerprint: String,
    #[serde(alias = "APPLY_ID")]
    apply_id: String,
    #[serde(alias = "ROW_VERSION")]
    row_version: u64,
    #[serde(alias = "VALID_FROM")]
    valid_from: u64,
    #[serde(alias = "DELETED")]
    deleted: bool,
}

impl ManagedOwnershipRow {
    fn from_mutation(
        mutation: &ManagedOwnershipMutation,
        apply_id: String,
        row_version: u64,
        valid_from: u64,
    ) -> Self {
        Self {
            entity_kind: mutation.entity_kind.to_owned(),
            entity_key: mutation.entity_key.clone(),
            desired_fingerprint: mutation.desired_fingerprint.clone().unwrap_or_default(),
            apply_id,
            row_version,
            valid_from,
            deleted: mutation.deleted,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedStorePlan {
    pub noop: bool,
    pub summary: ManagedMutationCounts,
    pub changes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct StoredManagedApply {
    pub apply_id: String,
    pub applied_at: u64,
    pub bundle_fingerprint: String,
    pub summary: ManagedMutationCounts,
    pub noop: bool,
    pub managed: ManagedConfig,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedApplyPhase {
    Checkpoint,
    StartTransaction,
    Ingress,
    Commit,
    CommitVisibility,
}

impl ManagedApplyPhase {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Checkpoint => "checkpoint",
            Self::StartTransaction => "start_transaction",
            Self::Ingress => "ingress",
            Self::Commit => "commit",
            Self::CommitVisibility => "commit_visibility",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ManagedApplyFailure {
    pub apply_id: String,
    pub phase: ManagedApplyPhase,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint_sequence_number: Option<u64>,
    pub summary: ManagedMutationCounts,
    pub affected_resources: Vec<String>,
    pub rolled_back_resources: Vec<String>,
    pub recovery_attempted: bool,
    pub recovery_succeeded: bool,
    pub operator_intervention: Vec<String>,
    pub error: String,
}

impl ManagedApplyFailure {
    fn new(
        apply_id: String,
        phase: ManagedApplyPhase,
        transaction_id: Option<u64>,
        checkpoint_sequence_number: Option<u64>,
        summary: ManagedMutationCounts,
        affected_resources: Vec<String>,
        error: impl Into<String>,
    ) -> Self {
        Self {
            apply_id,
            phase,
            transaction_id,
            checkpoint_sequence_number,
            summary,
            affected_resources,
            rolled_back_resources: Vec::new(),
            recovery_attempted: false,
            recovery_succeeded: false,
            operator_intervention: Vec::new(),
            error: error.into(),
        }
    }
}

impl std::fmt::Display for ManagedApplyFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "managed apply {} failed during {}: {}",
            self.apply_id,
            self.phase.as_str(),
            self.error
        )
    }
}

impl std::error::Error for ManagedApplyFailure {}

#[derive(Clone)]
enum ManagedEntityOperation {
    Create,
    Update,
    Delete,
}

#[derive(Clone)]
struct ManagedEntityChange<T> {
    value: T,
    operation: ManagedEntityOperation,
}

#[derive(Clone)]
struct ManagedOwnershipMutation {
    entity_kind: &'static str,
    entity_key: String,
    desired_fingerprint: Option<String>,
    deleted: bool,
}

struct EntityPlan<T> {
    changes: Vec<ManagedEntityChange<T>>,
    ownership: Vec<ManagedOwnershipMutation>,
    reported_changes: Vec<String>,
}

#[derive(Clone)]
struct ManagedApplyPlan {
    desired_bundle_json: String,
    desired_bundle_fingerprint: String,
    summary: ManagedMutationCounts,
    changes: Vec<String>,
    noop: bool,
    tenant_changes: Vec<ManagedEntityChange<TenantConfig>>,
    subject_changes: Vec<ManagedEntityChange<SubjectConfig>>,
    membership_changes: Vec<ManagedEntityChange<MembershipConfig>>,
    assumption_grant_changes: Vec<ManagedEntityChange<AssumptionGrantConfig>>,
    action_changes: Vec<ManagedEntityChange<ActionSpec>>,
    template_changes: Vec<ManagedEntityChange<TemplateConfig>>,
    role_changes: Vec<ManagedEntityChange<RoleConfig>>,
    ownership_mutations: Vec<ManagedOwnershipMutation>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TenantRow {
    #[serde(alias = "TENANT_ID")]
    tenant_id: String,
    #[serde(alias = "DISPLAY_NAME")]
    display_name: Option<String>,
    #[serde(alias = "PARENT_TENANT_ID")]
    parent_tenant_id: Option<String>,
    #[serde(alias = "STATE")]
    state: String,
    #[serde(alias = "APPLY_ID")]
    apply_id: String,
    #[serde(alias = "ROW_VERSION")]
    row_version: u64,
    #[serde(alias = "VALID_FROM")]
    valid_from: u64,
    #[serde(alias = "DELETED")]
    deleted: bool,
}

impl TenantRow {
    fn from_config(
        tenant: &TenantConfig,
        apply_id: String,
        row_version: u64,
        valid_from: u64,
        deleted: bool,
    ) -> Self {
        Self {
            tenant_id: tenant.id.clone(),
            display_name: tenant.display_name.clone(),
            parent_tenant_id: tenant.parent.clone(),
            state: tenant.state.clone(),
            apply_id,
            row_version,
            valid_from,
            deleted,
        }
    }

    fn into_config(self) -> TenantConfig {
        TenantConfig {
            id: self.tenant_id,
            display_name: self.display_name,
            parent: self.parent_tenant_id,
            state: self.state,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SubjectRow {
    #[serde(alias = "SUBJECT_ID")]
    subject_id: String,
    #[serde(alias = "DISPLAY_NAME")]
    display_name: Option<String>,
    #[serde(alias = "APPLY_ID")]
    apply_id: String,
    #[serde(alias = "ROW_VERSION")]
    row_version: u64,
    #[serde(alias = "VALID_FROM")]
    valid_from: u64,
    #[serde(alias = "DELETED")]
    deleted: bool,
}

impl SubjectRow {
    fn from_config(
        subject: &SubjectConfig,
        apply_id: String,
        row_version: u64,
        valid_from: u64,
        deleted: bool,
    ) -> Self {
        Self {
            subject_id: subject.id.clone(),
            display_name: subject.display_name.clone(),
            apply_id,
            row_version,
            valid_from,
            deleted,
        }
    }

    fn into_config(self) -> SubjectConfig {
        SubjectConfig {
            id: self.subject_id,
            display_name: self.display_name,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct MembershipRow {
    #[serde(alias = "TENANT_ID")]
    tenant_id: String,
    #[serde(alias = "SUBJECT_ID")]
    subject_id: String,
    #[serde(alias = "ROLES_JSON")]
    roles_json: String,
    #[serde(alias = "FACTS_JSON")]
    facts_json: String,
    #[serde(alias = "APPLY_ID")]
    apply_id: String,
    #[serde(alias = "ROW_VERSION")]
    row_version: u64,
    #[serde(alias = "VALID_FROM")]
    valid_from: u64,
    #[serde(alias = "DELETED")]
    deleted: bool,
}

impl MembershipRow {
    fn from_config(
        membership: &MembershipConfig,
        apply_id: String,
        row_version: u64,
        valid_from: u64,
        deleted: bool,
    ) -> Self {
        Self {
            tenant_id: membership.tenant.clone(),
            subject_id: membership.subject.clone(),
            roles_json: serialize_json(&membership.roles),
            facts_json: serialize_json(&membership.facts),
            apply_id,
            row_version,
            valid_from,
            deleted,
        }
    }

    fn into_config(self) -> Result<MembershipConfig, DynError> {
        Ok(MembershipConfig {
            subject: self.subject_id,
            tenant: self.tenant_id,
            roles: serde_json::from_str(&self.roles_json)?,
            facts: serde_json::from_str::<Vec<PortableFactConfig>>(&self.facts_json)?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AssumptionGrantRow {
    #[serde(alias = "SUBJECT_ID")]
    subject_id: String,
    #[serde(alias = "SOURCE_TENANT_ID")]
    source_tenant_id: String,
    #[serde(alias = "TARGET_TENANT_ID")]
    target_tenant_id: String,
    #[serde(alias = "TARGET_ROLES_JSON")]
    target_roles_json: String,
    #[serde(alias = "TTL_SECONDS")]
    ttl_seconds: Option<u64>,
    #[serde(alias = "APPLY_ID")]
    apply_id: String,
    #[serde(alias = "ROW_VERSION")]
    row_version: u64,
    #[serde(alias = "VALID_FROM")]
    valid_from: u64,
    #[serde(alias = "DELETED")]
    deleted: bool,
}

impl AssumptionGrantRow {
    fn from_config(
        grant: &AssumptionGrantConfig,
        apply_id: String,
        row_version: u64,
        valid_from: u64,
        deleted: bool,
    ) -> Self {
        Self {
            subject_id: grant.subject.clone(),
            source_tenant_id: grant.source_tenant.clone(),
            target_tenant_id: grant.target_tenant.clone(),
            target_roles_json: serialize_json(&grant.target_roles),
            ttl_seconds: grant.ttl_seconds,
            apply_id,
            row_version,
            valid_from,
            deleted,
        }
    }

    fn into_config(self) -> Result<AssumptionGrantConfig, DynError> {
        Ok(AssumptionGrantConfig {
            subject: self.subject_id,
            source_tenant: self.source_tenant_id,
            target_tenant: self.target_tenant_id,
            target_roles: serde_json::from_str(&self.target_roles_json)?,
            ttl_seconds: self.ttl_seconds,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ActionRow {
    #[serde(alias = "ACTION_NAME")]
    action_name: String,
    #[serde(alias = "DESCRIPTION")]
    description: Option<String>,
    #[serde(alias = "APPLY_ID")]
    apply_id: String,
    #[serde(alias = "ROW_VERSION")]
    row_version: u64,
    #[serde(alias = "VALID_FROM")]
    valid_from: u64,
    #[serde(alias = "DELETED")]
    deleted: bool,
}

impl ActionRow {
    fn from_config(
        action: &ActionSpec,
        apply_id: String,
        row_version: u64,
        valid_from: u64,
        deleted: bool,
    ) -> Self {
        Self {
            action_name: action.name.clone(),
            description: action.description.clone(),
            apply_id,
            row_version,
            valid_from,
            deleted,
        }
    }

    fn into_config(self) -> ActionSpec {
        ActionSpec {
            name: self.action_name,
            description: self.description,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TemplateRow {
    #[serde(alias = "TENANT_ID")]
    tenant_id: String,
    #[serde(alias = "TEMPLATE_KEY")]
    template_key: String,
    #[serde(alias = "SOURCE_TENANT_ID")]
    source_tenant_id: Option<String>,
    #[serde(alias = "SOURCE_TEMPLATE_KEY")]
    source_template_key: Option<String>,
    #[serde(alias = "SOURCE_MODE")]
    source_mode: Option<String>,
    #[serde(alias = "POLICIES_JSON")]
    policies_json: String,
    #[serde(alias = "APPLY_ID")]
    apply_id: String,
    #[serde(alias = "ROW_VERSION")]
    row_version: u64,
    #[serde(alias = "VALID_FROM")]
    valid_from: u64,
    #[serde(alias = "DELETED")]
    deleted: bool,
}

impl TemplateRow {
    fn from_config(
        template: &TemplateConfig,
        apply_id: String,
        row_version: u64,
        valid_from: u64,
        deleted: bool,
    ) -> Self {
        let (source_tenant_id, source_template_key, source_mode) = template
            .source
            .as_ref()
            .map(|source| {
                (
                    Some(source.tenant.clone()),
                    Some(source.key.clone()),
                    Some(source.mode.clone()),
                )
            })
            .unwrap_or((None, None, None));

        Self {
            tenant_id: template.tenant.clone(),
            template_key: template.key.clone(),
            source_tenant_id,
            source_template_key,
            source_mode,
            policies_json: serialize_json(&template.policies),
            apply_id,
            row_version,
            valid_from,
            deleted,
        }
    }

    fn into_config(self) -> Result<TemplateConfig, DynError> {
        let source = match (
            self.source_tenant_id,
            self.source_template_key,
            self.source_mode,
        ) {
            (Some(tenant), Some(key), Some(mode)) => {
                Some(TemplateSourceConfig { tenant, key, mode })
            }
            (None, None, None) => None,
            (tenant, key, mode) => {
                return Err(Box::<std::io::Error>::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "template {} has incomplete source columns tenant={tenant:?} key={key:?} mode={mode:?}",
                        self.template_key
                    ),
                )));
            }
        };

        Ok(TemplateConfig {
            tenant: self.tenant_id,
            key: self.template_key,
            source,
            policies: serde_json::from_str::<Vec<PolicySpec>>(&self.policies_json)?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RoleRow {
    #[serde(alias = "TENANT_ID")]
    tenant_id: String,
    #[serde(alias = "ROLE_KEY")]
    role_key: String,
    #[serde(alias = "TEMPLATE_KEY")]
    template_key: Option<String>,
    #[serde(alias = "POLICIES_JSON")]
    policies_json: String,
    #[serde(alias = "APPLY_ID")]
    apply_id: String,
    #[serde(alias = "ROW_VERSION")]
    row_version: u64,
    #[serde(alias = "VALID_FROM")]
    valid_from: u64,
    #[serde(alias = "DELETED")]
    deleted: bool,
}

impl RoleRow {
    fn from_config(
        role: &RoleConfig,
        apply_id: String,
        row_version: u64,
        valid_from: u64,
        deleted: bool,
    ) -> Self {
        Self {
            tenant_id: role.tenant.clone(),
            role_key: role.key.clone(),
            template_key: role.template.clone(),
            policies_json: serialize_json(&role.policies),
            apply_id,
            row_version,
            valid_from,
            deleted,
        }
    }

    fn into_config(self) -> Result<RoleConfig, DynError> {
        Ok(RoleConfig {
            tenant: self.tenant_id,
            key: self.role_key,
            template: self.template_key,
            policies: serde_json::from_str::<Vec<PolicySpec>>(&self.policies_json)?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InviteRow {
    #[serde(alias = "INVITE_ID")]
    invite_id: String,
    #[serde(alias = "SUBJECT_ID")]
    subject_id: String,
    #[serde(alias = "REDEEM_CODE_HASH")]
    redeem_code_hash: String,
    #[serde(alias = "CREATED_AT")]
    created_at: u64,
    #[serde(alias = "EXPIRES_AT")]
    expires_at: u64,
    #[serde(alias = "REDEEMED_AT")]
    redeemed_at: Option<u64>,
    #[serde(alias = "CHANGE_ID")]
    change_id: String,
    #[serde(alias = "ROW_VERSION")]
    row_version: u64,
    #[serde(alias = "VALID_FROM")]
    valid_from: u64,
    #[serde(alias = "DELETED")]
    deleted: bool,
}

impl InviteRow {
    fn from_record(invite: &InviteRecord, change_id: String, deleted: bool) -> Self {
        Self {
            invite_id: invite.invite_id.clone(),
            subject_id: invite.subject.clone(),
            redeem_code_hash: invite.redeem_code_hash.clone(),
            created_at: invite.created_at,
            expires_at: invite.expires_at,
            redeemed_at: invite.redeemed_at,
            change_id,
            row_version: invite.row_version,
            valid_from: invite.valid_from,
            deleted,
        }
    }

    fn into_record(self) -> InviteRecord {
        InviteRecord {
            invite_id: self.invite_id,
            subject: self.subject_id,
            redeem_code_hash: self.redeem_code_hash,
            created_at: self.created_at,
            expires_at: self.expires_at,
            redeemed_at: self.redeemed_at,
            valid_from: self.valid_from,
            row_version: self.row_version,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SubjectCredentialRow {
    #[serde(alias = "SUBJECT_ID")]
    subject_id: String,
    #[serde(alias = "SALT")]
    salt: String,
    #[serde(alias = "PASSWORD_HASH")]
    password_hash: String,
    #[serde(alias = "CREDENTIAL_VALID_TO")]
    credential_valid_to: Option<u64>,
    #[serde(alias = "CHANGE_ID")]
    change_id: String,
    #[serde(alias = "ROW_VERSION")]
    row_version: u64,
    #[serde(alias = "VALID_FROM")]
    valid_from: u64,
    #[serde(alias = "DELETED")]
    deleted: bool,
}

impl SubjectCredentialRow {
    fn from_record(credential: &CredentialRecord, change_id: String, deleted: bool) -> Self {
        Self {
            subject_id: credential.subject.clone(),
            salt: credential.salt.clone(),
            password_hash: credential.password_hash.clone(),
            credential_valid_to: credential.valid_to,
            change_id,
            row_version: credential.row_version,
            valid_from: credential.valid_from,
            deleted,
        }
    }

    fn into_record(self) -> CredentialRecord {
        CredentialRecord {
            subject: self.subject_id,
            salt: self.salt,
            password_hash: self.password_hash,
            valid_from: self.valid_from,
            valid_to: self.credential_valid_to,
            row_version: self.row_version,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SessionRow {
    #[serde(alias = "SESSION_ID")]
    session_id: String,
    #[serde(alias = "SUBJECT_ID")]
    subject_id: String,
    #[serde(alias = "TENANT_ID")]
    tenant_id: String,
    #[serde(alias = "CREATED_AT")]
    created_at: u64,
    #[serde(alias = "LAST_SEEN_AT")]
    last_seen_at: u64,
    #[serde(alias = "SESSION_VALID_TO")]
    session_valid_to: Option<u64>,
    #[serde(alias = "CHANGE_ID")]
    change_id: String,
    #[serde(alias = "ROW_VERSION")]
    row_version: u64,
    #[serde(alias = "VALID_FROM")]
    valid_from: u64,
    #[serde(alias = "DELETED")]
    deleted: bool,
}

impl SessionRow {
    fn from_record(session: &SessionRecord, change_id: String, deleted: bool) -> Self {
        Self {
            session_id: session.session_id.clone(),
            subject_id: session.subject.clone(),
            tenant_id: session.tenant.clone(),
            created_at: session.created_at,
            last_seen_at: session.last_seen_at,
            session_valid_to: session.valid_to,
            change_id,
            row_version: session.row_version,
            valid_from: session.valid_from,
            deleted,
        }
    }

    fn into_record(self) -> SessionRecord {
        SessionRecord {
            session_id: self.session_id,
            subject: self.subject_id,
            tenant: self.tenant_id,
            created_at: self.created_at,
            last_seen_at: self.last_seen_at,
            valid_from: self.valid_from,
            valid_to: self.session_valid_to,
            row_version: self.row_version,
        }
    }
}

impl FelderaManagedStore {
    pub fn new(client: FelderaClient, config: FelderaConfig) -> Self {
        Self {
            pipeline_name: format!("{}_controlplane", config.pipeline_prefix),
            client,
            config,
        }
    }

    // r[impl config.managed.feldera-authoritative-store]
    pub async fn ensure_pipeline(&self) -> Result<(), DynError> {
        let desired = DesiredPipeline {
            name: self.pipeline_name.clone(),
            description: "Conclave managed control-plane state".to_owned(),
            program_code: managed_store_sql(),
            program_config: Some(PipelineProgramConfig {
                profile: Some(self.config.compile_profile.clone()),
            }),
            runtime_config: None,
        };
        let current = self.client.get_pipeline(&self.pipeline_name, "all").await?;

        match current {
            None => {
                self.client.create_pipeline(&desired).await?;
                self.client
                    .start_pipeline(
                        &self.pipeline_name,
                        &crate::feldera::StartPipelineRequest {
                            initial: "paused".to_owned(),
                            bootstrap_policy: None,
                        },
                    )
                    .await?;
            }
            Some(current) => {
                let program_code_matches =
                    current.program_code.as_deref() == Some(desired.program_code.as_str());
                let profile_matches = current.program_config == desired.program_config;
                if !program_code_matches || !profile_matches {
                    self.client.patch_pipeline(&desired).await?;
                }
            }
        }

        self.wait_for_queryable_pipeline().await?;

        Ok(())
    }

    pub async fn bootstrap_if_empty(&self, managed: &ManagedConfig) -> Result<bool, DynError> {
        self.ensure_pipeline().await?;
        let rows = self.query_apply_commit_count().await?;

        if rows.first().map(|row| row.count).unwrap_or(0) == 0 {
            let planned = self.build_apply_plan(managed).await?;
            let (apply_id, valid_from) = self.issue_apply_identity(managed)?;
            self.persist_planned_apply(&planned, &apply_id, valid_from)
                .await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    // r[impl config.managed.store.current-state-views]
    pub async fn load_managed(&self) -> Result<ManagedConfig, DynError> {
        self.ensure_pipeline().await?;

        let mut tenants = self
            .load_current_rows::<TenantRow>("current_tenant")
            .await?
            .into_iter()
            .map(TenantRow::into_config)
            .collect::<Vec<_>>();
        let mut subjects = self
            .load_current_rows::<SubjectRow>("current_subject")
            .await?
            .into_iter()
            .map(SubjectRow::into_config)
            .collect::<Vec<_>>();
        let mut memberships = Vec::new();
        for row in self
            .load_current_rows::<MembershipRow>("current_membership")
            .await?
        {
            memberships.push(row.into_config()?);
        }
        let mut assumption_grants = Vec::new();
        for row in self
            .load_current_rows::<AssumptionGrantRow>("current_assumption_grant")
            .await?
        {
            assumption_grants.push(row.into_config()?);
        }
        let mut catalog = self
            .load_current_rows::<ActionRow>("current_action")
            .await?
            .into_iter()
            .map(ActionRow::into_config)
            .collect::<Vec<_>>();
        let mut templates = Vec::new();
        for row in self
            .load_current_rows::<TemplateRow>("current_template")
            .await?
        {
            templates.push(row.into_config()?);
        }
        let mut roles = Vec::new();
        for row in self.load_current_rows::<RoleRow>("current_role").await? {
            roles.push(row.into_config()?);
        }

        tenants.sort_by(|left, right| left.id.cmp(&right.id));
        subjects.sort_by(|left, right| left.id.cmp(&right.id));
        memberships.sort_by(|left, right| {
            left.tenant
                .cmp(&right.tenant)
                .then_with(|| left.subject.cmp(&right.subject))
        });
        assumption_grants.sort_by(|left, right| {
            left.source_tenant
                .cmp(&right.source_tenant)
                .then_with(|| left.target_tenant.cmp(&right.target_tenant))
                .then_with(|| left.subject.cmp(&right.subject))
        });
        templates.sort_by(|left, right| {
            left.tenant
                .cmp(&right.tenant)
                .then_with(|| left.key.cmp(&right.key))
        });
        roles.sort_by(|left, right| {
            left.tenant
                .cmp(&right.tenant)
                .then_with(|| left.key.cmp(&right.key))
        });
        catalog.sort_by(|left, right| left.name.cmp(&right.name));

        Ok(ManagedConfig {
            catalog: conclave_managed_config::ActionCatalogConfig { actions: catalog },
            templates,
            roles,
            tenants,
            subjects,
            memberships,
            assumption_grants,
        })
    }

    pub async fn load_latest_apply_id(&self) -> Result<Option<String>, DynError> {
        self.ensure_pipeline().await?;
        let rows: Vec<LatestApplyRow> = self
            .client
            .query_json(
                &self.pipeline_name,
                "SELECT apply_id FROM apply_commit WHERE committed = TRUE ORDER BY committed_at DESC LIMIT 1",
            )
            .await?;

        Ok(rows.into_iter().next().map(|row| row.apply_id))
    }

    pub async fn load_latest_managed_apply(&self) -> Result<Option<StoredManagedApply>, DynError> {
        self.ensure_pipeline().await?;
        let rows: Vec<ManagedApplyRow> = self
            .client
            .query_json(
                &self.pipeline_name,
                r#"
SELECT ma.*
FROM managed_apply ma
JOIN apply_commit ac
  ON ma.apply_id = ac.apply_id
 AND ac.committed = TRUE
ORDER BY ma.applied_at DESC
LIMIT 1
"#,
            )
            .await?;

        rows.into_iter()
            .next()
            .map(ManagedApplyRow::into_record)
            .transpose()
    }

    // r[impl config.managed.store.runtime-provenance]
    pub async fn load_runtime_auth_state(
        &self,
    ) -> Result<(Vec<InviteRecord>, Vec<CredentialRecord>, Vec<SessionRecord>), DynError> {
        self.ensure_pipeline().await?;

        let mut invites = self
            .load_current_rows::<InviteRow>("current_invite")
            .await?
            .into_iter()
            .map(InviteRow::into_record)
            .collect::<Vec<_>>();
        let mut credentials = self
            .load_current_rows::<SubjectCredentialRow>("current_subject_credential")
            .await?
            .into_iter()
            .map(SubjectCredentialRow::into_record)
            .collect::<Vec<_>>();
        let mut sessions = self
            .load_current_rows::<SessionRow>("current_session")
            .await?
            .into_iter()
            .map(SessionRow::into_record)
            .collect::<Vec<_>>();

        invites.sort_by(|left, right| left.invite_id.cmp(&right.invite_id));
        credentials.sort_by(|left, right| left.subject.cmp(&right.subject));
        sessions.sort_by(|left, right| {
            left.tenant
                .cmp(&right.tenant)
                .then_with(|| left.session_id.cmp(&right.session_id))
        });

        Ok((invites, credentials, sessions))
    }

    // r[impl config.managed.plan-before-apply]
    // r[impl config.managed.server-authoritative-validation]
    pub async fn plan(&self, desired: &ManagedConfig) -> Result<ManagedStorePlan, DynError> {
        self.ensure_pipeline().await?;
        let planned = self.build_apply_plan(desired).await?;

        Ok(ManagedStorePlan {
            noop: planned.noop,
            summary: planned.summary,
            changes: planned.changes,
        })
    }

    // r[impl config.managed.apply-operation]
    // r[impl config.managed.idempotent-apply]
    // r[impl config.managed.versioned-history]
    // r[impl config.managed.store.typed-entity-tables]
    // r[impl config.managed.store.apply-provenance]
    // r[impl config.managed.store.managed-apply-state]
    // r[impl config.managed.store.managed-ownership-state]
    // r[impl config.managed.store.transactional-apply]
    // r[impl config.managed.store.transactional-recovery]
    // r[impl config.managed.partial-failure]
    pub async fn apply(&self, desired: &ManagedConfig) -> Result<StoredManagedApply, DynError> {
        self.ensure_pipeline().await?;
        let planned = self.build_apply_plan(desired).await?;
        let (apply_id, valid_from) = self.issue_apply_identity(desired)?;
        let checkpoint = self
            .client
            .checkpoint_now(&self.pipeline_name)
            .await
            .map_err(|err| {
                Box::new(ManagedApplyFailure::new(
                    apply_id.clone(),
                    ManagedApplyPhase::Checkpoint,
                    None,
                    None,
                    planned.summary.clone(),
                    planned.changes.clone(),
                    err.to_string(),
                )) as DynError
            })?;
        self.client
            .wait_for_checkpoint(&self.pipeline_name, checkpoint.checkpoint_sequence_number)
            .await
            .map_err(|err| {
                Box::new(ManagedApplyFailure::new(
                    apply_id.clone(),
                    ManagedApplyPhase::Checkpoint,
                    None,
                    Some(checkpoint.checkpoint_sequence_number),
                    planned.summary.clone(),
                    planned.changes.clone(),
                    err.to_string(),
                )) as DynError
            })?;

        let transaction = self
            .client
            .start_transaction(&self.pipeline_name)
            .await
            .map_err(|err| {
                Box::new(ManagedApplyFailure::new(
                    apply_id.clone(),
                    ManagedApplyPhase::StartTransaction,
                    None,
                    Some(checkpoint.checkpoint_sequence_number),
                    planned.summary.clone(),
                    planned.changes.clone(),
                    err.to_string(),
                )) as DynError
            })?;

        if let Err(err) = self
            .persist_planned_apply(&planned, &apply_id, valid_from)
            .await
        {
            return Err(Box::new(
                self.recover_failed_apply(
                    &planned,
                    &apply_id,
                    ManagedApplyPhase::Ingress,
                    Some(transaction.transaction_id),
                    Some(checkpoint.checkpoint_sequence_number),
                    err.to_string(),
                )
                .await,
            ));
        }

        if let Err(err) = self.client.commit_transaction(&self.pipeline_name).await {
            return Err(Box::new(
                self.recover_failed_apply(
                    &planned,
                    &apply_id,
                    ManagedApplyPhase::Commit,
                    Some(transaction.transaction_id),
                    Some(checkpoint.checkpoint_sequence_number),
                    err.to_string(),
                )
                .await,
            ));
        }

        if let Err(err) = self
            .client
            .wait_for_no_transaction(&self.pipeline_name)
            .await
        {
            return Err(Box::new(
                self.recover_failed_apply(
                    &planned,
                    &apply_id,
                    ManagedApplyPhase::CommitVisibility,
                    Some(transaction.transaction_id),
                    Some(checkpoint.checkpoint_sequence_number),
                    err.to_string(),
                )
                .await,
            ));
        }

        Ok(stored_apply_from_plan(
            desired, &planned, apply_id, valid_from,
        ))
    }

    // r[impl identity.subject.invite.audit-history]
    pub async fn persist_invite(&self, invite: &InviteRecord) -> Result<(), DynError> {
        self.persist_runtime_auth_changes(vec![RuntimeAuthChange::Invite(invite.clone())])
            .await
    }

    // r[impl identity.subject.linked-credentials.versioned-history]
    // r[impl identity.subject.invite.audit-history]
    pub async fn persist_redeemed_invite(
        &self,
        invite: &InviteRecord,
        expected_previous_row_version: u64,
        credential: &CredentialRecord,
    ) -> Result<(), DynError> {
        let (invites, _, _) = self.load_runtime_auth_state().await?;
        let current = invites
            .iter()
            .find(|entry| entry.invite_id == invite.invite_id)
            .ok_or_else(|| {
                Box::<std::io::Error>::new(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("invite {} not found in runtime store", invite.invite_id),
                )) as DynError
            })?;

        if current.row_version != expected_previous_row_version || current.redeemed_at.is_some() {
            return Err(Box::<std::io::Error>::new(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "invite has already been redeemed or changed",
            )));
        }

        self.persist_runtime_auth_changes(vec![
            RuntimeAuthChange::Invite(invite.clone()),
            RuntimeAuthChange::SubjectCredential(credential.clone()),
        ])
        .await
    }

    // r[impl authn.session.persisted-history]
    pub async fn persist_session(&self, session: &SessionRecord) -> Result<(), DynError> {
        self.persist_runtime_auth_changes(vec![RuntimeAuthChange::Session(session.clone())])
            .await
    }

    async fn load_current_rows<T>(&self, view_name: &str) -> Result<Vec<T>, DynError>
    where
        T: DeserializeOwned,
    {
        let sql = select_current_sql(view_name);
        self.client.query_json(&self.pipeline_name, &sql).await
    }

    async fn load_current_ownership_rows(&self) -> Result<Vec<ManagedOwnershipRow>, DynError> {
        self.load_current_rows::<ManagedOwnershipRow>("current_managed_ownership")
            .await
    }

    // r[impl config.managed.store.row-version-per-entity]
    async fn next_row_version(
        &self,
        table_name: &str,
        key_filters: &[(&str, String)],
    ) -> Result<u64, DynError> {
        let sql = select_max_row_version_sql(table_name, key_filters);
        let rows: Vec<CountRow> = self.client.query_json(&self.pipeline_name, &sql).await?;
        Ok(rows.first().map(|row| row.count).unwrap_or(0) + 1)
    }

    // r[impl config.managed.store.runtime-provenance]
    async fn persist_runtime_auth_changes(
        &self,
        changes: Vec<RuntimeAuthChange>,
    ) -> Result<(), DynError> {
        self.ensure_pipeline().await?;
        if changes.is_empty() {
            return Ok(());
        }

        let valid_from = now_unix_seconds()?;
        let change_id = format!(
            "change-{}",
            &digest_hex(&format!(
                "{valid_from}:{}",
                serde_json::to_string(&changes)?
            ))[0..12]
        );

        for change in changes {
            match change {
                RuntimeAuthChange::Invite(invite) => {
                    self.client
                        .insert_json_rows(
                            &self.pipeline_name,
                            "invite",
                            vec![InviteRow::from_record(&invite, change_id.clone(), false)],
                        )
                        .await?;
                }
                RuntimeAuthChange::SubjectCredential(credential) => {
                    self.client
                        .insert_json_rows(
                            &self.pipeline_name,
                            "subject_credential",
                            vec![SubjectCredentialRow::from_record(
                                &credential,
                                change_id.clone(),
                                false,
                            )],
                        )
                        .await?;
                }
                RuntimeAuthChange::Session(session) => {
                    self.client
                        .insert_json_rows(
                            &self.pipeline_name,
                            "session_state",
                            vec![SessionRow::from_record(&session, change_id.clone(), false)],
                        )
                        .await?;
                }
            }
        }

        self.client
            .insert_json_rows(
                &self.pipeline_name,
                "auth_runtime_commit",
                vec![AuthRuntimeCommitRow {
                    change_id,
                    committed_at: valid_from,
                    committed: true,
                }],
            )
            .await?;

        Ok(())
    }

    async fn wait_for_queryable_pipeline(&self) -> Result<(), DynError> {
        for _ in 0..600 {
            if let Some(pipeline) = self.client.get_pipeline(&self.pipeline_name, "all").await? {
                match pipeline.program_status.as_deref() {
                    Some("Success") | Some("SqlCompiled") => {
                        if self.query_apply_commit_count().await.is_ok() {
                            return Ok(());
                        }
                    }
                    Some(status)
                        if status.contains("Error")
                            || status == "SqlError"
                            || status == "RustError" =>
                    {
                        return Err(Box::<std::io::Error>::new(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!(
                                "pipeline {} is not queryable because compilation ended in {status}",
                                self.pipeline_name
                            ),
                        )));
                    }
                    _ => {}
                }
            }

            actix_web::rt::time::sleep(Duration::from_secs(1)).await;
        }

        Err(Box::<std::io::Error>::new(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!(
                "timed out waiting for pipeline {} to become queryable",
                self.pipeline_name
            ),
        )))
    }

    async fn query_apply_commit_count(&self) -> Result<Vec<CountRow>, DynError> {
        self.client
            .query_json(
                &self.pipeline_name,
                "SELECT CAST(COUNT(*) AS BIGINT) AS count FROM apply_commit WHERE committed = TRUE",
            )
            .await
    }

    // r[impl config.managed.three-way-diff]
    // r[impl config.managed.ownership]
    // r[impl config.managed.store.entity-fingerprint]
    async fn build_apply_plan(
        &self,
        desired: &ManagedConfig,
    ) -> Result<ManagedApplyPlan, DynError> {
        let issues = ControlPlaneState::validate(desired);
        if !issues.is_empty() {
            return Err(Box::<std::io::Error>::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                issues.join("; "),
            )));
        }

        let current = self
            .load_managed()
            .await
            .unwrap_or_else(|_| empty_managed_config());
        let ownership_rows = self.load_current_ownership_rows().await.unwrap_or_default();
        let ownership = ownership_rows
            .into_iter()
            .map(|row| ((row.entity_kind.clone(), row.entity_key.clone()), row))
            .collect::<BTreeMap<_, _>>();

        let tenant_plan = plan_entity_changes(
            "tenant",
            &current.tenants,
            &desired.tenants,
            &ownership,
            |entry| entry.id.clone(),
        );
        let subject_plan = plan_entity_changes(
            "subject",
            &current.subjects,
            &desired.subjects,
            &ownership,
            |entry| entry.id.clone(),
        );
        let membership_plan = plan_entity_changes(
            "membership",
            &current.memberships,
            &desired.memberships,
            &ownership,
            |entry| format!("{}@{}", entry.subject, entry.tenant),
        );
        let assumption_grant_plan = plan_entity_changes(
            "assumption_grant",
            &current.assumption_grants,
            &desired.assumption_grants,
            &ownership,
            |entry| {
                format!(
                    "{}:{}:{}",
                    entry.subject, entry.source_tenant, entry.target_tenant
                )
            },
        );
        let action_plan = plan_entity_changes(
            "action",
            &current.catalog.actions,
            &desired.catalog.actions,
            &ownership,
            |entry| entry.name.clone(),
        );
        let template_plan = plan_entity_changes(
            "template",
            &current.templates,
            &desired.templates,
            &ownership,
            |entry| format!("{}:{}", entry.tenant, entry.key),
        );
        let role_plan = plan_entity_changes(
            "role",
            &current.roles,
            &desired.roles,
            &ownership,
            |entry| format!("{}:{}", entry.tenant, entry.key),
        );

        let summary = sum_mutation_counts(&[
            summarize_entity_changes(&tenant_plan.changes),
            summarize_entity_changes(&subject_plan.changes),
            summarize_entity_changes(&membership_plan.changes),
            summarize_entity_changes(&assumption_grant_plan.changes),
            summarize_entity_changes(&action_plan.changes),
            summarize_entity_changes(&template_plan.changes),
            summarize_entity_changes(&role_plan.changes),
        ]);

        let changes = tenant_plan
            .reported_changes
            .iter()
            .chain(subject_plan.reported_changes.iter())
            .chain(membership_plan.reported_changes.iter())
            .chain(assumption_grant_plan.reported_changes.iter())
            .chain(action_plan.reported_changes.iter())
            .chain(template_plan.reported_changes.iter())
            .chain(role_plan.reported_changes.iter())
            .cloned()
            .collect::<Vec<_>>();
        let ownership_mutations = tenant_plan
            .ownership
            .into_iter()
            .chain(subject_plan.ownership.into_iter())
            .chain(membership_plan.ownership.into_iter())
            .chain(assumption_grant_plan.ownership.into_iter())
            .chain(action_plan.ownership.into_iter())
            .chain(template_plan.ownership.into_iter())
            .chain(role_plan.ownership.into_iter())
            .collect::<Vec<_>>();
        let desired_bundle_json = serialize_json(desired);
        let noop = changes.is_empty() && ownership_mutations.is_empty();

        Ok(ManagedApplyPlan {
            desired_bundle_fingerprint: digest_hex(&desired_bundle_json),
            desired_bundle_json,
            summary,
            changes,
            noop,
            tenant_changes: tenant_plan.changes,
            subject_changes: subject_plan.changes,
            membership_changes: membership_plan.changes,
            assumption_grant_changes: assumption_grant_plan.changes,
            action_changes: action_plan.changes,
            template_changes: template_plan.changes,
            role_changes: role_plan.changes,
            ownership_mutations,
        })
    }

    fn issue_apply_identity(&self, desired: &ManagedConfig) -> Result<(String, u64), DynError> {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let apply_id = format!(
            "apply-{}",
            &digest_hex(&format!("{nonce}:{}", serde_json::to_string(desired)?))[0..12]
        );
        let valid_from = now_unix_seconds()?;

        Ok((apply_id, valid_from))
    }

    async fn recover_failed_apply(
        &self,
        planned: &ManagedApplyPlan,
        apply_id: &str,
        phase: ManagedApplyPhase,
        transaction_id: Option<u64>,
        checkpoint_sequence_number: Option<u64>,
        error: String,
    ) -> ManagedApplyFailure {
        let mut failure = ManagedApplyFailure::new(
            apply_id.to_owned(),
            phase,
            transaction_id,
            checkpoint_sequence_number,
            planned.summary.clone(),
            planned.changes.clone(),
            error,
        );

        failure.recovery_attempted = true;
        match self.recover_to_last_checkpoint().await {
            Ok(()) => {
                failure.recovery_succeeded = true;
                failure.rolled_back_resources = failure.affected_resources.clone();
            }
            Err(err) => {
                failure.operator_intervention = vec![
                    "inspect the Feldera control-plane pipeline before retrying managed apply"
                        .to_owned(),
                    "confirm checkpoint-and-resume is enabled for the pipeline".to_owned(),
                    format!("recovery failed: {err}"),
                ];
            }
        }

        failure
    }

    async fn recover_to_last_checkpoint(&self) -> Result<(), DynError> {
        self.client.stop_pipeline(&self.pipeline_name, true).await?;
        self.client
            .start_pipeline(
                &self.pipeline_name,
                &crate::feldera::StartPipelineRequest {
                    initial: "paused".to_owned(),
                    bootstrap_policy: None,
                },
            )
            .await?;
        self.wait_for_queryable_pipeline().await
    }

    async fn persist_planned_apply(
        &self,
        planned: &ManagedApplyPlan,
        apply_id: &str,
        valid_from: u64,
    ) -> Result<(), DynError> {
        for change in &planned.tenant_changes {
            let deleted = matches!(change.operation, ManagedEntityOperation::Delete);
            let row_version = self
                .next_row_version("tenant", &[("tenant_id", change.value.id.clone())])
                .await?;
            self.client
                .insert_json_rows(
                    &self.pipeline_name,
                    "tenant",
                    vec![TenantRow::from_config(
                        &change.value,
                        apply_id.to_owned(),
                        row_version,
                        valid_from,
                        deleted,
                    )],
                )
                .await?;
        }

        for change in &planned.subject_changes {
            let deleted = matches!(change.operation, ManagedEntityOperation::Delete);
            let row_version = self
                .next_row_version("subject", &[("subject_id", change.value.id.clone())])
                .await?;
            self.client
                .insert_json_rows(
                    &self.pipeline_name,
                    "subject",
                    vec![SubjectRow::from_config(
                        &change.value,
                        apply_id.to_owned(),
                        row_version,
                        valid_from,
                        deleted,
                    )],
                )
                .await?;
        }

        for change in &planned.membership_changes {
            let deleted = matches!(change.operation, ManagedEntityOperation::Delete);
            let row_version = self
                .next_row_version(
                    "membership",
                    &[
                        ("tenant_id", change.value.tenant.clone()),
                        ("subject_id", change.value.subject.clone()),
                    ],
                )
                .await?;
            self.client
                .insert_json_rows(
                    &self.pipeline_name,
                    "membership",
                    vec![MembershipRow::from_config(
                        &change.value,
                        apply_id.to_owned(),
                        row_version,
                        valid_from,
                        deleted,
                    )],
                )
                .await?;
        }

        for change in &planned.assumption_grant_changes {
            let deleted = matches!(change.operation, ManagedEntityOperation::Delete);
            let row_version = self
                .next_row_version(
                    "assumption_grant",
                    &[
                        ("subject_id", change.value.subject.clone()),
                        ("source_tenant_id", change.value.source_tenant.clone()),
                        ("target_tenant_id", change.value.target_tenant.clone()),
                    ],
                )
                .await?;
            self.client
                .insert_json_rows(
                    &self.pipeline_name,
                    "assumption_grant",
                    vec![AssumptionGrantRow::from_config(
                        &change.value,
                        apply_id.to_owned(),
                        row_version,
                        valid_from,
                        deleted,
                    )],
                )
                .await?;
        }

        for change in &planned.action_changes {
            let deleted = matches!(change.operation, ManagedEntityOperation::Delete);
            let row_version = self
                .next_row_version("action", &[("action_name", change.value.name.clone())])
                .await?;
            self.client
                .insert_json_rows(
                    &self.pipeline_name,
                    "action",
                    vec![ActionRow::from_config(
                        &change.value,
                        apply_id.to_owned(),
                        row_version,
                        valid_from,
                        deleted,
                    )],
                )
                .await?;
        }

        for change in &planned.template_changes {
            let deleted = matches!(change.operation, ManagedEntityOperation::Delete);
            let row_version = self
                .next_row_version(
                    "template",
                    &[
                        ("tenant_id", change.value.tenant.clone()),
                        ("template_key", change.value.key.clone()),
                    ],
                )
                .await?;
            self.client
                .insert_json_rows(
                    &self.pipeline_name,
                    "template",
                    vec![TemplateRow::from_config(
                        &change.value,
                        apply_id.to_owned(),
                        row_version,
                        valid_from,
                        deleted,
                    )],
                )
                .await?;
        }

        for change in &planned.role_changes {
            let deleted = matches!(change.operation, ManagedEntityOperation::Delete);
            let row_version = self
                .next_row_version(
                    "role",
                    &[
                        ("tenant_id", change.value.tenant.clone()),
                        ("role_key", change.value.key.clone()),
                    ],
                )
                .await?;
            self.client
                .insert_json_rows(
                    &self.pipeline_name,
                    "role",
                    vec![RoleRow::from_config(
                        &change.value,
                        apply_id.to_owned(),
                        row_version,
                        valid_from,
                        deleted,
                    )],
                )
                .await?;
        }

        for mutation in &planned.ownership_mutations {
            let row_version = self
                .next_row_version(
                    "managed_ownership",
                    &[
                        ("entity_kind", mutation.entity_kind.to_owned()),
                        ("entity_key", mutation.entity_key.clone()),
                    ],
                )
                .await?;
            self.client
                .insert_json_rows(
                    &self.pipeline_name,
                    "managed_ownership",
                    vec![ManagedOwnershipRow::from_mutation(
                        mutation,
                        apply_id.to_owned(),
                        row_version,
                        valid_from,
                    )],
                )
                .await?;
        }

        self.client
            .insert_json_rows(
                &self.pipeline_name,
                "managed_apply",
                vec![ManagedApplyRow {
                    apply_id: apply_id.to_owned(),
                    applied_at: valid_from,
                    bundle_json: planned.desired_bundle_json.clone(),
                    bundle_fingerprint: planned.desired_bundle_fingerprint.clone(),
                    created_count: planned.summary.created as u64,
                    updated_count: planned.summary.updated as u64,
                    deleted_count: planned.summary.deleted as u64,
                    noop: planned.noop,
                }],
            )
            .await?;

        self.client
            .insert_json_rows(
                &self.pipeline_name,
                "apply_commit",
                vec![ApplyCommitRow {
                    apply_id: apply_id.to_owned(),
                    committed_at: valid_from,
                    committed: true,
                }],
            )
            .await?;

        Ok(())
    }
}

fn stored_apply_from_plan(
    desired: &ManagedConfig,
    planned: &ManagedApplyPlan,
    apply_id: String,
    valid_from: u64,
) -> StoredManagedApply {
    StoredManagedApply {
        apply_id,
        applied_at: valid_from,
        bundle_fingerprint: planned.desired_bundle_fingerprint.clone(),
        summary: planned.summary.clone(),
        noop: planned.noop,
        managed: desired.clone(),
    }
}

#[derive(Clone)]
struct EntityChange<T> {
    value: T,
    deleted: bool,
}

#[derive(Clone, Debug, Serialize)]
enum RuntimeAuthChange {
    Invite(InviteRecord),
    SubjectCredential(CredentialRecord),
    Session(SessionRecord),
}

fn collect_changes<T, K>(current: &[T], desired: &[T], key: K) -> Vec<EntityChange<T>>
where
    T: Clone + PartialEq,
    K: Fn(&T) -> String,
{
    let current_map: BTreeMap<String, &T> =
        current.iter().map(|entry| (key(entry), entry)).collect();
    let desired_map: BTreeMap<String, &T> =
        desired.iter().map(|entry| (key(entry), entry)).collect();
    let keys: BTreeSet<String> = current_map
        .keys()
        .chain(desired_map.keys())
        .cloned()
        .collect();
    let mut changes = Vec::new();

    for entity_key in keys {
        match (current_map.get(&entity_key), desired_map.get(&entity_key)) {
            (Some(left), Some(right)) if *left == *right => {}
            (_, Some(value)) => changes.push(EntityChange {
                value: (*value).clone(),
                deleted: false,
            }),
            (Some(value), None) => changes.push(EntityChange {
                value: (*value).clone(),
                deleted: true,
            }),
            _ => {}
        }
    }

    changes
}

fn plan_entity_changes<T, K>(
    entity_kind: &'static str,
    current: &[T],
    desired: &[T],
    ownership: &BTreeMap<(String, String), ManagedOwnershipRow>,
    key: K,
) -> EntityPlan<T>
where
    T: Clone + PartialEq + Serialize,
    K: Fn(&T) -> String,
{
    let current_map: BTreeMap<String, &T> =
        current.iter().map(|entry| (key(entry), entry)).collect();
    let desired_map: BTreeMap<String, &T> =
        desired.iter().map(|entry| (key(entry), entry)).collect();
    let mut keys: BTreeSet<String> = current_map
        .keys()
        .chain(desired_map.keys())
        .cloned()
        .collect();
    for (kind, entity_key) in ownership.keys() {
        if kind == entity_kind {
            keys.insert(entity_key.clone());
        }
    }

    let mut changes = Vec::new();
    let mut ownership_changes = Vec::new();
    let mut reported_changes = Vec::new();

    for entity_key in keys {
        let ownership_key = (entity_kind.to_owned(), entity_key.clone());
        let current_ownership = ownership.get(&ownership_key);
        let current_entry = current_map.get(&entity_key).copied();
        let desired_entry = desired_map.get(&entity_key).copied();

        match (current_entry, desired_entry) {
            (Some(left), Some(right)) if left == right => {
                let desired_fingerprint = entity_fingerprint(right);
                if ownership_needs_update(current_ownership, &desired_fingerprint) {
                    ownership_changes.push(ManagedOwnershipMutation {
                        entity_kind,
                        entity_key: entity_key.clone(),
                        desired_fingerprint: Some(desired_fingerprint),
                        deleted: false,
                    });
                    reported_changes.push(format!("adopt {entity_kind} {entity_key}"));
                }
            }
            (None, Some(value)) => {
                let desired_fingerprint = entity_fingerprint(value);
                changes.push(ManagedEntityChange {
                    value: value.clone(),
                    operation: ManagedEntityOperation::Create,
                });
                ownership_changes.push(ManagedOwnershipMutation {
                    entity_kind,
                    entity_key: entity_key.clone(),
                    desired_fingerprint: Some(desired_fingerprint),
                    deleted: false,
                });
                reported_changes.push(format!("create {entity_kind} {entity_key}"));
            }
            (Some(_), Some(value)) => {
                let desired_fingerprint = entity_fingerprint(value);
                changes.push(ManagedEntityChange {
                    value: value.clone(),
                    operation: ManagedEntityOperation::Update,
                });
                if ownership_needs_update(current_ownership, &desired_fingerprint) {
                    ownership_changes.push(ManagedOwnershipMutation {
                        entity_kind,
                        entity_key: entity_key.clone(),
                        desired_fingerprint: Some(desired_fingerprint),
                        deleted: false,
                    });
                }
                reported_changes.push(format!("update {entity_kind} {entity_key}"));
            }
            (Some(value), None) if current_ownership.is_some() => {
                changes.push(ManagedEntityChange {
                    value: value.clone(),
                    operation: ManagedEntityOperation::Delete,
                });
                ownership_changes.push(ManagedOwnershipMutation {
                    entity_kind,
                    entity_key: entity_key.clone(),
                    desired_fingerprint: None,
                    deleted: true,
                });
                reported_changes.push(format!("delete {entity_kind} {entity_key}"));
            }
            (None, None) if current_ownership.is_some() => {
                ownership_changes.push(ManagedOwnershipMutation {
                    entity_kind,
                    entity_key: entity_key.clone(),
                    desired_fingerprint: None,
                    deleted: true,
                });
                reported_changes.push(format!("release {entity_kind} {entity_key}"));
            }
            _ => {}
        }
    }

    EntityPlan {
        changes,
        ownership: ownership_changes,
        reported_changes,
    }
}

fn summarize_entity_changes<T>(changes: &[ManagedEntityChange<T>]) -> ManagedMutationCounts {
    let mut counts = ManagedMutationCounts {
        created: 0,
        updated: 0,
        deleted: 0,
    };

    for change in changes {
        match change.operation {
            ManagedEntityOperation::Create => counts.created += 1,
            ManagedEntityOperation::Update => counts.updated += 1,
            ManagedEntityOperation::Delete => counts.deleted += 1,
        }
    }

    counts
}

fn sum_mutation_counts(counts: &[ManagedMutationCounts]) -> ManagedMutationCounts {
    counts.iter().fold(
        ManagedMutationCounts {
            created: 0,
            updated: 0,
            deleted: 0,
        },
        |mut total, count| {
            total.created += count.created;
            total.updated += count.updated;
            total.deleted += count.deleted;
            total
        },
    )
}

fn ownership_needs_update(
    current: Option<&ManagedOwnershipRow>,
    desired_fingerprint: &str,
) -> bool {
    current
        .map(|row| row.desired_fingerprint != desired_fingerprint)
        .unwrap_or(true)
}

fn entity_fingerprint<T>(value: &T) -> String
where
    T: Serialize,
{
    digest_hex(&serialize_json(value))
}

// r[impl config.managed.store.sql-lower-snake-case]
fn managed_store_sql() -> String {
    let mut statements = vec![
        r#"
CREATE TABLE apply_commit (
    apply_id VARCHAR NOT NULL,
    committed_at BIGINT NOT NULL,
    committed BOOLEAN NOT NULL
) WITH ('materialized' = 'true');
"#
        .trim()
        .to_owned(),
        r#"
CREATE TABLE managed_apply (
    apply_id VARCHAR NOT NULL,
    applied_at BIGINT NOT NULL,
    bundle_json VARCHAR NOT NULL,
    bundle_fingerprint VARCHAR NOT NULL,
    created_count BIGINT NOT NULL,
    updated_count BIGINT NOT NULL,
    deleted_count BIGINT NOT NULL,
    noop BOOLEAN NOT NULL
) WITH ('materialized' = 'true');
"#
        .trim()
        .to_owned(),
        r#"
CREATE TABLE tenant (
    tenant_id VARCHAR NOT NULL,
    display_name VARCHAR,
    parent_tenant_id VARCHAR,
    state VARCHAR NOT NULL,
    apply_id VARCHAR NOT NULL,
    row_version BIGINT NOT NULL,
    valid_from BIGINT NOT NULL,
    deleted BOOLEAN NOT NULL
) WITH ('materialized' = 'true');
"#
        .trim()
        .to_owned(),
        r#"
CREATE TABLE subject (
    subject_id VARCHAR NOT NULL,
    display_name VARCHAR,
    apply_id VARCHAR NOT NULL,
    row_version BIGINT NOT NULL,
    valid_from BIGINT NOT NULL,
    deleted BOOLEAN NOT NULL
) WITH ('materialized' = 'true');
"#
        .trim()
        .to_owned(),
        r#"
CREATE TABLE membership (
    tenant_id VARCHAR NOT NULL,
    subject_id VARCHAR NOT NULL,
    roles_json VARCHAR NOT NULL,
    facts_json VARCHAR NOT NULL,
    apply_id VARCHAR NOT NULL,
    row_version BIGINT NOT NULL,
    valid_from BIGINT NOT NULL,
    deleted BOOLEAN NOT NULL
) WITH ('materialized' = 'true');
"#
        .trim()
        .to_owned(),
        r#"
CREATE TABLE assumption_grant (
    subject_id VARCHAR NOT NULL,
    source_tenant_id VARCHAR NOT NULL,
    target_tenant_id VARCHAR NOT NULL,
    target_roles_json VARCHAR NOT NULL,
    ttl_seconds BIGINT,
    apply_id VARCHAR NOT NULL,
    row_version BIGINT NOT NULL,
    valid_from BIGINT NOT NULL,
    deleted BOOLEAN NOT NULL
) WITH ('materialized' = 'true');
"#
        .trim()
        .to_owned(),
        r#"
CREATE TABLE action (
    action_name VARCHAR NOT NULL,
    description VARCHAR,
    apply_id VARCHAR NOT NULL,
    row_version BIGINT NOT NULL,
    valid_from BIGINT NOT NULL,
    deleted BOOLEAN NOT NULL
) WITH ('materialized' = 'true');
"#
        .trim()
        .to_owned(),
        r#"
CREATE TABLE template (
    tenant_id VARCHAR NOT NULL,
    template_key VARCHAR NOT NULL,
    source_tenant_id VARCHAR,
    source_template_key VARCHAR,
    source_mode VARCHAR,
    policies_json VARCHAR NOT NULL,
    apply_id VARCHAR NOT NULL,
    row_version BIGINT NOT NULL,
    valid_from BIGINT NOT NULL,
    deleted BOOLEAN NOT NULL
) WITH ('materialized' = 'true');
"#
        .trim()
        .to_owned(),
        r#"
CREATE TABLE role (
    tenant_id VARCHAR NOT NULL,
    role_key VARCHAR NOT NULL,
    template_key VARCHAR,
    policies_json VARCHAR NOT NULL,
    apply_id VARCHAR NOT NULL,
    row_version BIGINT NOT NULL,
    valid_from BIGINT NOT NULL,
    deleted BOOLEAN NOT NULL
) WITH ('materialized' = 'true');
"#
        .trim()
        .to_owned(),
        r#"
CREATE TABLE managed_ownership (
    entity_kind VARCHAR NOT NULL,
    entity_key VARCHAR NOT NULL,
    desired_fingerprint VARCHAR NOT NULL,
    apply_id VARCHAR NOT NULL,
    row_version BIGINT NOT NULL,
    valid_from BIGINT NOT NULL,
    deleted BOOLEAN NOT NULL
) WITH ('materialized' = 'true');
"#
        .trim()
        .to_owned(),
        r#"
CREATE TABLE auth_runtime_commit (
    change_id VARCHAR NOT NULL,
    committed_at BIGINT NOT NULL,
    committed BOOLEAN NOT NULL
) WITH ('materialized' = 'true');
"#
        .trim()
        .to_owned(),
        r#"
CREATE TABLE invite (
    invite_id VARCHAR NOT NULL,
    subject_id VARCHAR NOT NULL,
    redeem_code_hash VARCHAR NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    redeemed_at BIGINT,
    change_id VARCHAR NOT NULL,
    row_version BIGINT NOT NULL,
    valid_from BIGINT NOT NULL,
    deleted BOOLEAN NOT NULL
) WITH ('materialized' = 'true');
"#
        .trim()
        .to_owned(),
        r#"
CREATE TABLE subject_credential (
    subject_id VARCHAR NOT NULL,
    salt VARCHAR NOT NULL,
    password_hash VARCHAR NOT NULL,
    credential_valid_to BIGINT,
    change_id VARCHAR NOT NULL,
    row_version BIGINT NOT NULL,
    valid_from BIGINT NOT NULL,
    deleted BOOLEAN NOT NULL
) WITH ('materialized' = 'true');
"#
        .trim()
        .to_owned(),
        r#"
CREATE TABLE session_state (
    session_id VARCHAR NOT NULL,
    subject_id VARCHAR NOT NULL,
    tenant_id VARCHAR NOT NULL,
    created_at BIGINT NOT NULL,
    last_seen_at BIGINT NOT NULL,
    session_valid_to BIGINT,
    change_id VARCHAR NOT NULL,
    row_version BIGINT NOT NULL,
    valid_from BIGINT NOT NULL,
    deleted BOOLEAN NOT NULL
) WITH ('materialized' = 'true');
"#
        .trim()
        .to_owned(),
    ];

    for spec in MANAGED_VIEW_SPECS.iter().chain(RUNTIME_VIEW_SPECS.iter()) {
        statements.push(versioned_view_sql(*spec));
        statements.push(current_view_sql(*spec));
    }

    statements.join("\n\n")
}

fn versioned_view_sql(spec: TemporalViewSpec) -> String {
    let source_table = spec.table_name;
    let key_predicates = spec
        .key_columns
        .iter()
        .map(|column| format!("t2.{column} = t1.{column}"))
        .collect::<Vec<_>>()
        .join("\n          AND ");

    format!(
        r#"
CREATE MATERIALIZED VIEW {versioned_view} AS
SELECT
    t1.*,
    (
        SELECT MIN(t2.valid_from)
        FROM {source_table} t2
        JOIN {commit_table} c2
          ON t2.{provenance_column} = c2.{provenance_column}
         AND c2.committed = TRUE
        WHERE {key_predicates}
          AND t2.row_version > t1.row_version
    ) AS valid_to
FROM {source_table} t1
JOIN {commit_table} c
  ON t1.{provenance_column} = c.{provenance_column}
 AND c.committed = TRUE;
"#,
        versioned_view = spec.versioned_view,
        source_table = source_table,
        commit_table = spec.commit_table,
        provenance_column = spec.provenance_column,
        key_predicates = key_predicates,
    )
    .trim()
    .to_owned()
}

fn current_view_sql(spec: TemporalViewSpec) -> String {
    format!(
        r#"
CREATE MATERIALIZED VIEW {current_view} AS
SELECT *
FROM {versioned_view}
WHERE valid_to IS NULL
  AND deleted = FALSE;
"#,
        current_view = spec.current_view,
        versioned_view = spec.versioned_view,
    )
    .trim()
    .to_owned()
}

fn select_current_sql(view_name: &str) -> String {
    format!("SELECT * FROM {view_name}")
}

#[cfg(test)]
fn select_history_sql(view_name: &str, key_filters: &[(&str, String)]) -> String {
    let predicates = equality_predicates(key_filters);
    format!("SELECT * FROM {view_name} WHERE {predicates} ORDER BY row_version")
}

fn select_max_row_version_sql(table_name: &str, key_filters: &[(&str, String)]) -> String {
    let predicates = equality_predicates(key_filters);
    format!(
        "SELECT CAST(COALESCE(MAX(row_version), 0) AS BIGINT) AS count FROM {table_name} WHERE {predicates}"
    )
}

fn equality_predicates(key_filters: &[(&str, String)]) -> String {
    key_filters
        .iter()
        .map(|(column, value)| format!("{column} = '{}'", escape_sql(value)))
        .collect::<Vec<_>>()
        .join(" AND ")
}

fn empty_managed_config() -> ManagedConfig {
    ManagedConfig::load_from_str("catalog { actions () }")
        .expect("empty managed config should parse")
}

fn escape_sql(input: &str) -> String {
    input.replace('\'', "''")
}

fn serialize_json<T>(value: &T) -> String
where
    T: Serialize,
{
    serde_json::to_string(value).expect("row payload should serialize")
}

#[cfg(test)]
mod tests {
    use super::{
        collect_changes, managed_store_sql, plan_entity_changes, select_current_sql,
        select_history_sql, select_max_row_version_sql, ApplyCommitRow, InviteRow,
        ManagedApplyFailure, ManagedOwnershipRow, TenantRow,
    };
    use conclave_managed_config::ManagedConfig;
    use serde_json::Value;
    use std::collections::{BTreeMap, BTreeSet};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    // r[verify config.managed.store.typed-entity-tables]
    // r[verify config.managed.store.apply-provenance]
    // r[verify config.managed.store.runtime-provenance]
    // r[verify config.managed.store.sql-lower-snake-case]
    #[test]
    fn generates_store_sql_with_typed_tables_and_views() {
        let sql = managed_store_sql();

        assert!(sql.contains("CREATE TABLE apply_commit"));
        assert!(sql.contains("CREATE TABLE managed_apply"));
        assert!(sql.contains("CREATE TABLE tenant"));
        assert!(sql.contains("CREATE TABLE subject"));
        assert!(sql.contains("CREATE TABLE membership"));
        assert!(sql.contains("CREATE TABLE assumption_grant"));
        assert!(sql.contains("CREATE TABLE action"));
        assert!(sql.contains("CREATE TABLE template"));
        assert!(sql.contains("CREATE TABLE role"));
        assert!(sql.contains("CREATE TABLE managed_ownership"));
        assert!(sql.contains("CREATE TABLE invite"));
        assert!(sql.contains("CREATE TABLE subject_credential"));
        assert!(sql.contains("CREATE TABLE session_state"));
        assert!(sql.contains("CREATE MATERIALIZED VIEW versioned_tenant"));
        assert!(sql.contains("CREATE MATERIALIZED VIEW current_tenant"));
        assert!(sql.contains("CREATE MATERIALIZED VIEW current_managed_ownership"));
        assert!(sql.contains("CREATE MATERIALIZED VIEW versioned_invite"));
        assert!(sql.contains("CREATE MATERIALIZED VIEW current_session"));
        assert!(!sql.contains("MANAGED_EVENT"));
        assert!(!sql.contains("CURRENT_MANAGED_EVENT"));
    }

    // r[verify config.managed.store.current-state-views]
    #[test]
    fn builds_current_and_history_queries_for_typed_views() {
        assert_eq!(
            select_current_sql("current_tenant"),
            "SELECT * FROM current_tenant"
        );

        let history_sql = select_history_sql(
            "versioned_membership",
            &[
                ("tenant_id", "tenant-a".to_owned()),
                ("subject_id", "subject-a".to_owned()),
            ],
        );

        assert_eq!(
            history_sql,
            "SELECT * FROM versioned_membership WHERE tenant_id = 'tenant-a' AND subject_id = 'subject-a' ORDER BY row_version"
        );
    }

    // r[verify config.managed.store.row-version-per-entity]
    #[test]
    fn scopes_row_version_queries_to_logical_entity_keys() {
        let membership_sql = select_max_row_version_sql(
            "membership",
            &[
                ("tenant_id", "tenant-a".to_owned()),
                ("subject_id", "subject-a".to_owned()),
            ],
        );
        let action_sql =
            select_max_row_version_sql("action", &[("action_name", "tenant:user:read".to_owned())]);

        assert_eq!(
            membership_sql,
            "SELECT CAST(COALESCE(MAX(row_version), 0) AS BIGINT) AS count FROM membership WHERE tenant_id = 'tenant-a' AND subject_id = 'subject-a'"
        );
        assert_eq!(
            action_sql,
            "SELECT CAST(COALESCE(MAX(row_version), 0) AS BIGINT) AS count FROM action WHERE action_name = 'tenant:user:read'"
        );
    }

    #[test]
    fn diffs_managed_resources_into_typed_changes() {
        let current = ManagedConfig::load_from_str(
            r#"
catalog { actions ({name "tenant:user:read"}) }
tenants ({id "tenant-a"})
"#,
        )
        .expect("current should parse");
        let desired = ManagedConfig::load_from_str(
            r#"
catalog { actions ({name "tenant:user:read"} {name "tenant:user:write"}) }
tenants ({id "tenant-b"})
"#,
        )
        .expect("desired should parse");

        let tenant_changes =
            collect_changes(&current.tenants, &desired.tenants, |entry| entry.id.clone());
        let action_changes = collect_changes(
            &current.catalog.actions,
            &desired.catalog.actions,
            |entry| entry.name.clone(),
        );

        assert!(tenant_changes
            .iter()
            .any(|change| change.value.id == "tenant-a" && change.deleted));
        assert!(tenant_changes
            .iter()
            .any(|change| change.value.id == "tenant-b" && !change.deleted));
        assert!(action_changes
            .iter()
            .any(|change| change.value.name == "tenant:user:write" && !change.deleted));
    }

    #[test]
    fn ownership_aware_plan_only_deletes_owned_entities() {
        let current = vec![
            conclave_managed_config::TenantConfig {
                id: "tenant-owned".to_owned(),
                display_name: None,
                parent: None,
                state: "active".to_owned(),
            },
            conclave_managed_config::TenantConfig {
                id: "tenant-unowned".to_owned(),
                display_name: None,
                parent: None,
                state: "active".to_owned(),
            },
        ];
        let ownership = BTreeMap::from([(
            ("tenant".to_owned(), "tenant-owned".to_owned()),
            ManagedOwnershipRow {
                entity_kind: "tenant".to_owned(),
                entity_key: "tenant-owned".to_owned(),
                desired_fingerprint: "fp-1".to_owned(),
                apply_id: "apply-1".to_owned(),
                row_version: 1,
                valid_from: 1,
                deleted: false,
            },
        )]);

        let plan = plan_entity_changes("tenant", &current, &[], &ownership, |entry| {
            entry.id.clone()
        });

        assert!(plan
            .reported_changes
            .iter()
            .any(|change| change == "delete tenant tenant-owned"));
        assert!(!plan
            .reported_changes
            .iter()
            .any(|change| change.contains("tenant-unowned")));
    }

    #[test]
    fn deserializes_uppercase_query_rows_for_typed_schema() {
        let tenant: TenantRow = serde_json::from_str(
            r#"{
                "TENANT_ID":"tenant-a",
                "DISPLAY_NAME":"Tenant A",
                "PARENT_TENANT_ID":"root",
                "STATE":"active",
                "APPLY_ID":"apply-1",
                "ROW_VERSION":1,
                "VALID_FROM":1,
                "DELETED":false
            }"#,
        )
        .expect("tenant row should deserialize");
        let invite: InviteRow = serde_json::from_str(
            r#"{
                "INVITE_ID":"invite-1",
                "SUBJECT_ID":"subject-1",
                "REDEEM_CODE_HASH":"hash",
                "CREATED_AT":1,
                "EXPIRES_AT":2,
                "REDEEMED_AT":null,
                "CHANGE_ID":"change-1",
                "ROW_VERSION":1,
                "VALID_FROM":1,
                "DELETED":false
            }"#,
        )
        .expect("invite row should deserialize");
        let commit: ApplyCommitRow =
            serde_json::from_str(r#"{"APPLY_ID":"apply-1","COMMITTED_AT":1,"COMMITTED":true}"#)
                .expect("commit row should deserialize");

        assert_eq!(tenant.tenant_id, "tenant-a");
        assert_eq!(invite.invite_id, "invite-1");
        assert!(commit.committed);
    }

    // r[verify config.managed.apply-operation]
    // r[verify config.managed.plan-before-apply]
    // r[verify config.managed.idempotent-apply]
    // r[verify config.managed.three-way-diff]
    // r[verify config.managed.ownership]
    // r[verify config.managed.store.managed-apply-state]
    // r[verify config.managed.store.managed-ownership-state]
    // r[verify config.managed.store.entity-fingerprint]
    #[actix_web::test]
    async fn persists_managed_apply_and_ownership_state_across_reapply() {
        use actix_web::{get, patch, post, web, App, HttpRequest, HttpResponse, Responder};
        use std::time::Duration;

        #[derive(Default)]
        struct FakeStore {
            pipeline: Option<crate::feldera::PipelineRecord>,
            committed_tables: BTreeMap<String, Vec<Value>>,
            staged_tables: BTreeMap<String, Vec<Value>>,
            checkpoint_tables: BTreeMap<String, Vec<Value>>,
            next_transaction_id: u64,
            checkpoint_sequence_number: u64,
            last_successful_checkpoint: u64,
            transaction_status: &'static str,
            fail_commit: bool,
        }

        fn decode_sql(request: &HttpRequest) -> String {
            request
                .query_string()
                .split('&')
                .find_map(|entry| entry.strip_prefix("sql="))
                .unwrap_or_default()
                .replace('+', " ")
                .replace("%20", " ")
                .replace("%28", "(")
                .replace("%29", ")")
                .replace("%2A", "*")
        }

        fn table_key_columns(name: &str) -> &'static [&'static str] {
            match name {
                "tenant" | "versioned_tenant" | "current_tenant" => &["tenant_id"],
                "subject" | "versioned_subject" | "current_subject" => &["subject_id"],
                "membership" | "versioned_membership" | "current_membership" => {
                    &["tenant_id", "subject_id"]
                }
                "assumption_grant" | "versioned_assumption_grant" | "current_assumption_grant" => {
                    &["subject_id", "source_tenant_id", "target_tenant_id"]
                }
                "action" | "versioned_action" | "current_action" => &["action_name"],
                "template" | "versioned_template" | "current_template" => {
                    &["tenant_id", "template_key"]
                }
                "role" | "versioned_role" | "current_role" => &["tenant_id", "role_key"],
                "managed_ownership"
                | "versioned_managed_ownership"
                | "current_managed_ownership" => &["entity_kind", "entity_key"],
                "invite" | "versioned_invite" | "current_invite" => &["invite_id"],
                "subject_credential"
                | "versioned_subject_credential"
                | "current_subject_credential" => &["subject_id"],
                "session_state" => &["session_id"],
                "session" | "versioned_session" | "current_session" => &["session_id"],
                _ => &[],
            }
        }

        fn backing_table_name(name: &str) -> &str {
            match name {
                "session" | "versioned_session" | "current_session" => "session_state",
                _ => name,
            }
        }

        fn table_name_from_sql(sql: &str) -> Option<&str> {
            sql.split("FROM ")
                .nth(1)
                .and_then(|part| part.split_whitespace().next())
        }

        fn sql_filters(sql: &str) -> Vec<(String, String)> {
            let Some(where_clause) = sql.split(" WHERE ").nth(1) else {
                return Vec::new();
            };
            let predicate_segment = where_clause
                .split(" ORDER BY ")
                .next()
                .unwrap_or(where_clause);

            predicate_segment
                .split(" AND ")
                .filter_map(|predicate| {
                    let (column, rest) = predicate.split_once(" = '")?;
                    let value = rest.strip_suffix('\'')?.replace("''", "'");
                    Some((column.to_owned(), value))
                })
                .collect()
        }

        fn latest_rows(rows: &[Value], key_columns: &[&str]) -> Vec<Value> {
            let mut latest = BTreeMap::<Vec<String>, Value>::new();

            for row in rows {
                let key = key_columns
                    .iter()
                    .map(|column| {
                        row.get(*column)
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned()
                    })
                    .collect::<Vec<_>>();
                let row_version = row.get("row_version").and_then(Value::as_u64).unwrap_or(0);
                let replace = latest
                    .get(&key)
                    .and_then(|current| current.get("row_version").and_then(Value::as_u64))
                    .map(|current| row_version >= current)
                    .unwrap_or(true);
                if replace {
                    latest.insert(key, row.clone());
                }
            }

            latest
                .into_values()
                .filter(|row| !row.get("deleted").and_then(Value::as_bool).unwrap_or(false))
                .collect()
        }

        fn visible_tables(store: &FakeStore) -> &BTreeMap<String, Vec<Value>> {
            &store.committed_tables
        }

        #[get("/v0/pipelines/{name}")]
        async fn get_pipeline(store: web::Data<Arc<Mutex<FakeStore>>>) -> impl Responder {
            let pipeline = store.lock().expect("store lock").pipeline.clone();
            if let Some(pipeline) = pipeline {
                HttpResponse::Ok().json(pipeline)
            } else {
                HttpResponse::NotFound().finish()
            }
        }

        #[post("/v0/pipelines")]
        async fn create_pipeline(
            store: web::Data<Arc<Mutex<FakeStore>>>,
            body: web::Json<crate::feldera::DesiredPipeline>,
        ) -> impl Responder {
            let record = crate::feldera::PipelineRecord {
                name: body.name.clone(),
                description: Some(body.description.clone()),
                program_code: Some(body.program_code.clone()),
                program_status: Some("SqlCompiled".to_owned()),
                deployment_status: Some("Stopped".to_owned()),
                deployment_resources_status: Some("Stopped".to_owned()),
                deployment_runtime_status: None,
                program_config: body.program_config.clone(),
            };
            store.lock().expect("store lock").pipeline = Some(record.clone());
            HttpResponse::Ok().json(record)
        }

        #[post("/v0/pipelines/{name}/start")]
        async fn start_pipeline() -> impl Responder {
            HttpResponse::Ok().finish()
        }

        #[post("/v0/pipelines/{name}/stop")]
        async fn stop_pipeline(
            request: HttpRequest,
            store: web::Data<Arc<Mutex<FakeStore>>>,
        ) -> impl Responder {
            let force = request.query_string().contains("force=true");
            let mut store = store.lock().expect("store lock");
            if force {
                store.committed_tables = store.checkpoint_tables.clone();
                store.staged_tables.clear();
                store.transaction_status = "NoTransaction";
            }
            HttpResponse::Ok().finish()
        }

        #[post("/v0/pipelines/{name}/checkpoint")]
        async fn checkpoint(store: web::Data<Arc<Mutex<FakeStore>>>) -> impl Responder {
            let mut store = store.lock().expect("store lock");
            store.checkpoint_sequence_number += 1;
            store.last_successful_checkpoint = store.checkpoint_sequence_number;
            store.checkpoint_tables = store.committed_tables.clone();
            HttpResponse::Ok().json(serde_json::json!({
                "checkpoint_sequence_number": store.checkpoint_sequence_number
            }))
        }

        #[get("/v0/pipelines/{name}/checkpoint_status")]
        async fn checkpoint_status(store: web::Data<Arc<Mutex<FakeStore>>>) -> impl Responder {
            let store = store.lock().expect("store lock");
            HttpResponse::Ok().json(serde_json::json!({
                "success": store.last_successful_checkpoint
            }))
        }

        #[post("/v0/pipelines/{name}/start_transaction")]
        async fn start_transaction(store: web::Data<Arc<Mutex<FakeStore>>>) -> impl Responder {
            let mut store = store.lock().expect("store lock");
            store.next_transaction_id += 1;
            store.staged_tables.clear();
            store.transaction_status = "InProgress";
            HttpResponse::Ok().json(serde_json::json!({
                "transaction_id": store.next_transaction_id
            }))
        }

        #[post("/v0/pipelines/{name}/commit_transaction")]
        async fn commit_transaction(store: web::Data<Arc<Mutex<FakeStore>>>) -> impl Responder {
            let mut store = store.lock().expect("store lock");
            if store.fail_commit {
                store.transaction_status = "CommitFailed";
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "message": "commit failed"
                }));
            }

            for (table, rows) in std::mem::take(&mut store.staged_tables) {
                store
                    .committed_tables
                    .entry(table)
                    .or_default()
                    .extend(rows);
            }
            store.transaction_status = "NoTransaction";
            HttpResponse::Ok().finish()
        }

        #[get("/v0/pipelines/{name}/stats")]
        async fn get_stats(store: web::Data<Arc<Mutex<FakeStore>>>) -> impl Responder {
            let store = store.lock().expect("store lock");
            HttpResponse::Ok().json(serde_json::json!({
                "global_metrics": {
                    "transaction_status": store.transaction_status,
                    "transaction_id": store.next_transaction_id,
                }
            }))
        }

        #[patch("/v0/pipelines/{name}")]
        async fn patch_pipeline(
            body: web::Json<serde_json::Value>,
            path: web::Path<String>,
            store: web::Data<Arc<Mutex<FakeStore>>>,
        ) -> impl Responder {
            let record = crate::feldera::PipelineRecord {
                name: path.into_inner(),
                description: body
                    .get("description")
                    .and_then(serde_json::Value::as_str)
                    .map(ToOwned::to_owned),
                program_code: body
                    .get("program_code")
                    .and_then(serde_json::Value::as_str)
                    .map(ToOwned::to_owned),
                program_status: Some("SqlCompiled".to_owned()),
                deployment_status: Some("Stopped".to_owned()),
                deployment_resources_status: Some("Stopped".to_owned()),
                deployment_runtime_status: None,
                program_config: serde_json::from_value(
                    body.get("program_config")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null),
                )
                .ok(),
            };
            store.lock().expect("store lock").pipeline = Some(record.clone());
            HttpResponse::Ok().json(record)
        }

        #[post("/v0/pipelines/{name}/ingress/{table}")]
        async fn ingress_rows(
            path: web::Path<(String, String)>,
            store: web::Data<Arc<Mutex<FakeStore>>>,
            body: web::Json<Vec<Value>>,
        ) -> impl Responder {
            let table = &path.1;
            let mut store = store.lock().expect("store lock");
            let target = if store.transaction_status == "NoTransaction" {
                &mut store.committed_tables
            } else {
                &mut store.staged_tables
            };
            target
                .entry(table.to_owned())
                .or_default()
                .extend(body.into_inner());

            HttpResponse::Ok().json(serde_json::json!({ "completion_token": "done-1" }))
        }

        #[get("/v0/pipelines/{name}/completion_status")]
        async fn completion_status() -> impl Responder {
            HttpResponse::Ok().json(serde_json::json!({ "completed": true }))
        }

        #[get("/v0/pipelines/{name}/query")]
        async fn query_pipeline(
            request: HttpRequest,
            store: web::Data<Arc<Mutex<FakeStore>>>,
        ) -> impl Responder {
            let sql = decode_sql(&request);
            let store = store.lock().expect("store lock");
            let tables = visible_tables(&store);

            if sql.contains("FROM apply_commit") && sql.contains("COUNT(*)") {
                let count = tables
                    .get("apply_commit")
                    .map(Vec::as_slice)
                    .unwrap_or(&[])
                    .iter()
                    .filter(|row| row.get("committed").and_then(Value::as_bool) == Some(true))
                    .count();
                HttpResponse::Ok().json(vec![serde_json::json!({ "count": count })])
            } else if sql.contains("FROM managed_apply")
                && sql.contains("ORDER BY ma.applied_at DESC")
            {
                let committed = tables
                    .get("apply_commit")
                    .map(Vec::as_slice)
                    .unwrap_or(&[])
                    .iter()
                    .filter(|row| row.get("committed").and_then(Value::as_bool) == Some(true))
                    .filter_map(|row| row.get("apply_id").and_then(Value::as_str))
                    .collect::<BTreeSet<_>>();
                let row = tables
                    .get("managed_apply")
                    .map(Vec::as_slice)
                    .unwrap_or(&[])
                    .iter()
                    .filter(|row| {
                        row.get("apply_id")
                            .and_then(Value::as_str)
                            .map(|apply_id| committed.contains(apply_id))
                            .unwrap_or(false)
                    })
                    .max_by_key(|row| row.get("applied_at").and_then(Value::as_u64).unwrap_or(0))
                    .cloned();
                HttpResponse::Ok().json(row.into_iter().collect::<Vec<_>>())
            } else if sql.contains("ORDER BY committed_at DESC") {
                let apply_id = tables
                    .get("apply_commit")
                    .map(Vec::as_slice)
                    .unwrap_or(&[])
                    .iter()
                    .filter(|row| row.get("committed").and_then(Value::as_bool) == Some(true))
                    .max_by_key(|row| row.get("committed_at").and_then(Value::as_u64).unwrap_or(0))
                    .and_then(|row| row.get("apply_id").and_then(Value::as_str))
                    .unwrap_or("apply-bootstrap");
                HttpResponse::Ok().json(vec![serde_json::json!({ "apply_id": apply_id })])
            } else if sql.contains("MAX(row_version)") {
                let table_name = table_name_from_sql(&sql).unwrap_or_default();
                let filters = sql_filters(&sql);
                let max = tables
                    .get(table_name)
                    .map(Vec::as_slice)
                    .unwrap_or(&[])
                    .iter()
                    .filter(|row| {
                        filters.iter().all(|(column, expected)| {
                            row.get(column)
                                .and_then(Value::as_str)
                                .map(|value| value == expected)
                                .unwrap_or(false)
                        })
                    })
                    .filter_map(|row| row.get("row_version").and_then(Value::as_u64))
                    .max()
                    .unwrap_or(0);
                HttpResponse::Ok().json(vec![serde_json::json!({ "count": max })])
            } else if let Some(view_name) = table_name_from_sql(&sql) {
                let table_name =
                    backing_table_name(view_name.strip_prefix("current_").unwrap_or(view_name));
                let key_columns = table_key_columns(view_name);
                let rows = tables.get(table_name).map(Vec::as_slice).unwrap_or(&[]);
                HttpResponse::Ok().json(latest_rows(rows, key_columns))
            } else {
                HttpResponse::Ok().json(Vec::<Value>::new())
            }
        }

        let store = Arc::new(Mutex::new(FakeStore::default()));
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let addr = listener
            .local_addr()
            .expect("listener should have local addr");
        let server_store = store.clone();
        let server = actix_web::HttpServer::new(move || {
            App::new()
                .app_data(web::Data::new(server_store.clone()))
                .service(get_pipeline)
                .service(create_pipeline)
                .service(start_pipeline)
                .service(stop_pipeline)
                .service(patch_pipeline)
                .service(checkpoint)
                .service(checkpoint_status)
                .service(start_transaction)
                .service(commit_transaction)
                .service(get_stats)
                .service(ingress_rows)
                .service(completion_status)
                .service(query_pipeline)
        })
        .listen(listener)
        .expect("server should listen")
        .run();
        let handle = server.handle();
        actix_web::rt::spawn(server);
        actix_web::rt::time::sleep(Duration::from_millis(25)).await;

        let client = crate::feldera::FelderaClient::new(format!("http://{}", addr), None);
        let store_client = super::FelderaManagedStore::new(
            client,
            crate::config::FelderaConfig {
                enabled: true,
                base_url: format!("http://{}", addr),
                pipeline_prefix: "task2-store".to_owned(),
                readiness_probe: false,
                api_key: None,
                compile_profile: "dev".to_owned(),
                auto_start: false,
                start_initial: "paused".to_owned(),
            },
        );

        let initial = ManagedConfig::load_from_str(
            r#"
catalog { actions ({name "tenant:user:read"}) }
tenants ({id "tenant-a"})
subjects ({id "subject-a", display_name "Subject A"})
"#,
        )
        .expect("initial config should parse");
        let updated = ManagedConfig::load_from_str(
            r#"
catalog { actions ({name "tenant:user:write"}) }
tenants ({id "tenant-a", display_name "Tenant A"})
subjects ({id "subject-a", display_name "Subject A+"})
"#,
        )
        .expect("updated config should parse");

        let first_plan = store_client
            .plan(&initial)
            .await
            .expect("plan should succeed");
        let first_apply = store_client
            .apply(&initial)
            .await
            .expect("first apply should succeed");
        let second_plan = store_client
            .plan(&updated)
            .await
            .expect("plan should succeed");
        let second_apply = store_client
            .apply(&updated)
            .await
            .expect("second apply should succeed");
        let third_plan = store_client
            .plan(&updated)
            .await
            .expect("plan should succeed");
        let third_apply = store_client
            .apply(&updated)
            .await
            .expect("noop apply should succeed");
        let latest_apply = store_client
            .load_latest_managed_apply()
            .await
            .expect("latest apply should load")
            .expect("latest apply should exist");
        let loaded = store_client
            .load_managed()
            .await
            .expect("managed state should load");

        handle.stop(true).await;

        assert!(!first_plan.noop);
        assert_eq!(first_apply.summary.created, 3);
        assert!(second_plan
            .changes
            .iter()
            .any(|change| change.starts_with("update tenant")));
        assert!(second_plan
            .changes
            .iter()
            .any(|change| change.starts_with("update subject")));
        assert!(second_plan
            .changes
            .iter()
            .any(|change| change.starts_with("delete action")));
        assert!(second_plan
            .changes
            .iter()
            .any(|change| change.starts_with("create action")));
        assert_eq!(second_apply.summary.created, 1);
        assert_eq!(second_apply.summary.updated, 2);
        assert_eq!(second_apply.summary.deleted, 1);
        assert!(third_plan.noop);
        assert!(third_apply.noop);
        assert_eq!(third_apply.summary.created, 0);
        assert_eq!(latest_apply.managed, updated);
        assert!(loaded
            .catalog
            .actions
            .iter()
            .any(|action| action.name == "tenant:user:write"));
        assert_eq!(
            store
                .lock()
                .expect("store lock")
                .committed_tables
                .get("managed_ownership")
                .map(Vec::len)
                .unwrap_or(0),
            7
        );
    }

    // r[verify config.managed.store.transactional-apply]
    // r[verify config.managed.store.transactional-recovery]
    // r[verify config.managed.partial-failure]
    #[actix_web::test]
    async fn recovers_failed_transactional_apply_to_last_checkpoint() {
        use actix_web::{get, patch, post, web, App, HttpRequest, HttpResponse, Responder};
        use std::time::Duration;

        #[derive(Default)]
        struct FakeStore {
            pipeline: Option<crate::feldera::PipelineRecord>,
            committed_tables: BTreeMap<String, Vec<Value>>,
            staged_tables: BTreeMap<String, Vec<Value>>,
            checkpoint_tables: BTreeMap<String, Vec<Value>>,
            next_transaction_id: u64,
            checkpoint_sequence_number: u64,
            last_successful_checkpoint: u64,
            transaction_status: &'static str,
            fail_commit: bool,
        }

        fn decode_sql(request: &HttpRequest) -> String {
            request
                .query_string()
                .split('&')
                .find_map(|entry| entry.strip_prefix("sql="))
                .unwrap_or_default()
                .replace('+', " ")
                .replace("%20", " ")
                .replace("%28", "(")
                .replace("%29", ")")
                .replace("%2A", "*")
        }

        fn table_key_columns(name: &str) -> &'static [&'static str] {
            match name {
                "tenant" | "versioned_tenant" | "current_tenant" => &["tenant_id"],
                "subject" | "versioned_subject" | "current_subject" => &["subject_id"],
                "membership" | "versioned_membership" | "current_membership" => {
                    &["tenant_id", "subject_id"]
                }
                "assumption_grant" | "versioned_assumption_grant" | "current_assumption_grant" => {
                    &["subject_id", "source_tenant_id", "target_tenant_id"]
                }
                "action" | "versioned_action" | "current_action" => &["action_name"],
                "template" | "versioned_template" | "current_template" => {
                    &["tenant_id", "template_key"]
                }
                "role" | "versioned_role" | "current_role" => &["tenant_id", "role_key"],
                "managed_ownership"
                | "versioned_managed_ownership"
                | "current_managed_ownership" => &["entity_kind", "entity_key"],
                _ => &[],
            }
        }

        fn table_name_from_sql(sql: &str) -> Option<&str> {
            sql.split("FROM ")
                .nth(1)
                .and_then(|part| part.split_whitespace().next())
        }

        fn sql_filters(sql: &str) -> Vec<(String, String)> {
            let Some(where_clause) = sql.split(" WHERE ").nth(1) else {
                return Vec::new();
            };
            where_clause
                .split(" ORDER BY ")
                .next()
                .unwrap_or(where_clause)
                .split(" AND ")
                .filter_map(|predicate| {
                    let (column, rest) = predicate.split_once(" = '")?;
                    let value = rest.strip_suffix('\'')?.replace("''", "'");
                    Some((column.to_owned(), value))
                })
                .collect()
        }

        fn latest_rows(rows: &[Value], key_columns: &[&str]) -> Vec<Value> {
            let mut latest = BTreeMap::<Vec<String>, Value>::new();
            for row in rows {
                let key = key_columns
                    .iter()
                    .map(|column| {
                        row.get(*column)
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned()
                    })
                    .collect::<Vec<_>>();
                let row_version = row.get("row_version").and_then(Value::as_u64).unwrap_or(0);
                let replace = latest
                    .get(&key)
                    .and_then(|current| current.get("row_version").and_then(Value::as_u64))
                    .map(|current| row_version >= current)
                    .unwrap_or(true);
                if replace {
                    latest.insert(key, row.clone());
                }
            }

            latest
                .into_values()
                .filter(|row| !row.get("deleted").and_then(Value::as_bool).unwrap_or(false))
                .collect()
        }

        #[get("/v0/pipelines/{name}")]
        async fn get_pipeline(store: web::Data<Arc<Mutex<FakeStore>>>) -> impl Responder {
            let pipeline = store.lock().expect("store lock").pipeline.clone();
            if let Some(pipeline) = pipeline {
                HttpResponse::Ok().json(pipeline)
            } else {
                HttpResponse::NotFound().finish()
            }
        }

        #[post("/v0/pipelines")]
        async fn create_pipeline(
            store: web::Data<Arc<Mutex<FakeStore>>>,
            body: web::Json<crate::feldera::DesiredPipeline>,
        ) -> impl Responder {
            let record = crate::feldera::PipelineRecord {
                name: body.name.clone(),
                description: Some(body.description.clone()),
                program_code: Some(body.program_code.clone()),
                program_status: Some("SqlCompiled".to_owned()),
                deployment_status: Some("Stopped".to_owned()),
                deployment_resources_status: Some("Stopped".to_owned()),
                deployment_runtime_status: None,
                program_config: body.program_config.clone(),
            };
            store.lock().expect("store lock").pipeline = Some(record.clone());
            HttpResponse::Ok().json(record)
        }

        #[post("/v0/pipelines/{name}/start")]
        async fn start_pipeline() -> impl Responder {
            HttpResponse::Ok().finish()
        }

        #[post("/v0/pipelines/{name}/stop")]
        async fn stop_pipeline(
            request: HttpRequest,
            store: web::Data<Arc<Mutex<FakeStore>>>,
        ) -> impl Responder {
            let force = request.query_string().contains("force=true");
            let mut store = store.lock().expect("store lock");
            if force {
                store.committed_tables = store.checkpoint_tables.clone();
                store.staged_tables.clear();
                store.transaction_status = "NoTransaction";
                store.fail_commit = false;
            }
            HttpResponse::Ok().finish()
        }

        #[patch("/v0/pipelines/{name}")]
        async fn patch_pipeline(
            body: web::Json<serde_json::Value>,
            path: web::Path<String>,
            store: web::Data<Arc<Mutex<FakeStore>>>,
        ) -> impl Responder {
            let record = crate::feldera::PipelineRecord {
                name: path.into_inner(),
                description: body
                    .get("description")
                    .and_then(serde_json::Value::as_str)
                    .map(ToOwned::to_owned),
                program_code: body
                    .get("program_code")
                    .and_then(serde_json::Value::as_str)
                    .map(ToOwned::to_owned),
                program_status: Some("SqlCompiled".to_owned()),
                deployment_status: Some("Stopped".to_owned()),
                deployment_resources_status: Some("Stopped".to_owned()),
                deployment_runtime_status: None,
                program_config: serde_json::from_value(
                    body.get("program_config")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null),
                )
                .ok(),
            };
            store.lock().expect("store lock").pipeline = Some(record.clone());
            HttpResponse::Ok().json(record)
        }

        #[post("/v0/pipelines/{name}/checkpoint")]
        async fn checkpoint(store: web::Data<Arc<Mutex<FakeStore>>>) -> impl Responder {
            let mut store = store.lock().expect("store lock");
            store.checkpoint_sequence_number += 1;
            store.last_successful_checkpoint = store.checkpoint_sequence_number;
            store.checkpoint_tables = store.committed_tables.clone();
            HttpResponse::Ok().json(serde_json::json!({
                "checkpoint_sequence_number": store.checkpoint_sequence_number
            }))
        }

        #[get("/v0/pipelines/{name}/checkpoint_status")]
        async fn checkpoint_status(store: web::Data<Arc<Mutex<FakeStore>>>) -> impl Responder {
            let store = store.lock().expect("store lock");
            HttpResponse::Ok().json(serde_json::json!({
                "success": store.last_successful_checkpoint
            }))
        }

        #[post("/v0/pipelines/{name}/start_transaction")]
        async fn start_transaction(store: web::Data<Arc<Mutex<FakeStore>>>) -> impl Responder {
            let mut store = store.lock().expect("store lock");
            store.next_transaction_id += 1;
            store.staged_tables.clear();
            store.transaction_status = "InProgress";
            HttpResponse::Ok().json(serde_json::json!({
                "transaction_id": store.next_transaction_id
            }))
        }

        #[post("/v0/pipelines/{name}/commit_transaction")]
        async fn commit_transaction(store: web::Data<Arc<Mutex<FakeStore>>>) -> impl Responder {
            let mut store = store.lock().expect("store lock");
            if store.fail_commit {
                store.transaction_status = "CommitFailed";
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "message": "commit failed"
                }));
            }

            for (table, rows) in std::mem::take(&mut store.staged_tables) {
                store
                    .committed_tables
                    .entry(table)
                    .or_default()
                    .extend(rows);
            }
            store.transaction_status = "NoTransaction";
            HttpResponse::Ok().finish()
        }

        #[get("/v0/pipelines/{name}/stats")]
        async fn get_stats(store: web::Data<Arc<Mutex<FakeStore>>>) -> impl Responder {
            let store = store.lock().expect("store lock");
            HttpResponse::Ok().json(serde_json::json!({
                "global_metrics": {
                    "transaction_status": store.transaction_status,
                    "transaction_id": store.next_transaction_id,
                }
            }))
        }

        #[post("/v0/pipelines/{name}/ingress/{table}")]
        async fn ingress_rows(
            path: web::Path<(String, String)>,
            store: web::Data<Arc<Mutex<FakeStore>>>,
            body: web::Json<Vec<Value>>,
        ) -> impl Responder {
            let table = &path.1;
            let mut store = store.lock().expect("store lock");
            let target = if store.transaction_status == "NoTransaction" {
                &mut store.committed_tables
            } else {
                &mut store.staged_tables
            };
            target
                .entry(table.to_owned())
                .or_default()
                .extend(body.into_inner());

            HttpResponse::Ok().json(serde_json::json!({ "completion_token": "done-1" }))
        }

        #[get("/v0/pipelines/{name}/completion_status")]
        async fn completion_status() -> impl Responder {
            HttpResponse::Ok().json(serde_json::json!({ "completed": true }))
        }

        #[get("/v0/pipelines/{name}/query")]
        async fn query_pipeline(
            request: HttpRequest,
            store: web::Data<Arc<Mutex<FakeStore>>>,
        ) -> impl Responder {
            let sql = decode_sql(&request);
            let store = store.lock().expect("store lock");
            let tables = &store.committed_tables;

            if sql.contains("FROM apply_commit") && sql.contains("COUNT(*)") {
                let count = tables
                    .get("apply_commit")
                    .map(Vec::as_slice)
                    .unwrap_or(&[])
                    .iter()
                    .filter(|row| row.get("committed").and_then(Value::as_bool) == Some(true))
                    .count();
                HttpResponse::Ok().json(vec![serde_json::json!({ "count": count })])
            } else if sql.contains("ORDER BY committed_at DESC") {
                let apply_id = tables
                    .get("apply_commit")
                    .map(Vec::as_slice)
                    .unwrap_or(&[])
                    .iter()
                    .filter(|row| row.get("committed").and_then(Value::as_bool) == Some(true))
                    .max_by_key(|row| row.get("committed_at").and_then(Value::as_u64).unwrap_or(0))
                    .and_then(|row| row.get("apply_id").and_then(Value::as_str))
                    .unwrap_or("apply-bootstrap");
                HttpResponse::Ok().json(vec![serde_json::json!({ "apply_id": apply_id })])
            } else if sql.contains("MAX(row_version)") {
                let table_name = table_name_from_sql(&sql).unwrap_or_default();
                let filters = sql_filters(&sql);
                let max = tables
                    .get(table_name)
                    .map(Vec::as_slice)
                    .unwrap_or(&[])
                    .iter()
                    .filter(|row| {
                        filters.iter().all(|(column, expected)| {
                            row.get(column)
                                .and_then(Value::as_str)
                                .map(|value| value == expected)
                                .unwrap_or(false)
                        })
                    })
                    .filter_map(|row| row.get("row_version").and_then(Value::as_u64))
                    .max()
                    .unwrap_or(0);
                HttpResponse::Ok().json(vec![serde_json::json!({ "count": max })])
            } else if let Some(view_name) = table_name_from_sql(&sql) {
                let rows = tables
                    .get(view_name.strip_prefix("current_").unwrap_or(view_name))
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);
                HttpResponse::Ok().json(latest_rows(rows, table_key_columns(view_name)))
            } else {
                HttpResponse::Ok().json(Vec::<Value>::new())
            }
        }

        let store = Arc::new(Mutex::new(FakeStore::default()));
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let addr = listener
            .local_addr()
            .expect("listener should have local addr");
        let server_store = store.clone();
        let server = actix_web::HttpServer::new(move || {
            App::new()
                .app_data(web::Data::new(server_store.clone()))
                .service(get_pipeline)
                .service(create_pipeline)
                .service(start_pipeline)
                .service(stop_pipeline)
                .service(patch_pipeline)
                .service(checkpoint)
                .service(checkpoint_status)
                .service(start_transaction)
                .service(commit_transaction)
                .service(get_stats)
                .service(ingress_rows)
                .service(completion_status)
                .service(query_pipeline)
        })
        .listen(listener)
        .expect("server should listen")
        .run();
        let handle = server.handle();
        actix_web::rt::spawn(server);
        actix_web::rt::time::sleep(Duration::from_millis(25)).await;

        let client = crate::feldera::FelderaClient::new(format!("http://{}", addr), None);
        let store_client = super::FelderaManagedStore::new(
            client,
            crate::config::FelderaConfig {
                enabled: true,
                base_url: format!("http://{}", addr),
                pipeline_prefix: "task2-store-recovery".to_owned(),
                readiness_probe: false,
                api_key: None,
                compile_profile: "dev".to_owned(),
                auto_start: false,
                start_initial: "paused".to_owned(),
            },
        );

        let initial = ManagedConfig::load_from_str(
            r#"
catalog { actions ({name "tenant:user:read"}) }
tenants ({id "tenant-a"})
"#,
        )
        .expect("initial config should parse");
        let updated = ManagedConfig::load_from_str(
            r#"
catalog { actions ({name "tenant:user:write"}) }
tenants ({id "tenant-a", display_name "Tenant A"}) 
"#,
        )
        .expect("updated config should parse");

        store_client
            .apply(&initial)
            .await
            .expect("initial apply should succeed");
        store.lock().expect("store lock").fail_commit = true;

        let err = store_client
            .apply(&updated)
            .await
            .expect_err("apply should fail during commit");
        let failure = err
            .downcast_ref::<ManagedApplyFailure>()
            .expect("error should expose structured failure");
        let loaded = store_client
            .load_managed()
            .await
            .expect("managed state should stay queryable");
        let latest_apply = store_client
            .load_latest_managed_apply()
            .await
            .expect("latest apply should load")
            .expect("latest apply should exist");

        handle.stop(true).await;

        assert_eq!(failure.phase, super::ManagedApplyPhase::Commit);
        assert!(failure.recovery_attempted);
        assert!(failure.recovery_succeeded);
        assert!(failure
            .affected_resources
            .iter()
            .any(|entry| entry == "update tenant tenant-a"));
        assert_eq!(failure.affected_resources, failure.rolled_back_resources);
        assert_eq!(loaded, initial);
        assert_eq!(latest_apply.managed, initial);
    }

    #[actix_web::test]
    #[ignore = "requires a running Feldera manager via CONCLAVE_COMPONENT_FELDERA_URL"]
    async fn bootstraps_typed_temporal_store_against_live_feldera_manager() {
        let base_url = std::env::var("CONCLAVE_COMPONENT_FELDERA_URL")
            .expect("set CONCLAVE_COMPONENT_FELDERA_URL to run this test");
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic enough")
            .as_nanos();
        let pipeline_prefix = format!("component-store-{nonce}");
        let client = crate::feldera::FelderaClient::new(base_url.clone(), None);
        let store = super::FelderaManagedStore::new(
            client,
            crate::config::FelderaConfig {
                enabled: true,
                base_url,
                pipeline_prefix,
                readiness_probe: false,
                api_key: None,
                compile_profile: "dev".to_owned(),
                auto_start: false,
                start_initial: "paused".to_owned(),
            },
        );
        let managed = ManagedConfig::load_from_str(
            r#"
catalog {
    actions (
        {name "tenant:user:read"}
    )
}
tenants (
    {id "root"}
    {id "tenant-a", parent "root"}
)
"#,
        )
        .expect("managed config should parse");

        let bootstrapped = store
            .bootstrap_if_empty(&managed)
            .await
            .expect("typed store bootstrap should succeed");
        let loaded = store
            .load_managed()
            .await
            .expect("typed store load should succeed");
        let latest_apply_id = store
            .load_latest_apply_id()
            .await
            .expect("typed store should expose an apply id");

        assert!(bootstrapped);
        assert!(latest_apply_id.is_some());
        assert!(loaded
            .catalog
            .actions
            .iter()
            .any(|action| action.name == "tenant:user:read"));
        assert!(loaded.tenants.iter().any(|tenant| tenant.id == "root"));
        assert!(loaded.tenants.iter().any(|tenant| tenant.id == "tenant-a"));
    }
}
