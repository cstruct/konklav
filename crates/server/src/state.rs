use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

use conclave_controlplane_api::{ManagedMutationCounts, ManagedPlanResponse};
use conclave_managed_config::{
    ActionSpec, AssumptionGrantConfig, ManagedConfig, MembershipConfig, RoleConfig, SubjectConfig,
    TemplateConfig, TenantConfig,
};

use crate::authz::{compile_managed_authz, CompiledAuthzModel};
use crate::tenants::{compile_managed_tenants, CompiledTenantModel};
use crate::types::DynError;

#[derive(Clone, Debug)]
pub struct VersionedRecord<T> {
    pub key: String,
    pub scope: String,
    pub value: T,
    pub row_version: u64,
    pub valid_from: u64,
    pub valid_to: Option<u64>,
    pub apply_id: String,
}

#[derive(Clone, Debug, Default)]
pub struct HistoryStore {
    pub tenants: Vec<VersionedRecord<TenantConfig>>,
    pub subjects: Vec<VersionedRecord<SubjectConfig>>,
    pub memberships: Vec<VersionedRecord<MembershipConfig>>,
    pub assumption_grants: Vec<VersionedRecord<AssumptionGrantConfig>>,
    pub templates: Vec<VersionedRecord<TemplateConfig>>,
    pub roles: Vec<VersionedRecord<RoleConfig>>,
    pub catalog_actions: Vec<VersionedRecord<ActionSpec>>,
}

#[derive(Clone, Debug)]
pub struct InviteRecord {
    pub invite_id: String,
    pub subject: String,
    pub redeem_code_hash: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub redeemed_at: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct CredentialRecord {
    pub subject: String,
    pub salt: String,
    pub password_hash: String,
    pub valid_from: u64,
    pub valid_to: Option<u64>,
    pub row_version: u64,
}

#[derive(Clone, Debug)]
pub struct SessionRecord {
    pub session_id: String,
    pub subject: String,
    pub tenant: String,
    pub created_at: u64,
    pub last_seen_at: u64,
}

#[derive(Clone, Debug)]
pub struct StateSnapshot {
    pub managed: ManagedConfig,
    pub authz: CompiledAuthzModel,
    pub tenants: CompiledTenantModel,
}

#[derive(Clone, Debug)]
pub struct ControlPlaneState {
    apply_seq: u64,
    apply_counter: u64,
    pub last_apply_id: String,
    managed: ManagedConfig,
    history: HistoryStore,
    invites: Vec<InviteRecord>,
    credentials: Vec<CredentialRecord>,
    sessions: Vec<SessionRecord>,
    scoped_versions: BTreeMap<(String, String), u64>,
}

impl ControlPlaneState {
    pub fn new(managed: ManagedConfig) -> Result<Self, DynError> {
        let mut state = Self::empty();
        state.bootstrap_from_managed_if_empty(managed)?;
        Ok(state)
    }

    pub fn empty() -> Self {
        Self {
            apply_seq: 0,
            apply_counter: 0,
            last_apply_id: "apply-000000".to_owned(),
            managed: empty_managed_config(),
            history: HistoryStore::default(),
            invites: Vec::new(),
            credentials: Vec::new(),
            sessions: Vec::new(),
            scoped_versions: BTreeMap::new(),
        }
    }

    // r[impl config.managed.bootstrap-seed]
    pub fn bootstrap_from_managed_if_empty(
        &mut self,
        managed: ManagedConfig,
    ) -> Result<bool, DynError> {
        if self.is_empty() {
            self.apply(managed)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn managed(&self) -> &ManagedConfig {
        &self.managed
    }

    pub fn invites(&self) -> &[InviteRecord] {
        &self.invites
    }

    pub fn credentials(&self) -> &[CredentialRecord] {
        &self.credentials
    }

    pub fn sessions(&self) -> &[SessionRecord] {
        &self.sessions
    }

    pub fn is_empty(&self) -> bool {
        self.history.tenants.is_empty()
            && self.history.subjects.is_empty()
            && self.history.memberships.is_empty()
            && self.history.assumption_grants.is_empty()
            && self.history.templates.is_empty()
            && self.history.roles.is_empty()
            && self.history.catalog_actions.is_empty()
            && self.invites.is_empty()
            && self.credentials.is_empty()
            && self.sessions.is_empty()
    }

    pub fn snapshot(&self) -> Result<StateSnapshot, DynError> {
        let managed = self.managed.clone();
        let authz = compile_managed_authz(&managed)?;
        let tenants = compile_managed_tenants(&managed, &authz)?;

        Ok(StateSnapshot {
            managed,
            authz,
            tenants,
        })
    }

    pub fn validate(managed: &ManagedConfig) -> Vec<String> {
        let mut issues = Vec::new();

        match compile_managed_authz(managed) {
            Ok(authz) => {
                if let Err(err) = compile_managed_tenants(managed, &authz) {
                    issues.push(err.to_string());
                }
            }
            Err(err) => issues.push(err.to_string()),
        }

        issues
    }

    pub fn plan(&self, managed: &ManagedConfig) -> Result<ManagedPlanResponse, DynError> {
        let issues = Self::validate(managed);
        if !issues.is_empty() {
            return Err(Box::<std::io::Error>::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                issues.join("; "),
            )));
        }

        let changes = diff_managed(&self.managed, managed);
        let authz = compile_managed_authz(managed)?;
        let tenants = compile_managed_tenants(managed, &authz)?;

        Ok(ManagedPlanResponse {
            noop: changes.is_empty(),
            summary: summarize_changes(&changes),
            changes,
            catalog_revision: authz.catalog_revision,
            policy_revision: tenants.policy_revision,
        })
    }

    pub fn apply(&mut self, managed: ManagedConfig) -> Result<ManagedPlanResponse, DynError> {
        self.apply_with_id(managed, None)
    }

    pub fn apply_with_id(
        &mut self,
        managed: ManagedConfig,
        apply_id: Option<String>,
    ) -> Result<ManagedPlanResponse, DynError> {
        let plan = self.plan(&managed)?;
        self.apply_counter += 1;
        self.apply_seq += 1;
        self.last_apply_id = apply_id.unwrap_or_else(|| format!("apply-{:06}", self.apply_counter));
        let apply_id = self.last_apply_id.clone();

        sync_versioned(
            &mut self.history.tenants,
            &self.managed.tenants,
            &managed.tenants,
            self.apply_seq,
            &apply_id,
            |entry| entry.id.clone(),
            |entry| entry.parent.clone().unwrap_or_else(|| "root".to_owned()),
            &mut self.scoped_versions,
            "tenants",
        );
        sync_versioned(
            &mut self.history.subjects,
            &self.managed.subjects,
            &managed.subjects,
            self.apply_seq,
            &apply_id,
            |entry| entry.id.clone(),
            |_| "global".to_owned(),
            &mut self.scoped_versions,
            "subjects",
        );
        sync_versioned(
            &mut self.history.memberships,
            &self.managed.memberships,
            &managed.memberships,
            self.apply_seq,
            &apply_id,
            |entry| format!("{}@{}", entry.subject, entry.tenant),
            |entry| entry.tenant.clone(),
            &mut self.scoped_versions,
            "memberships",
        );
        sync_versioned(
            &mut self.history.assumption_grants,
            &self.managed.assumption_grants,
            &managed.assumption_grants,
            self.apply_seq,
            &apply_id,
            |entry| {
                format!(
                    "{}:{}:{}",
                    entry.subject, entry.source_tenant, entry.target_tenant
                )
            },
            |entry| entry.source_tenant.clone(),
            &mut self.scoped_versions,
            "assumption_grants",
        );
        sync_versioned(
            &mut self.history.templates,
            &self.managed.templates,
            &managed.templates,
            self.apply_seq,
            &apply_id,
            |entry| format!("{}:{}", entry.tenant, entry.key),
            |entry| entry.tenant.clone(),
            &mut self.scoped_versions,
            "templates",
        );
        sync_versioned(
            &mut self.history.roles,
            &self.managed.roles,
            &managed.roles,
            self.apply_seq,
            &apply_id,
            |entry| format!("{}:{}", entry.tenant, entry.key),
            |entry| entry.tenant.clone(),
            &mut self.scoped_versions,
            "roles",
        );
        sync_versioned(
            &mut self.history.catalog_actions,
            &self.managed.catalog.actions,
            &managed.catalog.actions,
            self.apply_seq,
            &apply_id,
            |entry| entry.name.clone(),
            |_| "global".to_owned(),
            &mut self.scoped_versions,
            "catalog_actions",
        );

        self.managed = managed;
        Ok(plan)
    }

    pub fn set_last_apply_id(&mut self, apply_id: impl Into<String>) {
        self.last_apply_id = apply_id.into();
    }

    pub fn create_invite(
        &mut self,
        subject: &str,
        expires_in_seconds: u64,
    ) -> Result<(String, String, u64), DynError> {
        let snapshot = self.snapshot()?;
        if !snapshot
            .tenants
            .subjects
            .iter()
            .any(|entry| entry.id == subject)
        {
            return Err(Box::<std::io::Error>::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("unknown subject {subject}"),
            )));
        }

        let now = now_unix_seconds()?;
        let invite_id = format!("invite-{:06}", self.invites.len() + 1);
        let redeem_code = digest_hex(&format!("{subject}:{invite_id}:{now}:code"));
        let invite = InviteRecord {
            invite_id: invite_id.clone(),
            subject: subject.to_owned(),
            redeem_code_hash: digest_hex(&redeem_code),
            created_at: now,
            expires_at: now + expires_in_seconds.max(60),
            redeemed_at: None,
        };
        self.invites.push(invite);

        Ok((invite_id, redeem_code, now + expires_in_seconds.max(60)))
    }

    pub fn redeem_invite(&mut self, code: &str, password: &str) -> Result<String, DynError> {
        let now = now_unix_seconds()?;
        let digest = digest_hex(code);
        let invite = self
            .invites
            .iter_mut()
            .find(|entry| {
                entry.redeem_code_hash == digest
                    && entry.redeemed_at.is_none()
                    && entry.expires_at > now
            })
            .ok_or_else(|| {
                Box::<std::io::Error>::new(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "invalid or expired invite",
                )) as DynError
            })?;

        invite.redeemed_at = Some(now);
        let subject = invite.subject.clone();
        let salt = digest_hex(&format!("{subject}:{now}:salt"));
        let version = next_version(&mut self.scoped_versions, "credentials", "global");
        self.credentials.push(CredentialRecord {
            subject: subject.clone(),
            salt: salt.clone(),
            password_hash: digest_hex(&format!("{salt}:{password}")),
            valid_from: self.apply_seq.max(1),
            valid_to: None,
            row_version: version,
        });

        Ok(subject)
    }

    pub fn login(
        &mut self,
        subject: &str,
        password: &str,
        tenant: &str,
    ) -> Result<String, DynError> {
        let credential = self
            .credentials
            .iter()
            .rev()
            .find(|entry| entry.subject == subject && entry.valid_to.is_none())
            .ok_or_else(|| {
                Box::<std::io::Error>::new(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "subject has no credential",
                )) as DynError
            })?;

        if credential.password_hash != digest_hex(&format!("{}:{password}", credential.salt)) {
            return Err(Box::<std::io::Error>::new(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "invalid credentials",
            )));
        }

        let snapshot = self.snapshot()?;
        snapshot
            .tenants
            .find_membership(subject, tenant)
            .ok_or_else(|| {
                Box::<std::io::Error>::new(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("subject {subject} has no membership in tenant {tenant}"),
                )) as DynError
            })?;
        snapshot.tenants.require_active_tenant(tenant)?;

        let now = now_unix_seconds()?;
        let session_id = format!("session-{:06}", self.sessions.len() + 1);
        self.sessions.push(SessionRecord {
            session_id: session_id.clone(),
            subject: subject.to_owned(),
            tenant: tenant.to_owned(),
            created_at: now,
            last_seen_at: now,
        });

        Ok(session_id)
    }
}

fn diff_managed(current: &ManagedConfig, desired: &ManagedConfig) -> Vec<String> {
    let mut changes = Vec::new();
    append_changes(
        &mut changes,
        "tenant",
        &current.tenants,
        &desired.tenants,
        |entry| entry.id.clone(),
    );
    append_changes(
        &mut changes,
        "subject",
        &current.subjects,
        &desired.subjects,
        |entry| entry.id.clone(),
    );
    append_changes(
        &mut changes,
        "membership",
        &current.memberships,
        &desired.memberships,
        |entry| format!("{}@{}", entry.subject, entry.tenant),
    );
    append_changes(
        &mut changes,
        "assumption_grant",
        &current.assumption_grants,
        &desired.assumption_grants,
        |entry| {
            format!(
                "{}:{}:{}",
                entry.subject, entry.source_tenant, entry.target_tenant
            )
        },
    );
    append_changes(
        &mut changes,
        "template",
        &current.templates,
        &desired.templates,
        |entry| format!("{}:{}", entry.tenant, entry.key),
    );
    append_changes(
        &mut changes,
        "role",
        &current.roles,
        &desired.roles,
        |entry| format!("{}:{}", entry.tenant, entry.key),
    );
    append_changes(
        &mut changes,
        "action",
        &current.catalog.actions,
        &desired.catalog.actions,
        |entry| entry.name.clone(),
    );
    changes
}

fn append_changes<T, F>(
    changes: &mut Vec<String>,
    label: &str,
    current: &[T],
    desired: &[T],
    key: F,
) where
    T: Clone + PartialEq,
    F: Fn(&T) -> String,
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

    for entry in keys {
        match (current_map.get(&entry), desired_map.get(&entry)) {
            (None, Some(_)) => changes.push(format!("create {label} {entry}")),
            (Some(_), None) => changes.push(format!("delete {label} {entry}")),
            (Some(left), Some(right)) if *left != *right => {
                changes.push(format!("update {label} {entry}"))
            }
            _ => {}
        }
    }
}

fn summarize_changes(changes: &[String]) -> ManagedMutationCounts {
    let mut counts = ManagedMutationCounts {
        created: 0,
        updated: 0,
        deleted: 0,
    };

    for change in changes {
        if change.starts_with("create ") {
            counts.created += 1;
        } else if change.starts_with("update ") {
            counts.updated += 1;
        } else if change.starts_with("delete ") {
            counts.deleted += 1;
        }
    }

    counts
}

fn sync_versioned<T, K, S>(
    history: &mut Vec<VersionedRecord<T>>,
    current: &[T],
    desired: &[T],
    valid_from: u64,
    apply_id: &str,
    key: K,
    scope: S,
    scoped_versions: &mut BTreeMap<(String, String), u64>,
    table: &str,
) where
    T: Clone + PartialEq,
    K: Fn(&T) -> String,
    S: Fn(&T) -> String,
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

    for entry_key in keys {
        match (current_map.get(&entry_key), desired_map.get(&entry_key)) {
            (Some(left), Some(right)) if *left == *right => {}
            (Some(_), None) | (Some(_), Some(_)) => {
                if let Some(active) = history
                    .iter_mut()
                    .rev()
                    .find(|record| record.key == entry_key && record.valid_to.is_none())
                {
                    active.valid_to = Some(valid_from);
                }
            }
            _ => {}
        }

        if let Some(value) = desired_map.get(&entry_key) {
            let entry_scope = scope(value);
            let row_version = next_version(scoped_versions, table, &entry_scope);
            history.push(VersionedRecord {
                key: entry_key,
                scope: entry_scope,
                value: (*value).clone(),
                row_version,
                valid_from,
                valid_to: None,
                apply_id: apply_id.to_owned(),
            });
        }
    }
}

fn next_version(versions: &mut BTreeMap<(String, String), u64>, table: &str, scope: &str) -> u64 {
    let entry = versions
        .entry((table.to_owned(), scope.to_owned()))
        .or_insert(0);
    *entry += 1;
    *entry
}

pub fn now_unix_seconds() -> Result<u64, DynError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

pub fn digest_hex(input: &str) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn empty_managed_config() -> ManagedConfig {
    ManagedConfig::load_from_str("catalog { actions () }")
        .expect("empty managed config should parse")
}

#[cfg(test)]
mod tests {
    use super::ControlPlaneState;
    use conclave_managed_config::ManagedConfig;

    // r[verify config.managed.bootstrap-seed]
    #[test]
    fn bootstraps_empty_store_from_managed_config_once() {
        let mut state = ControlPlaneState::empty();
        let managed = ManagedConfig::load_from_str(
            r#"
catalog {
    actions (
        {name "tenant:user:read"}
    )
}
tenants (
    {id "tenant-a"}
)
subjects (
    {id "doctor-1"}
)
"#,
        )
        .expect("managed config should parse");

        let bootstrapped = state
            .bootstrap_from_managed_if_empty(managed.clone())
            .expect("bootstrap should succeed");
        let second = state
            .bootstrap_from_managed_if_empty(managed)
            .expect("second bootstrap should succeed");

        assert!(bootstrapped);
        assert!(!second);
        assert_eq!(state.last_apply_id, "apply-000001");
        assert!(state
            .managed()
            .subjects
            .iter()
            .any(|subject| subject.id == "doctor-1"));
    }
}
