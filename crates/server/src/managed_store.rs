use std::collections::{BTreeMap, BTreeSet};

use conclave_managed_config::{
    ActionSpec, AssumptionGrantConfig, ManagedConfig, MembershipConfig, RoleConfig, SubjectConfig,
    TemplateConfig, TenantConfig,
};
use serde::{Deserialize, Serialize};

use crate::config::FelderaConfig;
use crate::feldera::{DesiredPipeline, FelderaClient, PipelineProgramConfig};
use crate::state::{digest_hex, now_unix_seconds};
use crate::types::DynError;

#[derive(Clone, Debug)]
pub struct FelderaManagedStore {
    client: FelderaClient,
    pipeline_name: String,
    config: FelderaConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ManagedEventRow {
    #[serde(alias = "RESOURCE_KIND")]
    resource_kind: String,
    #[serde(alias = "RESOURCE_KEY")]
    resource_key: String,
    #[serde(alias = "SCOPE")]
    scope: String,
    #[serde(alias = "APPLY_ID")]
    apply_id: String,
    #[serde(alias = "ROW_VERSION")]
    row_version: u64,
    #[serde(alias = "VALID_FROM")]
    valid_from: u64,
    #[serde(alias = "DELETED")]
    deleted: bool,
    #[serde(alias = "PAYLOAD_JSON")]
    payload_json: Option<String>,
}

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
struct CountRow {
    #[serde(alias = "COUNT")]
    count: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LatestApplyRow {
    #[serde(alias = "APPLY_ID")]
    apply_id: String,
}

impl FelderaManagedStore {
    pub fn new(client: FelderaClient, config: FelderaConfig) -> Self {
        Self {
            pipeline_name: format!("{}_controlplane", config.pipeline_prefix),
            client,
            config,
        }
    }

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

        Ok(())
    }

    pub async fn bootstrap_if_empty(&self, managed: &ManagedConfig) -> Result<bool, DynError> {
        self.ensure_pipeline().await?;
        let rows: Vec<CountRow> = self
            .client
            .query_json(
                &self.pipeline_name,
                "SELECT CAST(COUNT(*) AS BIGINT) AS count FROM APPLY_COMMIT WHERE committed = TRUE",
            )
            .await?;

        if rows.first().map(|row| row.count).unwrap_or(0) == 0 {
            self.apply(managed).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub async fn load_managed(&self) -> Result<ManagedConfig, DynError> {
        self.ensure_pipeline().await?;
        let rows: Vec<ManagedEventRow> = self
            .client
            .query_json(
                &self.pipeline_name,
                "SELECT resource_kind, resource_key, scope, apply_id, row_version, valid_from, deleted, payload_json FROM CURRENT_MANAGED_EVENT WHERE deleted = FALSE",
            )
            .await?;

        let mut catalog = Vec::new();
        let mut templates = Vec::new();
        let mut roles = Vec::new();
        let mut tenants = Vec::new();
        let mut subjects = Vec::new();
        let mut memberships = Vec::new();
        let mut assumption_grants = Vec::new();

        for row in rows {
            let payload = row.payload_json.unwrap_or_default();
            match row.resource_kind.as_str() {
                "action" => catalog.push(serde_json::from_str::<ActionSpec>(&payload)?),
                "template" => templates.push(serde_json::from_str::<TemplateConfig>(&payload)?),
                "role" => roles.push(serde_json::from_str::<RoleConfig>(&payload)?),
                "tenant" => tenants.push(serde_json::from_str::<TenantConfig>(&payload)?),
                "subject" => subjects.push(serde_json::from_str::<SubjectConfig>(&payload)?),
                "membership" => {
                    memberships.push(serde_json::from_str::<MembershipConfig>(&payload)?)
                }
                "assumption_grant" => {
                    assumption_grants.push(serde_json::from_str::<AssumptionGrantConfig>(&payload)?)
                }
                _ => {}
            }
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
                "SELECT apply_id FROM APPLY_COMMIT WHERE committed = TRUE ORDER BY committed_at DESC LIMIT 1",
            )
            .await?;

        Ok(rows.into_iter().next().map(|row| row.apply_id))
    }

    pub async fn apply(&self, desired: &ManagedConfig) -> Result<String, DynError> {
        self.ensure_pipeline().await?;
        let current = self
            .load_managed()
            .await
            .unwrap_or_else(|_| empty_managed_config());
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let apply_id = format!(
            "apply-{}",
            &digest_hex(&format!("{nonce}:{}", serde_json::to_string(desired)?))[0..12]
        );
        let valid_from = now_unix_seconds()?;
        let changes = diff_rows(&current, desired);

        for change in changes {
            let row_version = self
                .next_row_version(&change.resource_kind, &change.scope)
                .await?;
            let event = ManagedEventRow {
                resource_kind: change.resource_kind,
                resource_key: change.resource_key,
                scope: change.scope,
                apply_id: apply_id.clone(),
                row_version,
                valid_from,
                deleted: change.deleted,
                payload_json: change.payload_json,
            };
            self.client
                .insert_json_rows(&self.pipeline_name, "MANAGED_EVENT", vec![event])
                .await?;
        }

        self.client
            .insert_json_rows(
                &self.pipeline_name,
                "APPLY_COMMIT",
                vec![ApplyCommitRow {
                    apply_id: apply_id.clone(),
                    committed_at: valid_from,
                    committed: true,
                }],
            )
            .await?;

        Ok(apply_id)
    }

    async fn next_row_version(&self, resource_kind: &str, scope: &str) -> Result<u64, DynError> {
        let sql = format!(
            "SELECT CAST(COALESCE(MAX(row_version), 0) AS BIGINT) AS count FROM MANAGED_EVENT WHERE resource_kind = '{}' AND scope = '{}'",
            escape_sql(resource_kind),
            escape_sql(scope)
        );
        let rows: Vec<CountRow> = self.client.query_json(&self.pipeline_name, &sql).await?;
        Ok(rows.first().map(|row| row.count).unwrap_or(0) + 1)
    }
}

#[derive(Clone)]
struct ChangeRow {
    resource_kind: String,
    resource_key: String,
    scope: String,
    deleted: bool,
    payload_json: Option<String>,
}

fn diff_rows(current: &ManagedConfig, desired: &ManagedConfig) -> Vec<ChangeRow> {
    let mut changes = Vec::new();
    append_changes(
        &mut changes,
        "tenant",
        &current.tenants,
        &desired.tenants,
        |entry| entry.id.clone(),
        |entry| entry.parent.clone().unwrap_or_else(|| "root".to_owned()),
    );
    append_changes(
        &mut changes,
        "subject",
        &current.subjects,
        &desired.subjects,
        |entry| entry.id.clone(),
        |_| "global".to_owned(),
    );
    append_changes(
        &mut changes,
        "membership",
        &current.memberships,
        &desired.memberships,
        |entry| format!("{}@{}", entry.subject, entry.tenant),
        |entry| entry.tenant.clone(),
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
        |entry| entry.source_tenant.clone(),
    );
    append_changes(
        &mut changes,
        "template",
        &current.templates,
        &desired.templates,
        |entry| format!("{}:{}", entry.tenant, entry.key),
        |entry| entry.tenant.clone(),
    );
    append_changes(
        &mut changes,
        "role",
        &current.roles,
        &desired.roles,
        |entry| format!("{}:{}", entry.tenant, entry.key),
        |entry| entry.tenant.clone(),
    );
    append_changes(
        &mut changes,
        "action",
        &current.catalog.actions,
        &desired.catalog.actions,
        |entry| entry.name.clone(),
        |_| "global".to_owned(),
    );
    changes
}

fn append_changes<T, K, S>(
    changes: &mut Vec<ChangeRow>,
    kind: &str,
    current: &[T],
    desired: &[T],
    key: K,
    scope: S,
) where
    T: Clone + PartialEq + Serialize,
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

    for resource_key in keys {
        match (
            current_map.get(&resource_key),
            desired_map.get(&resource_key),
        ) {
            (Some(left), Some(right)) if *left == *right => {}
            (_, Some(value)) => changes.push(ChangeRow {
                resource_kind: kind.to_owned(),
                resource_key,
                scope: scope(value),
                deleted: false,
                payload_json: Some(serde_json::to_string(value).expect("payload should serialize")),
            }),
            (Some(value), None) => changes.push(ChangeRow {
                resource_kind: kind.to_owned(),
                resource_key,
                scope: scope(value),
                deleted: true,
                payload_json: None,
            }),
            _ => {}
        }
    }
}

fn managed_store_sql() -> String {
    r#"
CREATE TABLE APPLY_COMMIT (
    apply_id VARCHAR NOT NULL,
    committed_at BIGINT NOT NULL,
    committed BOOLEAN NOT NULL
) WITH ('materialized' = 'true');

CREATE TABLE MANAGED_EVENT (
    resource_kind VARCHAR NOT NULL,
    resource_key VARCHAR NOT NULL,
    scope VARCHAR NOT NULL,
    apply_id VARCHAR NOT NULL,
    row_version BIGINT NOT NULL,
    valid_from BIGINT NOT NULL,
    deleted BOOLEAN NOT NULL,
    payload_json VARCHAR
) WITH ('materialized' = 'true');

CREATE MATERIALIZED VIEW VERSIONED_MANAGED_EVENT AS
SELECT
    e.resource_kind,
    e.resource_key,
    e.scope,
    e.apply_id,
    e.row_version,
    e.valid_from,
    (
        SELECT MIN(e2.valid_from)
        FROM MANAGED_EVENT e2
        JOIN APPLY_COMMIT c2 ON e2.apply_id = c2.apply_id AND c2.committed = TRUE
        WHERE e2.resource_kind = e.resource_kind
          AND e2.resource_key = e.resource_key
          AND e2.row_version > e.row_version
    ) AS valid_to,
    e.deleted,
    e.payload_json
FROM MANAGED_EVENT e
JOIN APPLY_COMMIT c ON e.apply_id = c.apply_id AND c.committed = TRUE;

CREATE MATERIALIZED VIEW CURRENT_MANAGED_EVENT AS
SELECT
    resource_kind,
    resource_key,
    scope,
    apply_id,
    row_version,
    valid_from,
    deleted,
    payload_json
FROM VERSIONED_MANAGED_EVENT
WHERE valid_to IS NULL;
"#
    .trim()
    .to_owned()
}

fn empty_managed_config() -> ManagedConfig {
    ManagedConfig::load_from_str("catalog { actions () }")
        .expect("empty managed config should parse")
}

fn escape_sql(input: &str) -> String {
    input.replace('\'', "''")
}

#[cfg(test)]
mod tests {
    use super::{diff_rows, managed_store_sql, ApplyCommitRow, ManagedEventRow};
    use conclave_managed_config::ManagedConfig;

    #[test]
    fn generates_store_sql_with_materialized_current_view() {
        let sql = managed_store_sql();

        assert!(sql.contains("CREATE TABLE APPLY_COMMIT"));
        assert!(sql.contains("CREATE TABLE MANAGED_EVENT"));
        assert!(sql.contains("CREATE MATERIALIZED VIEW VERSIONED_MANAGED_EVENT"));
        assert!(sql.contains("CREATE MATERIALIZED VIEW CURRENT_MANAGED_EVENT"));
        assert!(sql.contains("valid_to"));
    }

    #[test]
    fn diffs_managed_resources_into_event_rows() {
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

        let changes = diff_rows(&current, &desired);

        assert!(changes
            .iter()
            .any(|change| change.resource_key == "tenant-a" && change.deleted));
        assert!(changes
            .iter()
            .any(|change| change.resource_key == "tenant-b" && !change.deleted));
        assert!(changes
            .iter()
            .any(|change| change.resource_key == "tenant:user:write"));
    }

    #[test]
    fn deserializes_uppercase_query_rows() {
        let event: ManagedEventRow = serde_json::from_str(
            r#"{
                "RESOURCE_KIND":"tenant",
                "RESOURCE_KEY":"tenant-a",
                "SCOPE":"root",
                "APPLY_ID":"apply-1",
                "ROW_VERSION":1,
                "VALID_FROM":1,
                "DELETED":false,
                "PAYLOAD_JSON":"{\"id\":\"tenant-a\"}"
            }"#,
        )
        .expect("event row should deserialize");
        let commit: ApplyCommitRow =
            serde_json::from_str(r#"{"APPLY_ID":"apply-1","COMMITTED_AT":1,"COMMITTED":true}"#)
                .expect("commit row should deserialize");

        assert_eq!(event.resource_key, "tenant-a");
        assert!(commit.committed);
    }
}
