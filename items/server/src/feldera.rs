use std::time::Duration;

use reqwest::{Client, Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::authz::CompiledAuthzModel;
use crate::config::FelderaConfig;
use crate::tenants::{CompiledEffectiveGrant, CompiledScopeGrant, CompiledTenantModel};
use conclave_relying_auth::ActionCatalogEntry;

type DynError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone, Debug)]
pub struct FelderaClient {
    client: Client,
    base_url: String,
    api_key: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PipelineSummary {
    pub name: String,
    pub program_status: Option<String>,
    pub deployment_status: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PipelineProgramConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PipelineRuntimeConfig {}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DesiredPipeline {
    pub name: String,
    pub description: String,
    pub program_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program_config: Option<PipelineProgramConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_config: Option<PipelineRuntimeConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PipelineRecord {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub program_code: Option<String>,
    #[serde(default)]
    pub program_status: Option<String>,
    #[serde(default)]
    pub deployment_status: Option<String>,
    #[serde(default)]
    pub deployment_resources_status: Option<String>,
    #[serde(default)]
    pub deployment_runtime_status: Option<String>,
    #[serde(default)]
    pub program_config: Option<PipelineProgramConfig>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PipelineSyncAction {
    Create,
    Update,
    Noop,
    BlockedRunningUpdate,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PipelineSyncPlan {
    pub action: PipelineSyncAction,
    pub pipeline_name: String,
    pub changed_fields: Vec<String>,
    pub desired: DesiredPipeline,
    pub current: Option<PipelineRecord>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PipelineSyncResult {
    pub action: PipelineSyncAction,
    pub pipeline_name: String,
    pub changed_fields: Vec<String>,
    pub status: String,
}

#[derive(Clone, Debug)]
pub struct StartPipelineRequest {
    pub initial: String,
    pub bootstrap_policy: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct CompletionStatusResponse {
    #[serde(default, alias = "status", alias = "STATUS")]
    status: Option<String>,
    #[serde(default, alias = "completed", alias = "COMPLETED")]
    completed: Option<bool>,
}

#[derive(Clone, Debug, Deserialize)]
struct IngressResponse {
    #[serde(default, alias = "completion_token", alias = "COMPLETION_TOKEN")]
    completion_token: Option<String>,
    #[serde(default, alias = "token", alias = "TOKEN")]
    token: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct PipelineStats {
    #[serde(default)]
    pub global_metrics: PipelineGlobalMetrics,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct PipelineGlobalMetrics {
    #[serde(default)]
    pub transaction_status: Option<String>,
    #[serde(default)]
    pub transaction_id: Option<u64>,
    #[serde(default)]
    pub bootstrap_in_progress: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct TransactionStartResponse {
    pub transaction_id: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct CheckpointStartResponse {
    pub checkpoint_sequence_number: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct CheckpointStatus {
    #[serde(default)]
    pub success: Option<u64>,
    #[serde(default)]
    pub failure: Option<CheckpointFailure>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct CheckpointFailure {
    pub sequence_number: u64,
    pub error: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct CompiledAuthzMetadata {
    #[serde(alias = "catalog_revision", alias = "CATALOG_REVISION")]
    pub catalog_revision: u32,
    #[serde(alias = "policy_revision", alias = "POLICY_REVISION")]
    pub policy_revision: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
struct EffectiveGrantIdentityRow {
    #[serde(alias = "grant_kind", alias = "GRANT_KIND")]
    grant_kind: String,
    #[serde(alias = "subject_id", alias = "SUBJECT_ID")]
    subject_id: String,
    #[serde(alias = "source_tenant_id", alias = "SOURCE_TENANT_ID")]
    source_tenant_id: String,
    #[serde(alias = "source_tenant_state", alias = "SOURCE_TENANT_STATE")]
    source_tenant_state: String,
    #[serde(alias = "target_tenant_id", alias = "TARGET_TENANT_ID")]
    target_tenant_id: String,
    #[serde(alias = "target_tenant_state", alias = "TARGET_TENANT_STATE")]
    target_tenant_state: String,
    #[serde(alias = "facts_json", alias = "FACTS_JSON")]
    facts_json: String,
    #[serde(alias = "ttl_seconds", alias = "TTL_SECONDS")]
    ttl_seconds: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct EffectiveGrantActionRow {
    #[serde(alias = "scope_kind", alias = "SCOPE_KIND")]
    scope_kind: String,
    #[serde(alias = "scope_id", alias = "SCOPE_ID")]
    scope_id: String,
    #[serde(alias = "bit_index", alias = "BIT_INDEX")]
    bit_index: usize,
}

#[derive(Debug)]
struct FelderaError {
    message: String,
}

impl FelderaError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for FelderaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.message.fmt(f)
    }
}

impl std::error::Error for FelderaError {}

impl FelderaClient {
    pub fn new(base_url: impl Into<String>, api_key: Option<String>) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            api_key,
        }
    }

    // r[impl platform.server.control-plane-boundary]
    pub async fn list_pipelines(&self) -> Result<Vec<PipelineSummary>, DynError> {
        let url = format!("{}/v0/pipelines", self.base_url);
        let payload: Value = self
            .request(Method::GET, url)
            .query(&[("selector", "status")])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let entries = payload
            .as_array()
            .cloned()
            .or_else(|| payload.get("items").and_then(Value::as_array).cloned())
            .unwrap_or_default();

        Ok(entries.iter().map(PipelineSummary::from_value).collect())
    }

    pub async fn get_pipeline(
        &self,
        name: &str,
        selector: &str,
    ) -> Result<Option<PipelineRecord>, DynError> {
        let url = format!("{}/v0/pipelines/{name}", self.base_url);
        let response = self
            .request(Method::GET, url)
            .query(&[("selector", selector)])
            .send()
            .await?;

        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        Ok(Some(response.error_for_status()?.json().await?))
    }

    pub async fn create_pipeline(
        &self,
        desired: &DesiredPipeline,
    ) -> Result<PipelineRecord, DynError> {
        let url = format!("{}/v0/pipelines", self.base_url);
        Ok(self
            .request(Method::POST, url)
            .json(desired)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn patch_pipeline(
        &self,
        desired: &DesiredPipeline,
    ) -> Result<PipelineRecord, DynError> {
        let url = format!("{}/v0/pipelines/{}", self.base_url, desired.name);
        let patch = PipelinePatch::from_desired(desired);

        Ok(self
            .request(Method::PATCH, url)
            .json(&patch)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn start_pipeline(
        &self,
        name: &str,
        request: &StartPipelineRequest,
    ) -> Result<(), DynError> {
        let url = format!("{}/v0/pipelines/{name}/start", self.base_url);
        let mut query = vec![("initial", request.initial.as_str())];

        if let Some(bootstrap_policy) = request.bootstrap_policy.as_deref() {
            query.push(("bootstrap_policy", bootstrap_policy));
        }

        self.request(Method::POST, url)
            .query(&query)
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }

    pub async fn stop_pipeline(&self, name: &str, force: bool) -> Result<(), DynError> {
        let url = format!("{}/v0/pipelines/{name}/stop", self.base_url);
        self.request(Method::POST, url)
            .query(&[("force", force)])
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }

    pub async fn get_pipeline_stats(&self, pipeline_name: &str) -> Result<PipelineStats, DynError> {
        let url = format!("{}/v0/pipelines/{pipeline_name}/stats", self.base_url);
        Ok(self
            .request(Method::GET, url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn start_transaction(
        &self,
        pipeline_name: &str,
    ) -> Result<TransactionStartResponse, DynError> {
        let url = format!(
            "{}/v0/pipelines/{pipeline_name}/start_transaction",
            self.base_url
        );
        Ok(self
            .request(Method::POST, url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn commit_transaction(&self, pipeline_name: &str) -> Result<(), DynError> {
        let url = format!(
            "{}/v0/pipelines/{pipeline_name}/commit_transaction",
            self.base_url
        );
        self.request(Method::POST, url)
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }

    pub async fn checkpoint_now(
        &self,
        pipeline_name: &str,
    ) -> Result<CheckpointStartResponse, DynError> {
        let url = format!("{}/v0/pipelines/{pipeline_name}/checkpoint", self.base_url);
        Ok(self
            .request(Method::POST, url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn get_checkpoint_status(
        &self,
        pipeline_name: &str,
    ) -> Result<CheckpointStatus, DynError> {
        let url = format!(
            "{}/v0/pipelines/{pipeline_name}/checkpoint_status",
            self.base_url
        );
        Ok(self
            .request(Method::GET, url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn wait_for_checkpoint(
        &self,
        pipeline_name: &str,
        checkpoint_sequence_number: u64,
    ) -> Result<(), DynError> {
        for _ in 0..120 {
            let status = self.get_checkpoint_status(pipeline_name).await?;

            if status
                .success
                .is_some_and(|success| success >= checkpoint_sequence_number)
            {
                return Ok(());
            }

            if let Some(failure) = status.failure {
                if failure.sequence_number >= checkpoint_sequence_number {
                    return Err(Box::new(FelderaError::new(format!(
                        "checkpoint {checkpoint_sequence_number} failed for pipeline {pipeline_name}: {}",
                        failure.error
                    ))));
                }
            }

            actix_web::rt::time::sleep(Duration::from_millis(250)).await;
        }

        Err(Box::new(FelderaError::new(format!(
            "timed out waiting for checkpoint {checkpoint_sequence_number} on pipeline {pipeline_name}"
        ))))
    }

    pub async fn query_json<T>(&self, pipeline_name: &str, sql: &str) -> Result<Vec<T>, DynError>
    where
        T: DeserializeOwned,
    {
        let url = format!("{}/v0/pipelines/{pipeline_name}/query", self.base_url);
        let response = self
            .request(Method::GET, url)
            .query(&[("sql", sql), ("format", "json")])
            .send()
            .await?
            .error_for_status()?;
        let body = response.text().await?;

        parse_json_rows(&body)
    }

    pub async fn insert_json_rows<T>(
        &self,
        pipeline_name: &str,
        table_name: &str,
        rows: Vec<T>,
    ) -> Result<(), DynError>
    where
        T: Serialize,
    {
        if rows.is_empty() {
            return Ok(());
        }

        let url = format!(
            "{}/v0/pipelines/{pipeline_name}/ingress/{table_name}",
            self.base_url
        );
        let response = self
            .request(Method::POST, url)
            .query(&[
                ("format", "json"),
                ("array", "true"),
                ("force", "true"),
                ("update_format", "raw"),
            ])
            .json(&rows)
            .send()
            .await?
            .error_for_status()?;

        let completion = response.json::<IngressResponse>().await.ok();
        if let Some(token) = completion
            .and_then(|entry| entry.completion_token.or(entry.token))
            .filter(|token| !token.is_empty())
        {
            self.wait_for_completion(pipeline_name, &token).await?;
        }

        Ok(())
    }

    pub async fn wait_for_no_transaction(&self, pipeline_name: &str) -> Result<(), DynError> {
        for _ in 0..120 {
            let stats = self.get_pipeline_stats(pipeline_name).await?;
            if stats.global_metrics.transaction_status.as_deref() == Some("NoTransaction") {
                return Ok(());
            }

            actix_web::rt::time::sleep(Duration::from_millis(250)).await;
        }

        Err(Box::new(FelderaError::new(format!(
            "timed out waiting for pipeline {pipeline_name} to leave transactional state"
        ))))
    }
}

impl PipelineSummary {
    fn from_value(value: &Value) -> Self {
        Self {
            name: string_field(value, &["name", "pipeline_name"])
                .unwrap_or_else(|| "unknown".into()),
            program_status: string_field(value, &["program_status"]),
            deployment_status: string_field(
                value,
                &["deployment_status", "deployment_resources_status"],
            ),
        }
    }
}

impl DesiredPipeline {
    // r[impl config.managed.authz-recompile-before-issuance]
    pub fn from_snapshot(
        config: &FelderaConfig,
        authz: &CompiledAuthzModel,
        tenants: &CompiledTenantModel,
    ) -> Self {
        Self {
            name: authz_pipeline_name(config),
            description: format!(
                "Generated by conclave-server from catalog revision {}",
                authz.catalog_revision
            ),
            program_code: authz.feldera_sql(&config.pipeline_prefix, tenants),
            program_config: Some(PipelineProgramConfig {
                profile: Some(config.compile_profile.clone()),
            }),
            runtime_config: None,
        }
    }
}

impl PipelineSyncPlan {
    pub fn for_desired(desired: DesiredPipeline, current: Option<PipelineRecord>) -> Self {
        let changed_fields = current
            .as_ref()
            .map(|record| changed_fields(record, &desired))
            .unwrap_or_else(|| vec!["pipeline".to_owned()]);

        let action = match &current {
            None => PipelineSyncAction::Create,
            Some(_) if changed_fields.is_empty() => PipelineSyncAction::Noop,
            Some(record) if !pipeline_is_stopped(record) => {
                PipelineSyncAction::BlockedRunningUpdate
            }
            Some(_) => PipelineSyncAction::Update,
        };

        Self {
            action,
            pipeline_name: desired.name.clone(),
            changed_fields,
            desired,
            current,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct PipelinePatch {
    description: String,
    program_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    program_config: Option<PipelineProgramConfig>,
}

impl PipelinePatch {
    fn from_desired(desired: &DesiredPipeline) -> Self {
        Self {
            description: desired.description.clone(),
            program_code: desired.program_code.clone(),
            program_config: desired.program_config.clone(),
        }
    }
}

fn changed_fields(current: &PipelineRecord, desired: &DesiredPipeline) -> Vec<String> {
    let mut changed = Vec::new();

    if current.description.as_deref() != Some(desired.description.as_str()) {
        changed.push("description".to_owned());
    }

    if current.program_code.as_deref() != Some(desired.program_code.as_str()) {
        changed.push("program_code".to_owned());
    }

    if current.program_config != desired.program_config {
        changed.push("program_config".to_owned());
    }

    changed
}

fn pipeline_is_stopped(record: &PipelineRecord) -> bool {
    matches!(record.deployment_status.as_deref(), None | Some("Stopped"))
        || matches!(
            record.deployment_resources_status.as_deref(),
            Some("Stopped")
        )
}

fn sql_string(value: &str) -> String {
    value.replace('\'', "''")
}

fn string_field(value: &Value, names: &[&str]) -> Option<String> {
    names
        .iter()
        .find_map(|name| value.get(name))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn format_sync_status(action: &PipelineSyncAction) -> String {
    match action {
        PipelineSyncAction::Create => "created",
        PipelineSyncAction::Update => "updated",
        PipelineSyncAction::Noop => "noop",
        PipelineSyncAction::BlockedRunningUpdate => "blocked",
    }
    .to_owned()
}

impl FelderaClient {
    async fn apply_plan(
        &self,
        plan: &PipelineSyncPlan,
        start: Option<&StartPipelineRequest>,
    ) -> Result<PipelineSyncResult, DynError> {
        match plan.action {
            PipelineSyncAction::Create => {
                self.create_pipeline(&plan.desired).await?;

                if let Some(start_request) = start {
                    self.start_pipeline(&plan.pipeline_name, start_request)
                        .await?;
                }
            }
            PipelineSyncAction::Update => {
                self.patch_pipeline(&plan.desired).await?;

                if let Some(start_request) = start {
                    self.start_pipeline(&plan.pipeline_name, start_request)
                        .await?;
                }
            }
            PipelineSyncAction::Noop => {
                if let Some(start_request) = start {
                    self.start_pipeline(&plan.pipeline_name, start_request)
                        .await?;
                }
            }
            PipelineSyncAction::BlockedRunningUpdate => {
                return Err(Box::new(FelderaError::new(format!(
                    "refusing to update pipeline {} while it is not stopped",
                    plan.pipeline_name
                ))));
            }
        }

        Ok(PipelineSyncResult {
            action: plan.action.clone(),
            pipeline_name: plan.pipeline_name.clone(),
            changed_fields: plan.changed_fields.clone(),
            status: format_sync_status(&plan.action),
        })
    }

    fn request(&self, method: Method, url: String) -> reqwest::RequestBuilder {
        let builder = self.client.request(method, url);

        if let Some(api_key) = &self.api_key {
            builder.bearer_auth(api_key)
        } else {
            builder
        }
    }

    async fn wait_for_completion(&self, pipeline_name: &str, token: &str) -> Result<(), DynError> {
        let url = format!(
            "{}/v0/pipelines/{pipeline_name}/completion_status",
            self.base_url
        );

        for _ in 0..20 {
            let response = self
                .request(Method::GET, url.clone())
                .query(&[("token", token)])
                .send()
                .await?
                .error_for_status()?;
            let status = response.json::<CompletionStatusResponse>().await?;

            if status.completed == Some(true) {
                return Ok(());
            }

            if status.status.as_deref().is_some_and(|value| {
                value.eq_ignore_ascii_case("success")
                    || value.eq_ignore_ascii_case("complete")
                    || value.eq_ignore_ascii_case("completed")
            }) {
                return Ok(());
            }

            actix_web::rt::time::sleep(Duration::from_millis(25)).await;
        }

        Err(Box::new(FelderaError::new(format!(
            "timed out waiting for completion token {token} on pipeline {pipeline_name}"
        ))))
    }
}

fn parse_json_rows<T>(body: &str) -> Result<Vec<T>, DynError>
where
    T: DeserializeOwned,
{
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    if let Ok(rows) = serde_json::from_str::<Vec<T>>(trimmed) {
        return Ok(rows);
    }

    if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
        if let Some(rows) = value.get("rows").cloned() {
            return Ok(serde_json::from_value(rows)?);
        }

        if value.is_array() {
            return Ok(serde_json::from_value(value)?);
        }
    }

    trimmed
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<T>(line).map_err(|err| Box::new(err) as DynError))
        .collect()
}

pub async fn fetch_authz_pipeline_plan(
    client: &FelderaClient,
    config: &FelderaConfig,
    authz: &CompiledAuthzModel,
    tenants: &CompiledTenantModel,
) -> Result<PipelineSyncPlan, DynError> {
    let desired = DesiredPipeline::from_snapshot(config, authz, tenants);
    let current = client.get_pipeline(&desired.name, "all").await?;

    Ok(PipelineSyncPlan::for_desired(desired, current))
}

pub async fn sync_authz_pipeline(
    client: &FelderaClient,
    config: &FelderaConfig,
    authz: &CompiledAuthzModel,
    tenants: &CompiledTenantModel,
    start: Option<StartPipelineRequest>,
) -> Result<PipelineSyncResult, DynError> {
    let plan = fetch_authz_pipeline_plan(client, config, authz, tenants).await?;
    client.apply_plan(&plan, start.as_ref()).await
}

pub fn authz_pipeline_name(config: &FelderaConfig) -> String {
    format!("{}_authz", config.pipeline_prefix)
}

pub async fn load_compiled_authz_metadata(
    client: &FelderaClient,
    config: &FelderaConfig,
) -> Result<Option<CompiledAuthzMetadata>, DynError> {
    let mut rows = client
        .query_json::<CompiledAuthzMetadata>(
            &authz_pipeline_name(config),
            "SELECT catalog_revision, policy_revision FROM compiled_authz_metadata LIMIT 1",
        )
        .await?;
    Ok(rows.pop())
}

pub async fn load_action_catalog_entries(
    client: &FelderaClient,
    config: &FelderaConfig,
) -> Result<Vec<ActionCatalogEntry>, DynError> {
    client
        .query_json(
            &authz_pipeline_name(config),
            "SELECT action_name AS name, bit_index AS bit FROM action_catalog ORDER BY bit_index",
        )
        .await
}

pub async fn load_effective_grant(
    client: &FelderaClient,
    config: &FelderaConfig,
    grant_kind: &str,
    subject_id: &str,
    target_tenant_id: &str,
    source_tenant_id: Option<&str>,
) -> Result<Option<CompiledEffectiveGrant>, DynError> {
    let source_tenant_key = source_tenant_id.unwrap_or("");
    let identity_sql = format!(
        "SELECT grant_kind, subject_id, source_tenant_id, source_tenant_state, target_tenant_id, target_tenant_state, facts_json, ttl_seconds \
         FROM effective_grants \
         WHERE grant_kind = '{}' AND subject_id = '{}' AND target_tenant_id = '{}' AND source_tenant_id = '{}' \
         LIMIT 1",
        sql_string(grant_kind),
        sql_string(subject_id),
        sql_string(target_tenant_id),
        sql_string(source_tenant_key),
    );
    let mut identities = client
        .query_json::<EffectiveGrantIdentityRow>(&authz_pipeline_name(config), &identity_sql)
        .await?;
    let Some(identity) = identities.pop() else {
        return Ok(None);
    };

    let actions_sql = format!(
        "SELECT scope_kind, scope_id, bit_index \
         FROM effective_grant_actions \
         WHERE grant_kind = '{}' AND subject_id = '{}' AND target_tenant_id = '{}' AND source_tenant_id = '{}' \
         ORDER BY scope_kind, scope_id, bit_index",
        sql_string(grant_kind),
        sql_string(subject_id),
        sql_string(target_tenant_id),
        sql_string(source_tenant_key),
    );
    let action_rows = client
        .query_json::<EffectiveGrantActionRow>(&authz_pipeline_name(config), &actions_sql)
        .await?;

    Ok(Some(compiled_effective_grant_from_rows(
        identity,
        action_rows,
    )?))
}

fn compiled_effective_grant_from_rows(
    identity: EffectiveGrantIdentityRow,
    action_rows: Vec<EffectiveGrantActionRow>,
) -> Result<CompiledEffectiveGrant, DynError> {
    use std::collections::BTreeMap;

    let mut tenant_bits = DynamicBitset::default();
    let mut scoped_bits =
        BTreeMap::<(crate::types::ScopeKind, Option<crate::types::ScopeId>), DynamicBitset>::new();

    for row in action_rows {
        if row.scope_kind.is_empty() {
            tenant_bits.insert(row.bit_index);
            continue;
        }

        let scope_id = if row.scope_id.is_empty() {
            None
        } else {
            Some(row.scope_id)
        };
        scoped_bits
            .entry((row.scope_kind, scope_id))
            .or_default()
            .insert(row.bit_index);
    }

    Ok(CompiledEffectiveGrant {
        grant_kind: identity.grant_kind,
        subject: identity.subject_id,
        source_tenant: string_option(identity.source_tenant_id),
        source_tenant_state: string_option(identity.source_tenant_state),
        target_tenant: identity.target_tenant_id,
        target_tenant_state: identity.target_tenant_state,
        tenant_bits_hex: tenant_bits.to_hex(),
        scoped_entries: scoped_bits
            .into_iter()
            .map(|((kind, id), bits)| CompiledScopeGrant {
                kind,
                id,
                bits_hex: bits.to_hex(),
            })
            .collect(),
        facts: serde_json::from_str(&identity.facts_json)?,
        ttl_seconds: identity.ttl_seconds,
    })
}

#[derive(Clone, Debug, Default)]
struct DynamicBitset {
    words: Vec<u64>,
}

impl DynamicBitset {
    fn insert(&mut self, bit_index: usize) {
        let word_index = bit_index / 64;
        if self.words.len() <= word_index {
            self.words.resize(word_index + 1, 0);
        }
        self.words[word_index] |= 1_u64 << (bit_index % 64);
    }

    fn to_hex(&self) -> String {
        if self.words.is_empty() {
            return "0".to_owned();
        }

        let mut chunks: Vec<String> = self
            .words
            .iter()
            .rev()
            .map(|word| format!("{word:016x}"))
            .collect();

        while chunks.len() > 1
            && chunks
                .first()
                .is_some_and(|chunk| chunk == "0000000000000000")
        {
            chunks.remove(0);
        }

        let hex = chunks.join("");
        let trimmed = hex.trim_start_matches('0');
        if trimmed.is_empty() {
            "0".to_owned()
        } else {
            trimmed.to_owned()
        }
    }
}

fn string_option(value: String) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use conclave_managed_config::ManagedConfig;
    use serde::Deserialize;
    use serde_json::json;
    use std::net::TcpListener;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };

    use crate::authz::compile_managed_authz;
    use crate::config::FelderaConfig;
    use crate::tenants::compile_managed_tenants;

    use super::{
        changed_fields, compiled_effective_grant_from_rows, parse_json_rows, CheckpointStatus,
        DesiredPipeline, EffectiveGrantActionRow, EffectiveGrantIdentityRow, FelderaClient,
        PipelineGlobalMetrics, PipelineProgramConfig, PipelineRecord, PipelineStats,
        PipelineSummary, PipelineSyncAction, PipelineSyncPlan,
    };

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct QueryRow {
        id: u64,
    }

    #[test]
    fn rebuilds_compiled_effective_grant_from_identity_and_action_rows() {
        let grant = compiled_effective_grant_from_rows(
            EffectiveGrantIdentityRow {
                grant_kind: "assumed".to_owned(),
                subject_id: "doctor-1".to_owned(),
                source_tenant_id: "tenant-a".to_owned(),
                source_tenant_state: "active".to_owned(),
                target_tenant_id: "tenant-b".to_owned(),
                target_tenant_state: "active".to_owned(),
                facts_json: r#"{"department":"general"}"#.to_owned(),
                ttl_seconds: Some(900),
            },
            vec![
                EffectiveGrantActionRow {
                    scope_kind: String::new(),
                    scope_id: String::new(),
                    bit_index: 0,
                },
                EffectiveGrantActionRow {
                    scope_kind: "clinic".to_owned(),
                    scope_id: "west".to_owned(),
                    bit_index: 3,
                },
            ],
        )
        .expect("grant rows should rebuild");

        assert_eq!(grant.grant_kind, "assumed");
        assert_eq!(grant.source_tenant.as_deref(), Some("tenant-a"));
        assert_eq!(grant.tenant_bits_hex, "1");
        assert_eq!(grant.scoped_entries.len(), 1);
        assert_eq!(grant.scoped_entries[0].kind, "clinic");
        assert_eq!(grant.scoped_entries[0].id.as_deref(), Some("west"));
        assert_eq!(grant.scoped_entries[0].bits_hex, "8");
        assert_eq!(grant.ttl_seconds, Some(900));
    }

    #[test]
    fn preserves_zero_bit_grants_when_no_action_rows_exist() {
        let grant = compiled_effective_grant_from_rows(
            EffectiveGrantIdentityRow {
                grant_kind: "direct".to_owned(),
                subject_id: "doctor-1".to_owned(),
                source_tenant_id: String::new(),
                source_tenant_state: String::new(),
                target_tenant_id: "tenant-a".to_owned(),
                target_tenant_state: "active".to_owned(),
                facts_json: "{}".to_owned(),
                ttl_seconds: None,
            },
            Vec::new(),
        )
        .expect("grant rows should rebuild");

        assert_eq!(grant.grant_kind, "direct");
        assert_eq!(grant.source_tenant, None);
        assert_eq!(grant.tenant_bits_hex, "0");
        assert!(grant.scoped_entries.is_empty());
    }

    #[test]
    fn reads_pipeline_summary_from_known_fields() {
        let summary = PipelineSummary::from_value(&json!({
            "name": "conclave-authz",
            "program_status": "SqlCompiled",
            "deployment_status": "Stopped"
        }));

        assert_eq!(summary.name, "conclave-authz");
        assert_eq!(summary.program_status.as_deref(), Some("SqlCompiled"));
        assert_eq!(summary.deployment_status.as_deref(), Some("Stopped"));
    }

    #[test]
    fn plans_create_when_pipeline_is_missing() {
        let desired = DesiredPipeline {
            name: "conclave_authz".to_owned(),
            description: "generated".to_owned(),
            program_code: "CREATE TABLE t();".to_owned(),
            program_config: Some(PipelineProgramConfig {
                profile: Some("dev".to_owned()),
            }),
            runtime_config: None,
        };

        let plan = PipelineSyncPlan::for_desired(desired, None);

        assert_eq!(plan.action, PipelineSyncAction::Create);
        assert_eq!(plan.changed_fields, vec!["pipeline"]);
    }

    #[test]
    fn plans_noop_when_pipeline_matches() {
        let desired = DesiredPipeline {
            name: "conclave_authz".to_owned(),
            description: "generated".to_owned(),
            program_code: "CREATE TABLE t();".to_owned(),
            program_config: Some(PipelineProgramConfig {
                profile: Some("dev".to_owned()),
            }),
            runtime_config: None,
        };
        let current = PipelineRecord {
            name: "conclave_authz".to_owned(),
            description: Some("generated".to_owned()),
            program_code: Some("CREATE TABLE t();".to_owned()),
            program_status: Some("Success".to_owned()),
            deployment_status: Some("Stopped".to_owned()),
            deployment_resources_status: Some("Stopped".to_owned()),
            deployment_runtime_status: None,
            program_config: Some(PipelineProgramConfig {
                profile: Some("dev".to_owned()),
            }),
        };

        let changed = changed_fields(&current, &desired);
        let plan = PipelineSyncPlan::for_desired(desired, Some(current));

        assert!(changed.is_empty());
        assert_eq!(plan.action, PipelineSyncAction::Noop);
    }

    #[test]
    fn blocks_updates_while_pipeline_is_running() {
        let desired = DesiredPipeline {
            name: "conclave_authz".to_owned(),
            description: "generated".to_owned(),
            program_code: "CREATE TABLE next();".to_owned(),
            program_config: Some(PipelineProgramConfig {
                profile: Some("dev".to_owned()),
            }),
            runtime_config: None,
        };
        let current = PipelineRecord {
            name: "conclave_authz".to_owned(),
            description: Some("old".to_owned()),
            program_code: Some("CREATE TABLE old();".to_owned()),
            program_status: Some("Success".to_owned()),
            deployment_status: Some("Running".to_owned()),
            deployment_resources_status: Some("Provisioned".to_owned()),
            deployment_runtime_status: Some("Running".to_owned()),
            program_config: Some(PipelineProgramConfig {
                profile: Some("optimized".to_owned()),
            }),
        };

        let plan = PipelineSyncPlan::for_desired(desired, Some(current));

        assert_eq!(plan.action, PipelineSyncAction::BlockedRunningUpdate);
        assert!(plan.changed_fields.contains(&"program_code".to_owned()));
    }

    #[test]
    fn builds_desired_pipeline_from_authz_model() {
        let authz = compile_managed_authz(
            &ManagedConfig::load_from_str(
                r#"
catalog {
    actions (
        {name "tenant:user:read"}
    )
}
templates ()
roles ()
"#,
            )
            .expect("managed config should parse"),
        )
        .expect("bundle should compile");
        let tenants = compile_managed_tenants(
            &ManagedConfig::load_from_str(
                r#"
catalog {
    actions (
        {name "tenant:user:read"}
    )
}
"#,
            )
            .expect("managed config should parse"),
            &authz,
        )
        .expect("tenant bundle should compile");
        let config = FelderaConfig {
            enabled: true,
            base_url: "http://127.0.0.1:8080".to_owned(),
            pipeline_prefix: "sandbox".to_owned(),
            readiness_probe: true,
            api_key: None,
            compile_profile: "optimized".to_owned(),
            auto_start: false,
            start_initial: "paused".to_owned(),
        };

        let desired = DesiredPipeline::from_snapshot(&config, &authz, &tenants);

        assert_eq!(desired.name, "sandbox_authz");
        assert!(desired.program_code.contains("action_catalog"));
        assert!(desired.program_code.contains("effective_grants"));
        assert_eq!(
            desired.program_config.and_then(|config| config.profile),
            Some("optimized".to_owned())
        );
    }

    #[test]
    fn parses_json_query_arrays() {
        let rows: Vec<QueryRow> =
            parse_json_rows(r#"[{"id":1},{"id":2}]"#).expect("rows should parse");

        assert_eq!(rows, vec![QueryRow { id: 1 }, QueryRow { id: 2 }]);
    }

    #[test]
    fn parses_ndjson_query_rows() {
        let rows: Vec<QueryRow> =
            parse_json_rows("{\"id\":1}\n{\"id\":2}\n").expect("rows should parse");

        assert_eq!(rows, vec![QueryRow { id: 1 }, QueryRow { id: 2 }]);
    }

    #[test]
    fn deserializes_pipeline_stats_with_transaction_fields() {
        let stats: PipelineStats = serde_json::from_value(json!({
            "global_metrics": {
                "transaction_status": "CommitInProgress",
                "transaction_id": 7,
                "bootstrap_in_progress": true
            }
        }))
        .expect("stats should deserialize");

        assert_eq!(
            stats.global_metrics,
            PipelineGlobalMetrics {
                transaction_status: Some("CommitInProgress".to_owned()),
                transaction_id: Some(7),
                bootstrap_in_progress: Some(true),
            }
        );
    }

    #[actix_web::test]
    async fn starts_commits_and_recovers_transactional_pipeline_primitives() {
        use actix_web::{get, post, web, App, HttpRequest, HttpResponse, Responder};

        #[derive(Default)]
        struct Seen {
            stop_forces: Vec<bool>,
            starts: usize,
            commits: usize,
        }

        #[post("/v0/pipelines/{name}/start_transaction")]
        async fn start_transaction(seen: web::Data<Arc<Mutex<Seen>>>) -> impl Responder {
            seen.lock().expect("seen lock").starts += 1;
            HttpResponse::Ok().json(json!({ "transaction_id": 42 }))
        }

        #[post("/v0/pipelines/{name}/commit_transaction")]
        async fn commit_transaction(seen: web::Data<Arc<Mutex<Seen>>>) -> impl Responder {
            seen.lock().expect("seen lock").commits += 1;
            HttpResponse::Ok().body("Transaction commit initiated")
        }

        #[post("/v0/pipelines/{name}/stop")]
        async fn stop_pipeline(
            request: HttpRequest,
            seen: web::Data<Arc<Mutex<Seen>>>,
        ) -> impl Responder {
            let force = request.query_string().contains("force=true");
            seen.lock().expect("seen lock").stop_forces.push(force);
            HttpResponse::Accepted().finish()
        }

        #[get("/v0/pipelines/{name}/stats")]
        async fn get_stats(calls: web::Data<Arc<AtomicUsize>>) -> impl Responder {
            let call = calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                HttpResponse::Ok().json(json!({
                    "global_metrics": {
                        "transaction_status": "CommitInProgress",
                        "transaction_id": 42
                    }
                }))
            } else {
                HttpResponse::Ok().json(json!({
                    "global_metrics": {
                        "transaction_status": "NoTransaction",
                        "transaction_id": 0
                    }
                }))
            }
        }

        let seen = Arc::new(Mutex::new(Seen::default()));
        let stats_calls = Arc::new(AtomicUsize::new(0));
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let addr = listener
            .local_addr()
            .expect("listener should expose address");
        let server_seen = seen.clone();
        let server_calls = stats_calls.clone();
        let server = actix_web::HttpServer::new(move || {
            App::new()
                .app_data(web::Data::new(server_seen.clone()))
                .app_data(web::Data::new(server_calls.clone()))
                .service(start_transaction)
                .service(commit_transaction)
                .service(stop_pipeline)
                .service(get_stats)
        })
        .listen(listener)
        .expect("server should listen")
        .run();
        let handle = server.handle();
        actix_web::rt::spawn(server);

        let client = FelderaClient::new(format!("http://{}", addr), None);
        let started = client
            .start_transaction("conclave_controlplane")
            .await
            .expect("start transaction should succeed");
        client
            .commit_transaction("conclave_controlplane")
            .await
            .expect("commit transaction should succeed");
        client
            .wait_for_no_transaction("conclave_controlplane")
            .await
            .expect("transaction wait should succeed");
        client
            .stop_pipeline("conclave_controlplane", false)
            .await
            .expect("checkpoint-preserving stop should succeed");

        handle.stop(true).await;

        assert_eq!(started.transaction_id, 42);
        assert_eq!(stats_calls.load(Ordering::SeqCst), 2);
        let seen = seen.lock().expect("seen lock");
        assert_eq!(seen.starts, 1);
        assert_eq!(seen.commits, 1);
        assert_eq!(seen.stop_forces, vec![false]);
    }

    #[actix_web::test]
    async fn starts_and_waits_for_checkpoints() {
        use actix_web::{get, post, web, App, HttpResponse, Responder};

        #[derive(Default)]
        struct Seen {
            checkpoints: usize,
            status_calls: usize,
        }

        #[post("/v0/pipelines/{name}/checkpoint")]
        async fn start_checkpoint(seen: web::Data<Arc<Mutex<Seen>>>) -> impl Responder {
            seen.lock().expect("seen lock").checkpoints += 1;
            HttpResponse::Ok().json(json!({ "checkpoint_sequence_number": 12 }))
        }

        #[get("/v0/pipelines/{name}/checkpoint_status")]
        async fn checkpoint_status(seen: web::Data<Arc<Mutex<Seen>>>) -> impl Responder {
            let mut seen = seen.lock().expect("seen lock");
            seen.status_calls += 1;
            if seen.status_calls == 1 {
                HttpResponse::Ok().json(json!({ "success": 11 }))
            } else {
                HttpResponse::Ok().json(json!({ "success": 12 }))
            }
        }

        let seen = Arc::new(Mutex::new(Seen::default()));
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let addr = listener
            .local_addr()
            .expect("listener should expose address");
        let server_seen = seen.clone();
        let server = actix_web::HttpServer::new(move || {
            App::new()
                .app_data(web::Data::new(server_seen.clone()))
                .service(start_checkpoint)
                .service(checkpoint_status)
        })
        .listen(listener)
        .expect("server should listen")
        .run();
        let handle = server.handle();
        actix_web::rt::spawn(server);

        let client = FelderaClient::new(format!("http://{}", addr), None);
        let started_checkpoint = client
            .checkpoint_now("conclave_controlplane")
            .await
            .expect("checkpoint should start");
        let status = client
            .get_checkpoint_status("conclave_controlplane")
            .await
            .expect("checkpoint status should load");
        client
            .wait_for_checkpoint(
                "conclave_controlplane",
                started_checkpoint.checkpoint_sequence_number,
            )
            .await
            .expect("checkpoint wait should succeed");

        handle.stop(true).await;

        assert_eq!(started_checkpoint.checkpoint_sequence_number, 12);
        assert_eq!(
            status,
            CheckpointStatus {
                success: Some(11),
                failure: None,
            }
        );
        let seen = seen.lock().expect("seen lock");
        assert_eq!(seen.checkpoints, 1);
        assert_eq!(seen.status_calls, 2);
    }
}
