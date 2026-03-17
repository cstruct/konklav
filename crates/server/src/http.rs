use std::sync::Arc;

use actix_web::{get, post, web, HttpResponse, Responder};
use conclave_managed_config::{
    ActionCatalogConfig, AssumptionGrantConfig, ManagedConfig, MembershipConfig, RoleConfig,
    SubjectConfig, TemplateConfig, TenantConfig,
};
use facet::Facet;
use serde::{Deserialize, Serialize};

use crate::authz::CompiledAuthzModel;
use crate::config::{AppConfig, LoadedConfig};
use crate::control_plane::{built_in_capabilities, BuiltInControlPlaneCapability};
use crate::feldera::{
    fetch_authz_pipeline_plan, sync_authz_pipeline, DesiredPipeline, FelderaClient,
    PipelineSummary, PipelineSyncPlan, StartPipelineRequest,
};
use crate::tenants::{
    AssumeAccessTokenRequest, CompiledTenantModel, DirectAccessTokenRequest,
    ValidateAccessTokenRequest,
};

#[derive(Clone)]
pub struct AppState {
    config: Arc<AppConfig>,
    config_source: Arc<String>,
    managed: Arc<ManagedConfig>,
    managed_source: Arc<String>,
    authz: Arc<CompiledAuthzModel>,
    tenants: Arc<CompiledTenantModel>,
    feldera: Option<FelderaClient>,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[derive(Serialize)]
struct ReadyResponse {
    status: &'static str,
    feldera_enabled: bool,
    feldera_reachable: bool,
    pipeline_count: Option<usize>,
}

#[derive(Serialize)]
struct MetaResponse {
    service: &'static str,
    bind_address: String,
    config_source: String,
    authz_source: String,
    tenants_source: String,
    feldera_enabled: bool,
    feldera_base_url: Option<String>,
    feldera_pipeline_prefix: Option<String>,
    authz_catalog_revision: u32,
    authz_template_count: usize,
    authz_role_count: usize,
    tenant_count: usize,
    policy_revision: u64,
    desired_feldera_pipeline: String,
}

#[derive(Serialize)]
struct PipelinesResponse {
    pipelines: Vec<PipelineSummary>,
}

#[derive(Serialize)]
struct PipelinePlanResponse {
    desired: DesiredPipeline,
    plan: Option<PipelineSyncPlan>,
}

#[derive(Deserialize)]
struct SyncQuery {
    start: Option<bool>,
}

#[derive(Serialize)]
struct CatalogResponse {
    revision: u32,
    actions: Vec<crate::authz::CompiledAction>,
}

#[derive(Serialize)]
struct TemplatesResponse {
    templates: Vec<crate::authz::CompiledTemplate>,
}

#[derive(Serialize)]
struct RolesResponse {
    roles: Vec<crate::authz::CompiledRole>,
}

#[derive(Serialize)]
struct ControlPlaneCapabilitiesResponse {
    capabilities: Vec<BuiltInControlPlaneCapability>,
}

#[derive(Clone, Debug, Facet, Serialize)]
struct ManagedAuthzView {
    catalog: ActionCatalogConfig,
    #[facet(default)]
    templates: Vec<TemplateConfig>,
    #[facet(default)]
    roles: Vec<RoleConfig>,
}

impl From<&ManagedConfig> for ManagedAuthzView {
    fn from(value: &ManagedConfig) -> Self {
        Self {
            catalog: value.catalog.clone(),
            templates: value.templates.clone(),
            roles: value.roles.clone(),
        }
    }
}

#[derive(Serialize)]
struct ManagedAuthzResponse {
    managed: ManagedAuthzView,
}

#[derive(Clone, Debug, Facet, Serialize)]
struct ManagedTenantsView {
    #[facet(default)]
    tenants: Vec<TenantConfig>,
    #[facet(default)]
    subjects: Vec<SubjectConfig>,
    #[facet(default)]
    memberships: Vec<MembershipConfig>,
    #[facet(default)]
    assumption_grants: Vec<AssumptionGrantConfig>,
}

impl From<&ManagedConfig> for ManagedTenantsView {
    fn from(value: &ManagedConfig) -> Self {
        Self {
            tenants: value.tenants.clone(),
            subjects: value.subjects.clone(),
            memberships: value.memberships.clone(),
            assumption_grants: value.assumption_grants.clone(),
        }
    }
}

#[derive(Serialize)]
struct ManagedTenantsResponse {
    managed: ManagedTenantsView,
}

#[derive(Serialize)]
struct TenantsResponse {
    tenants: Vec<crate::tenants::CompiledTenant>,
}

#[derive(Serialize)]
struct MembershipsResponse {
    memberships: Vec<crate::tenants::CompiledMembership>,
}

#[derive(Serialize)]
struct AssumptionGrantsResponse {
    assumption_grants: Vec<crate::tenants::CompiledAssumptionGrant>,
}

impl AppState {
    pub fn from_loaded_config(
        loaded: LoadedConfig,
        managed: conclave_managed_config::LoadedManagedConfig,
        authz: CompiledAuthzModel,
        tenants: CompiledTenantModel,
    ) -> Self {
        let feldera = loaded.config.feldera.enabled.then(|| {
            FelderaClient::new(
                loaded.config.feldera.base_url.clone(),
                loaded.config.feldera.api_key.clone(),
            )
        });

        Self {
            config: Arc::new(loaded.config),
            config_source: Arc::new(loaded.source),
            managed: Arc::new(managed.managed),
            managed_source: Arc::new(managed.source),
            authz: Arc::new(authz),
            tenants: Arc::new(tenants),
            feldera,
        }
    }

    pub fn bind_address(&self) -> String {
        self.config.server.bind_address()
    }
}

// r[impl platform.server.bootstrap]
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(healthz)
        .service(readyz)
        .service(meta)
        .service(config_schema)
        .service(tenant_schema)
        .service(authz_catalog)
        .service(authz_managed)
        .service(authz_templates)
        .service(authz_roles)
        .service(control_plane_capabilities)
        .service(tenants_managed)
        .service(tenants_list)
        .service(tenant_memberships)
        .service(tenant_assumption_grants)
        .service(issue_direct_access_token)
        .service(issue_assumed_access_token)
        .service(validate_access_token)
        .service(authz_schema)
        .service(authz_feldera_sql)
        .service(authz_feldera_pipeline_plan)
        .service(authz_feldera_pipeline_status)
        .service(authz_feldera_pipeline_sync)
        .service(authz_feldera_pipeline_start)
        .service(list_pipelines);
}

#[get("/healthz")]
async fn healthz() -> impl Responder {
    HttpResponse::Ok().json(HealthResponse { status: "ok" })
}

#[get("/readyz")]
async fn readyz(state: web::Data<AppState>) -> impl Responder {
    let feldera_enabled = state.config.feldera.enabled;

    if !feldera_enabled || !state.config.feldera.readiness_probe {
        return HttpResponse::Ok().json(ReadyResponse {
            status: "ready",
            feldera_enabled,
            feldera_reachable: false,
            pipeline_count: None,
        });
    }

    match &state.feldera {
        Some(client) => match client.list_pipelines().await {
            Ok(pipelines) => HttpResponse::Ok().json(ReadyResponse {
                status: "ready",
                feldera_enabled,
                feldera_reachable: true,
                pipeline_count: Some(pipelines.len()),
            }),
            Err(err) => HttpResponse::ServiceUnavailable().json(serde_json::json!({
                "status": "not-ready",
                "feldera_enabled": feldera_enabled,
                "feldera_reachable": false,
                "error": err.to_string(),
            })),
        },
        None => HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "status": "not-ready",
            "feldera_enabled": feldera_enabled,
            "feldera_reachable": false,
            "error": "feldera client not initialized",
        })),
    }
}

#[get("/v1/meta")]
async fn meta(state: web::Data<AppState>) -> impl Responder {
    let feldera_enabled = state.config.feldera.enabled;
    let feldera_base_url = feldera_enabled.then(|| state.config.feldera.base_url.clone());
    let feldera_pipeline_prefix =
        feldera_enabled.then(|| state.config.feldera.pipeline_prefix.clone());

    HttpResponse::Ok().json(MetaResponse {
        service: "conclave-server",
        bind_address: state.bind_address(),
        config_source: (*state.config_source).clone(),
        authz_source: (*state.managed_source).clone(),
        tenants_source: (*state.managed_source).clone(),
        feldera_enabled,
        feldera_base_url,
        feldera_pipeline_prefix,
        authz_catalog_revision: state.authz.catalog_revision,
        authz_template_count: state.authz.templates.len(),
        authz_role_count: state.authz.roles.len(),
        tenant_count: state.tenants.tenants.len(),
        policy_revision: state.tenants.policy_revision,
        desired_feldera_pipeline: format!("{}_authz", state.config.feldera.pipeline_prefix),
    })
}

#[get("/v1/meta/config-schema")]
async fn config_schema() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/plain; charset=utf-8")
        .body(AppConfig::schema())
}

#[get("/v1/meta/tenant-schema")]
async fn tenant_schema() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/plain; charset=utf-8")
        .body(facet_styx::schema_from_type::<ManagedTenantsView>())
}

#[get("/v1/meta/authz-schema")]
async fn authz_schema() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/plain; charset=utf-8")
        .body(facet_styx::schema_from_type::<ManagedAuthzView>())
}

#[get("/v1/authz/catalog")]
async fn authz_catalog(state: web::Data<AppState>) -> impl Responder {
    HttpResponse::Ok().json(CatalogResponse {
        revision: state.authz.catalog_revision,
        actions: state.authz.actions.clone(),
    })
}

#[get("/v1/authz/managed")]
async fn authz_managed(state: web::Data<AppState>) -> impl Responder {
    HttpResponse::Ok().json(ManagedAuthzResponse {
        managed: ManagedAuthzView::from(state.managed.as_ref()),
    })
}

#[get("/v1/tenants/managed")]
async fn tenants_managed(state: web::Data<AppState>) -> impl Responder {
    HttpResponse::Ok().json(ManagedTenantsResponse {
        managed: ManagedTenantsView::from(state.managed.as_ref()),
    })
}

#[get("/v1/tenants")]
async fn tenants_list(state: web::Data<AppState>) -> impl Responder {
    HttpResponse::Ok().json(TenantsResponse {
        tenants: state.tenants.tenants.clone(),
    })
}

#[get("/v1/tenants/memberships")]
async fn tenant_memberships(state: web::Data<AppState>) -> impl Responder {
    HttpResponse::Ok().json(MembershipsResponse {
        memberships: state.tenants.memberships.clone(),
    })
}

#[get("/v1/tenants/assumptions")]
async fn tenant_assumption_grants(state: web::Data<AppState>) -> impl Responder {
    HttpResponse::Ok().json(AssumptionGrantsResponse {
        assumption_grants: state.tenants.assumption_grants.clone(),
    })
}

#[get("/v1/authz/templates")]
async fn authz_templates(state: web::Data<AppState>) -> impl Responder {
    HttpResponse::Ok().json(TemplatesResponse {
        templates: state.authz.templates.clone(),
    })
}

#[get("/v1/authz/roles")]
async fn authz_roles(state: web::Data<AppState>) -> impl Responder {
    HttpResponse::Ok().json(RolesResponse {
        roles: state.authz.roles.clone(),
    })
}

#[get("/v1/conclave/capabilities")]
async fn control_plane_capabilities() -> impl Responder {
    HttpResponse::Ok().json(ControlPlaneCapabilitiesResponse {
        capabilities: built_in_capabilities().to_vec(),
    })
}

#[post("/v1/auth/tokens/direct")]
async fn issue_direct_access_token(
    state: web::Data<AppState>,
    request: web::Json<DirectAccessTokenRequest>,
) -> impl Responder {
    match state
        .tenants
        .issue_direct_token(&state.authz, &state.config.jwt, &request.0)
    {
        Ok(token) => HttpResponse::Ok().json(token),
        Err(err) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": err.to_string(),
        })),
    }
}

#[post("/v1/auth/tokens/assume")]
async fn issue_assumed_access_token(
    state: web::Data<AppState>,
    request: web::Json<AssumeAccessTokenRequest>,
) -> impl Responder {
    match state
        .tenants
        .issue_assumed_token(&state.authz, &state.config.jwt, &request.0)
    {
        Ok(token) => HttpResponse::Ok().json(token),
        Err(err) => HttpResponse::Forbidden().json(serde_json::json!({
            "error": err.to_string(),
        })),
    }
}

#[post("/v1/auth/tokens/validate")]
async fn validate_access_token(
    state: web::Data<AppState>,
    request: web::Json<ValidateAccessTokenRequest>,
) -> impl Responder {
    match state
        .tenants
        .validate_access_token(&state.authz, &state.config.jwt, &request.0)
    {
        Ok(response) if response.valid => HttpResponse::Ok().json(response),
        Ok(response) => HttpResponse::Unauthorized().json(response),
        Err(err) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": err.to_string(),
        })),
    }
}

#[get("/v1/feldera/sql/authz")]
async fn authz_feldera_sql(state: web::Data<AppState>) -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/sql; charset=utf-8")
        .body(
            state
                .authz
                .feldera_sql(&state.config.feldera.pipeline_prefix),
        )
}

#[get("/v1/feldera/authz/plan")]
async fn authz_feldera_pipeline_plan(state: web::Data<AppState>) -> impl Responder {
    let desired = DesiredPipeline::from_authz(&state.config.feldera, &state.authz);

    match &state.feldera {
        Some(client) => {
            match fetch_authz_pipeline_plan(client, &state.config.feldera, &state.authz).await {
                Ok(plan) => HttpResponse::Ok().json(PipelinePlanResponse {
                    desired,
                    plan: Some(plan),
                }),
                Err(err) => HttpResponse::BadGateway().json(serde_json::json!({
                    "error": err.to_string(),
                    "desired": desired,
                })),
            }
        }
        None => HttpResponse::Ok().json(PipelinePlanResponse {
            desired,
            plan: None,
        }),
    }
}

#[get("/v1/feldera/authz/status")]
async fn authz_feldera_pipeline_status(state: web::Data<AppState>) -> impl Responder {
    let pipeline_name = format!("{}_authz", state.config.feldera.pipeline_prefix);

    match &state.feldera {
        Some(client) => match client.get_pipeline(&pipeline_name, "all").await {
            Ok(Some(pipeline)) => HttpResponse::Ok().json(pipeline),
            Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
                "error": format!("pipeline {pipeline_name} does not exist"),
            })),
            Err(err) => HttpResponse::BadGateway().json(serde_json::json!({
                "error": err.to_string(),
            })),
        },
        None => HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "error": "feldera integration is disabled",
        })),
    }
}

#[post("/v1/feldera/authz/sync")]
async fn authz_feldera_pipeline_sync(
    state: web::Data<AppState>,
    query: web::Query<SyncQuery>,
) -> impl Responder {
    match &state.feldera {
        Some(client) => {
            let start = if query.start.unwrap_or(state.config.feldera.auto_start) {
                Some(StartPipelineRequest {
                    initial: state.config.feldera.start_initial.clone(),
                    bootstrap_policy: None,
                })
            } else {
                None
            };

            match sync_authz_pipeline(client, &state.config.feldera, &state.authz, start).await {
                Ok(result) => HttpResponse::Ok().json(result),
                Err(err) => HttpResponse::Conflict().json(serde_json::json!({
                    "error": err.to_string(),
                })),
            }
        }
        None => HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "error": "feldera integration is disabled",
        })),
    }
}

#[post("/v1/feldera/authz/start")]
async fn authz_feldera_pipeline_start(state: web::Data<AppState>) -> impl Responder {
    let pipeline_name = format!("{}_authz", state.config.feldera.pipeline_prefix);

    match &state.feldera {
        Some(client) => match client
            .start_pipeline(
                &pipeline_name,
                &StartPipelineRequest {
                    initial: state.config.feldera.start_initial.clone(),
                    bootstrap_policy: None,
                },
            )
            .await
        {
            Ok(()) => HttpResponse::Accepted().json(serde_json::json!({
                "pipeline_name": pipeline_name,
                "status": "start-requested",
                "initial": state.config.feldera.start_initial,
            })),
            Err(err) => HttpResponse::BadGateway().json(serde_json::json!({
                "error": err.to_string(),
            })),
        },
        None => HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "error": "feldera integration is disabled",
        })),
    }
}

#[get("/v1/feldera/pipelines")]
async fn list_pipelines(state: web::Data<AppState>) -> impl Responder {
    match &state.feldera {
        Some(client) => match client.list_pipelines().await {
            Ok(pipelines) => HttpResponse::Ok().json(PipelinesResponse { pipelines }),
            Err(err) => HttpResponse::BadGateway().json(serde_json::json!({
                "error": err.to_string(),
            })),
        },
        None => HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "error": "feldera integration is disabled",
        })),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use actix_web::{http::StatusCode, test, App};
    use conclave_managed_config::{LoadedManagedConfig, ManagedConfig};
    use serde_json::json;

    use crate::authz::compile_managed_authz;
    use crate::config::{AppConfig, LoadedConfig};
    use crate::tenants::compile_managed_tenants;

    use super::{configure, AppState};

    fn test_state() -> AppState {
        let managed = ManagedConfig::load_from_str(
            r#"
catalog {
    actions (
        {name "tenant:user:read"}
        {name "tenant:clinic:read"}
    )
}
templates (
    {
        tenant "tenant-a",
        key "doctor",
        policies (
            {effect allow, action "tenant:user:read"}
            {effect allow, action "tenant:clinic:read", scope_kind "clinic"}
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
tenants (
    {id "tenant-a"}
)
subjects (
    {id "operator-1"}
    {id "doctor-1"}
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
        )
        .expect("managed config should parse");
        let authz = compile_managed_authz(&managed).expect("authz config should compile");
        let tenants =
            compile_managed_tenants(&managed, &authz).expect("tenant config should compile");

        AppState::from_loaded_config(
            LoadedConfig {
                config: AppConfig::default(),
                managed_dir: PathBuf::from("config"),
                source: "test".to_owned(),
            },
            LoadedManagedConfig {
                managed,
                source: "test-managed".to_owned(),
            },
            authz,
            tenants,
        )
    }

    // r[verify platform.server.bootstrap]
    #[actix_web::test]
    async fn health_endpoint_is_available() {
        let state = test_state();
        let app = test::init_service(
            App::new()
                .app_data(actix_web::web::Data::new(state))
                .configure(configure),
        )
        .await;

        let response =
            test::call_service(&app, test::TestRequest::get().uri("/healthz").to_request()).await;

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn authz_catalog_endpoint_returns_compiled_catalog() {
        let state = test_state();
        let app = test::init_service(
            App::new()
                .app_data(actix_web::web::Data::new(state))
                .configure(configure),
        )
        .await;

        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/v1/authz/catalog")
                .to_request(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn authz_plan_endpoint_returns_local_desired_pipeline_when_feldera_disabled() {
        let state = test_state();
        let app = test::init_service(
            App::new()
                .app_data(actix_web::web::Data::new(state))
                .configure(configure),
        )
        .await;

        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/v1/feldera/authz/plan")
                .to_request(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn tenants_endpoint_returns_bootstrap_tree() {
        let state = test_state();
        let app = test::init_service(
            App::new()
                .app_data(actix_web::web::Data::new(state))
                .configure(configure),
        )
        .await;

        let response = test::call_service(
            &app,
            test::TestRequest::get().uri("/v1/tenants").to_request(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn control_plane_capabilities_endpoint_is_available() {
        let state = test_state();
        let app = test::init_service(
            App::new()
                .app_data(actix_web::web::Data::new(state))
                .configure(configure),
        )
        .await;

        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/v1/conclave/capabilities")
                .to_request(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
    }

    // r[verify token.access.context.target-tenant]
    #[actix_web::test]
    async fn direct_token_endpoint_issues_access_token() {
        let state = test_state();
        let app = test::init_service(
            App::new()
                .app_data(actix_web::web::Data::new(state))
                .configure(configure),
        )
        .await;

        let response = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/v1/auth/tokens/direct")
                .set_json(json!({
                    "subject": "doctor-1",
                    "tenant": "tenant-a",
                    "audience": "clinic-api"
                }))
                .to_request(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
    }

    // r[verify authn.session.explicit-assumption]
    // r[verify token.access.use.offline-evaluation]
    #[actix_web::test]
    async fn assume_and_validate_token_endpoints_work_together() {
        let state = test_state();
        let app = test::init_service(
            App::new()
                .app_data(actix_web::web::Data::new(state))
                .configure(configure),
        )
        .await;

        let assume_response: crate::tenants::AccessTokenResponse = test::call_and_read_body_json(
            &app,
            test::TestRequest::post()
                .uri("/v1/auth/tokens/assume")
                .set_json(json!({
                    "subject": "operator-1",
                    "source_tenant": "root",
                    "target_tenant": "tenant-a",
                    "audience": "clinic-api"
                }))
                .to_request(),
        )
        .await;

        let validation_response = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/v1/auth/tokens/validate")
                .set_json(json!({
                    "token": assume_response.token,
                    "expected_tenant": "tenant-a",
                    "audience": "clinic-api",
                    "action": "tenant:clinic:read",
                    "scope_kind": "clinic",
                    "scope_id": "clinic-1"
                }))
                .to_request(),
        )
        .await;

        assert_eq!(validation_response.status(), StatusCode::OK);
    }
}
