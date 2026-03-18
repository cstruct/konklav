use std::sync::{Arc, RwLock};

use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use conclave_controlplane_api::{
    ActionCatalogResponse, CurrentRevisionsResponse, InviteCreateRequest, InviteCreateResponse,
    LoginRequest, LoginResponse, ManagedApplyRequest, ManagedApplyResponse, ManagedPlanRequest,
    ManagedValidateRequest, ManagedValidateResponse, RedeemInviteRequest, RedeemInviteResponse,
};
use conclave_relying_auth::{ActionCatalogEntry, JwkSet, JwtSigner, JwtVerifier};
use serde::Serialize;

use crate::authz::CompiledAuthzModel;
use crate::config::{AppConfig, LoadedConfig};
use crate::feldera::{sync_authz_pipeline, FelderaClient, StartPipelineRequest};
use crate::managed_store::FelderaManagedStore;
use crate::state::ControlPlaneState;
use crate::tenants::{AssumeAccessTokenRequest, CompiledTenantModel, ValidateAccessTokenRequest};

#[derive(Clone)]
pub struct AppState {
    config: Arc<AppConfig>,
    config_source: Arc<String>,
    managed_source: Arc<String>,
    state: Arc<RwLock<ControlPlaneState>>,
    signer: Arc<JwtSigner>,
    verifier: Arc<JwtVerifier>,
    feldera: Option<FelderaClient>,
    managed_store: Option<Arc<FelderaManagedStore>>,
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
}

#[derive(Serialize)]
struct MetaResponse {
    config_source: String,
    managed_source: String,
    control_plane_bind: String,
    subject_bind: String,
    relying_bind: String,
    bootstrap_subject: String,
    last_apply_id: String,
}

impl AppState {
    // r[impl config.managed.feldera-authoritative-store]
    pub async fn from_loaded_config(
        loaded: LoadedConfig,
        managed: conclave_managed_config::LoadedManagedConfig,
        signer: JwtSigner,
        verifier: JwtVerifier,
    ) -> Result<Self, crate::types::DynError> {
        let feldera = loaded.config.feldera.enabled.then(|| {
            FelderaClient::new(
                loaded.config.feldera.base_url.clone(),
                loaded.config.feldera.api_key.clone(),
            )
        });
        let managed_store = feldera.clone().map(|client| {
            Arc::new(FelderaManagedStore::new(
                client,
                loaded.config.feldera.clone(),
            ))
        });
        let (state, managed_source) = if let Some(store) = &managed_store {
            store.bootstrap_if_empty(&managed.managed).await?;
            let durable_managed = store.load_managed().await?;
            let durable_apply_id = store.load_latest_apply_id().await?;
            let mut state = ControlPlaneState::new(durable_managed)?;
            if let Some(apply_id) = durable_apply_id {
                state.set_last_apply_id(apply_id);
            }
            (
                state,
                format!(
                    "feldera:{} (bootstrap seed {})",
                    loaded.config.feldera.pipeline_prefix, managed.source
                ),
            )
        } else {
            let mut state = ControlPlaneState::empty();
            state.bootstrap_from_managed_if_empty(managed.managed)?;
            (state, managed.source)
        };

        Ok(Self {
            config: Arc::new(loaded.config),
            config_source: Arc::new(loaded.source),
            managed_source: Arc::new(managed_source),
            state: Arc::new(RwLock::new(state)),
            signer: Arc::new(signer),
            verifier: Arc::new(verifier),
            feldera,
            managed_store,
        })
    }

    pub fn control_plane_bind_address(&self) -> String {
        self.config.control_plane.bind_address()
    }

    pub fn subject_bind_address(&self) -> String {
        self.config.subject.bind_address()
    }

    pub fn relying_bind_address(&self) -> String {
        self.config.relying.bind_address()
    }

    fn current_snapshot(
        &self,
    ) -> Result<(CompiledAuthzModel, CompiledTenantModel), crate::types::DynError> {
        let guard = self.state.read().expect("state lock should not poison");
        let snapshot = guard.snapshot()?;
        Ok((snapshot.authz, snapshot.tenants))
    }

    fn current_catalog(&self) -> Result<ActionCatalogResponse, crate::types::DynError> {
        let (authz, _) = self.current_snapshot()?;
        Ok(ActionCatalogResponse {
            revision: authz.catalog_revision,
            actions: authz
                .actions
                .iter()
                .map(|entry| ActionCatalogEntry {
                    name: entry.name.clone(),
                    bit: entry.bit,
                })
                .collect(),
        })
    }

    // r[impl config.managed.authz-recompile-before-issuance]
    pub async fn sync_feldera_on_startup(&self) -> Result<Option<String>, crate::types::DynError> {
        let Some(client) = &self.feldera else {
            return Ok(None);
        };

        let (authz, _) = self.current_snapshot()?;
        let start = self
            .config
            .feldera
            .auto_start
            .then(|| StartPipelineRequest {
                initial: self.config.feldera.start_initial.clone(),
                bootstrap_policy: None,
            });
        let result = sync_authz_pipeline(client, &self.config.feldera, &authz, start).await?;

        Ok(Some(result.status))
    }

    fn ensure_bootstrap_token(&self, request: &HttpRequest) -> Result<(), HttpResponse> {
        let header = request
            .headers()
            .get("Authorization")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let expected = format!("Bearer {}", self.config.bootstrap.token);

        if header == expected {
            Ok(())
        } else {
            Err(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "missing or invalid bootstrap token",
            })))
        }
    }
}

pub fn configure_control_plane(cfg: &mut web::ServiceConfig) {
    cfg.service(healthz)
        .service(readyz)
        .service(meta)
        .service(managed_validate)
        .service(managed_plan)
        .service(managed_apply)
        .service(create_invite);
}

pub fn configure_subject(cfg: &mut web::ServiceConfig) {
    cfg.service(healthz)
        .service(redeem_invite)
        .service(login)
        .service(issue_assumed_access_token)
        .service(validate_access_token);
}

pub fn configure_relying(cfg: &mut web::ServiceConfig) {
    cfg.service(healthz)
        .service(current_revisions)
        .service(action_catalog)
        .service(jwks);
}

#[get("/healthz")]
async fn healthz() -> impl Responder {
    HttpResponse::Ok().json(HealthResponse { status: "ok" })
}

#[get("/readyz")]
async fn readyz(state: web::Data<AppState>) -> impl Responder {
    let feldera_enabled = state.config.feldera.enabled;
    let feldera_reachable = match &state.feldera {
        Some(client) if state.config.feldera.readiness_probe => {
            client.list_pipelines().await.is_ok()
        }
        _ => false,
    };

    HttpResponse::Ok().json(ReadyResponse {
        status: "ready",
        feldera_enabled,
        feldera_reachable,
    })
}

#[get("/v1/meta")]
async fn meta(state: web::Data<AppState>) -> impl Responder {
    let guard = state.state.read().expect("state lock should not poison");

    HttpResponse::Ok().json(MetaResponse {
        config_source: (*state.config_source).clone(),
        managed_source: (*state.managed_source).clone(),
        control_plane_bind: state.control_plane_bind_address(),
        subject_bind: state.subject_bind_address(),
        relying_bind: state.relying_bind_address(),
        bootstrap_subject: state.config.bootstrap.subject.clone(),
        last_apply_id: guard.last_apply_id.clone(),
    })
}

#[post("/v1/managed/validate")]
async fn managed_validate(
    state: web::Data<AppState>,
    request: HttpRequest,
    body: web::Json<ManagedValidateRequest>,
) -> impl Responder {
    if let Err(response) = state.ensure_bootstrap_token(&request) {
        return response;
    }

    let issues = ControlPlaneState::validate(&body.managed);
    HttpResponse::Ok().json(ManagedValidateResponse {
        valid: issues.is_empty(),
        issues,
    })
}

#[post("/v1/managed/plan")]
async fn managed_plan(
    state: web::Data<AppState>,
    request: HttpRequest,
    body: web::Json<ManagedPlanRequest>,
) -> impl Responder {
    if let Err(response) = state.ensure_bootstrap_token(&request) {
        return response;
    }

    let guard = state.state.read().expect("state lock should not poison");
    match guard.plan(&body.managed) {
        Ok(plan) => HttpResponse::Ok().json(plan),
        Err(err) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": err.to_string(),
        })),
    }
}

#[post("/v1/managed/apply")]
async fn managed_apply(
    state: web::Data<AppState>,
    request: HttpRequest,
    body: web::Json<ManagedApplyRequest>,
) -> impl Responder {
    if let Err(response) = state.ensure_bootstrap_token(&request) {
        return response;
    }

    {
        let guard = state.state.read().expect("state lock should not poison");
        if let Err(err) = guard.plan(&body.managed) {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": err.to_string(),
            }));
        }
    }

    let durable_apply_id = match &state.managed_store {
        Some(store) => match store.apply(&body.managed).await {
            Ok(apply_id) => Some(apply_id),
            Err(err) => {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": err.to_string(),
                }))
            }
        },
        None => None,
    };

    let mut guard = state.state.write().expect("state lock should not poison");
    match guard.apply_with_id(body.managed.clone(), durable_apply_id) {
        Ok(plan) => HttpResponse::Ok().json(ManagedApplyResponse {
            applied: true,
            apply_id: guard.last_apply_id.clone(),
            summary: plan.summary,
            catalog_revision: plan.catalog_revision,
            policy_revision: plan.policy_revision,
        }),
        Err(err) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": err.to_string(),
        })),
    }
}

#[post("/v1/invites")]
async fn create_invite(
    state: web::Data<AppState>,
    request: HttpRequest,
    body: web::Json<InviteCreateRequest>,
) -> impl Responder {
    if let Err(response) = state.ensure_bootstrap_token(&request) {
        return response;
    }

    let mut guard = state.state.write().expect("state lock should not poison");
    match guard.create_invite(&body.subject, body.expires_in_seconds.unwrap_or(900)) {
        Ok((invite_id, redeem_code, expires_at)) => HttpResponse::Ok().json(InviteCreateResponse {
            invite_id,
            subject: body.subject.clone(),
            redeem_code,
            expires_at,
        }),
        Err(err) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": err.to_string(),
        })),
    }
}

#[post("/v1/invites/redeem")]
async fn redeem_invite(
    state: web::Data<AppState>,
    body: web::Json<RedeemInviteRequest>,
) -> impl Responder {
    let mut guard = state.state.write().expect("state lock should not poison");
    match guard.redeem_invite(&body.redeem_code, &body.password) {
        Ok(subject) => HttpResponse::Ok().json(RedeemInviteResponse {
            subject,
            linked: true,
        }),
        Err(err) => HttpResponse::Forbidden().json(serde_json::json!({
            "error": err.to_string(),
        })),
    }
}

#[post("/v1/login")]
async fn login(state: web::Data<AppState>, body: web::Json<LoginRequest>) -> impl Responder {
    let session_id = {
        let mut guard = state.state.write().expect("state lock should not poison");
        match guard.login(&body.subject, &body.password, &body.tenant) {
            Ok(session_id) => session_id,
            Err(err) => {
                return HttpResponse::Forbidden().json(serde_json::json!({
                    "error": err.to_string(),
                }))
            }
        }
    };

    let (authz, tenants) = match state.current_snapshot() {
        Ok(snapshot) => snapshot,
        Err(err) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": err.to_string(),
            }))
        }
    };

    match tenants.issue_direct_token(
        &authz,
        &state.config.jwt,
        &state.signer,
        &crate::tenants::DirectAccessTokenRequest {
            subject: body.subject.clone(),
            tenant: body.tenant.clone(),
            audience: body.audience.clone(),
            ttl_seconds: None,
        },
    ) {
        Ok(issued) => HttpResponse::Ok().json(LoginResponse {
            session_id,
            token: issued.token,
            claims: issued.claims,
        }),
        Err(err) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": err.to_string(),
        })),
    }
}

#[post("/v1/auth/tokens/assume")]
async fn issue_assumed_access_token(
    state: web::Data<AppState>,
    body: web::Json<AssumeAccessTokenRequest>,
) -> impl Responder {
    let (authz, tenants) = match state.current_snapshot() {
        Ok(snapshot) => snapshot,
        Err(err) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": err.to_string(),
            }))
        }
    };

    match tenants.issue_assumed_token(&authz, &state.config.jwt, &state.signer, &body.0) {
        Ok(token) => HttpResponse::Ok().json(token),
        Err(err) => HttpResponse::Forbidden().json(serde_json::json!({
            "error": err.to_string(),
        })),
    }
}

#[post("/v1/auth/tokens/validate")]
async fn validate_access_token(
    state: web::Data<AppState>,
    body: web::Json<ValidateAccessTokenRequest>,
) -> impl Responder {
    let (authz, tenants) = match state.current_snapshot() {
        Ok(snapshot) => snapshot,
        Err(err) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": err.to_string(),
            }))
        }
    };

    match tenants.validate_access_token(&authz, &state.config.jwt, &state.verifier, &body.0) {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(err) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": err.to_string(),
        })),
    }
}

#[get("/v1/revisions")]
async fn current_revisions(state: web::Data<AppState>) -> impl Responder {
    match state.current_snapshot() {
        Ok((authz, tenants)) => HttpResponse::Ok().json(CurrentRevisionsResponse {
            catalog_revision: authz.catalog_revision,
            policy_revision: tenants.policy_revision,
        }),
        Err(err) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": err.to_string(),
        })),
    }
}

#[get("/v1/authz/catalog")]
async fn action_catalog(state: web::Data<AppState>) -> impl Responder {
    match state.current_catalog() {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(err) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": err.to_string(),
        })),
    }
}

#[get("/.well-known/jwks.json")]
async fn jwks(state: web::Data<AppState>) -> impl Responder {
    HttpResponse::Ok().json(JwkSet {
        keys: vec![state.signer.jwk()],
    })
}

#[cfg(test)]
mod tests {
    use actix_web::{http::StatusCode, test, App};
    use conclave_managed_config::ManagedConfig;

    use crate::config::{AppConfig, LoadedConfig};

    use super::*;

    async fn test_state() -> AppState {
        let loaded = LoadedConfig {
            config: AppConfig::default(),
            managed_dir: std::path::PathBuf::from("config"),
            source: "test".to_owned(),
        };
        let managed = conclave_managed_config::LoadedManagedConfig {
            managed: ManagedConfig::load_from_str(
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
roles (
    {
        tenant "tenant-a",
        key "doctor"
        template "doctor"
    }
)
tenants (
    {id "root"}
    {id "tenant-a"}
)
subjects (
    {id "doctor-1", display_name "Doctor One"}
)
memberships (
    {
        subject "doctor-1"
        tenant "tenant-a"
        roles ("doctor")
    }
)
"#,
            )
            .expect("managed config should parse"),
            source: "test-managed".to_owned(),
        };
        let signer = JwtSigner::from_seed(
            loaded.config.jwt.signing_key_id.clone(),
            loaded
                .config
                .jwt
                .signing_seed_bytes()
                .expect("seed should decode"),
        );
        let verifier = signer.verifier();

        AppState::from_loaded_config(loaded, managed, signer, verifier)
            .await
            .expect("state should build")
    }

    #[actix_web::test]
    async fn control_plane_invite_and_subject_login_flow() {
        let state = test_state().await;
        let control = test::init_service(
            App::new()
                .app_data(web::Data::new(state.clone()))
                .configure(configure_control_plane),
        )
        .await;
        let subject = test::init_service(
            App::new()
                .app_data(web::Data::new(state.clone()))
                .configure(configure_subject),
        )
        .await;

        let invite_request = test::TestRequest::post()
            .uri("/v1/invites")
            .insert_header(("Authorization", "Bearer conclave-bootstrap-token"))
            .set_json(&InviteCreateRequest {
                subject: "doctor-1".to_owned(),
                expires_in_seconds: Some(300),
            })
            .to_request();
        let invite_response: InviteCreateResponse =
            test::call_and_read_body_json(&control, invite_request).await;

        let redeem_request = test::TestRequest::post()
            .uri("/v1/invites/redeem")
            .set_json(&RedeemInviteRequest {
                redeem_code: invite_response.redeem_code,
                password: "swordfish".to_owned(),
            })
            .to_request();
        let redeem_response: RedeemInviteResponse =
            test::call_and_read_body_json(&subject, redeem_request).await;
        assert_eq!(redeem_response.subject, "doctor-1");

        let login_request = test::TestRequest::post()
            .uri("/v1/login")
            .set_json(&LoginRequest {
                subject: "doctor-1".to_owned(),
                password: "swordfish".to_owned(),
                tenant: "tenant-a".to_owned(),
                audience: Some("clinic-api".to_owned()),
            })
            .to_request();
        let login_response: LoginResponse =
            test::call_and_read_body_json(&subject, login_request).await;
        assert_eq!(login_response.claims.sub, "doctor-1");
        assert_eq!(login_response.claims.tid, "tenant-a");
        assert_eq!(login_response.claims.aud, "clinic-api");
        assert_eq!(login_response.token.split('.').count(), 3);
    }

    #[actix_web::test]
    async fn relying_surface_exposes_jwks_and_catalog() {
        let state = test_state().await;
        let relying = test::init_service(
            App::new()
                .app_data(web::Data::new(state))
                .configure(configure_relying),
        )
        .await;

        let jwks_request = test::TestRequest::get()
            .uri("/.well-known/jwks.json")
            .to_request();
        let jwks_response = test::call_service(&relying, jwks_request).await;
        assert_eq!(jwks_response.status(), StatusCode::OK);
        let _: JwkSet = test::read_body_json(jwks_response).await;

        let catalog_request = test::TestRequest::get()
            .uri("/v1/authz/catalog")
            .to_request();
        let catalog_response: ActionCatalogResponse =
            test::call_and_read_body_json(&relying, catalog_request).await;
        assert_eq!(catalog_response.actions.len(), 1);
        assert_eq!(catalog_response.actions[0].name, "tenant:user:read");
    }

    #[actix_web::test]
    async fn syncs_authz_pipeline_against_a_manager_endpoint() {
        use actix_web::patch;
        use std::sync::{Arc, Mutex};
        use std::{net::TcpListener, time::Duration};

        #[derive(Default, Clone)]
        struct Seen {
            gets: usize,
            creates: usize,
        }

        #[get("/v0/pipelines/{name}")]
        async fn get_pipeline(seen: web::Data<Arc<Mutex<Seen>>>) -> impl Responder {
            seen.lock().expect("seen lock").gets += 1;
            HttpResponse::NotFound().finish()
        }

        #[post("/v0/pipelines")]
        async fn create_pipeline(
            seen: web::Data<Arc<Mutex<Seen>>>,
            body: web::Json<crate::feldera::DesiredPipeline>,
        ) -> impl Responder {
            seen.lock().expect("seen lock").creates += 1;
            HttpResponse::Ok().json(crate::feldera::PipelineRecord {
                name: body.name.clone(),
                description: Some(body.description.clone()),
                program_code: Some(body.program_code.clone()),
                program_status: Some("SqlCompiled".to_owned()),
                deployment_status: Some("Stopped".to_owned()),
                deployment_resources_status: None,
                deployment_runtime_status: None,
                program_config: body.program_config.clone(),
            })
        }

        #[patch("/v0/pipelines/{name}")]
        async fn patch_pipeline() -> impl Responder {
            HttpResponse::Ok().finish()
        }

        #[post("/v0/pipelines/{name}/start")]
        async fn start_pipeline() -> impl Responder {
            HttpResponse::Ok().finish()
        }

        #[get("/v0/pipelines/{name}/query")]
        async fn query_pipeline(request: HttpRequest) -> impl Responder {
            let sql = request
                .query_string()
                .split('&')
                .find_map(|entry| entry.strip_prefix("sql="))
                .unwrap_or_default()
                .replace('+', " ")
                .replace("%20", " ")
                .replace("%28", "(")
                .replace("%29", ")")
                .replace("%2A", "*");

            if sql.contains("COUNT(*)") {
                HttpResponse::Ok().body(r#"[{"count":0}]"#)
            } else if sql.contains("ORDER BY committed_at DESC") {
                HttpResponse::Ok().body(r#"[{"apply_id":"apply-bootstrap"}]"#)
            } else {
                HttpResponse::Ok().body(
                    r#"[
                        {
                            "resource_kind":"action",
                            "resource_key":"tenant:user:read",
                            "scope":"global",
                            "apply_id":"apply-bootstrap",
                            "row_version":1,
                            "valid_from":1,
                            "deleted":false,
                            "payload_json":"{\"name\":\"tenant:user:read\"}"
                        }
                    ]"#,
                )
            }
        }

        #[post("/v0/pipelines/{name}/ingress/{table}")]
        async fn ingress_rows() -> impl Responder {
            HttpResponse::Ok().json(serde_json::json!({ "completion_token": "done-1" }))
        }

        #[get("/v0/pipelines/{name}/completion_status")]
        async fn completion_status() -> impl Responder {
            HttpResponse::Ok().json(serde_json::json!({ "completed": true }))
        }

        let seen = Arc::new(Mutex::new(Seen::default()));
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let addr = listener
            .local_addr()
            .expect("listener should have local addr");
        let server_seen = seen.clone();
        let server = actix_web::HttpServer::new(move || {
            App::new()
                .app_data(web::Data::new(server_seen.clone()))
                .service(get_pipeline)
                .service(create_pipeline)
                .service(patch_pipeline)
                .service(start_pipeline)
                .service(query_pipeline)
                .service(ingress_rows)
                .service(completion_status)
        })
        .listen(listener)
        .expect("server should listen")
        .run();
        let handle = server.handle();
        actix_web::rt::spawn(server);
        actix_web::rt::time::sleep(Duration::from_millis(25)).await;

        let mut loaded = LoadedConfig {
            config: AppConfig::default(),
            managed_dir: std::path::PathBuf::from("config"),
            source: "test".to_owned(),
        };
        loaded.config.feldera.enabled = true;
        loaded.config.feldera.base_url = format!("http://{}", addr);
        let managed = conclave_managed_config::LoadedManagedConfig {
            managed: ManagedConfig::load_from_str(
                r#"
catalog {
    actions (
        {name "tenant:user:read"}
    )
}
"#,
            )
            .expect("managed config should parse"),
            source: "test-managed".to_owned(),
        };
        let signer = JwtSigner::from_seed(
            loaded.config.jwt.signing_key_id.clone(),
            loaded
                .config
                .jwt
                .signing_seed_bytes()
                .expect("seed should decode"),
        );
        let verifier = signer.verifier();
        let state = AppState::from_loaded_config(loaded, managed, signer, verifier)
            .await
            .expect("state should build");

        let result = state
            .sync_feldera_on_startup()
            .await
            .expect("startup sync should succeed");

        handle.stop(true).await;
        assert_eq!(result.as_deref(), Some("created"));
        let seen = seen.lock().expect("seen lock");
        assert!(seen.gets >= 2);
        assert!(seen.creates >= 2);
    }

    // r[verify config.managed.feldera-authoritative-store]
    #[actix_web::test]
    async fn bootstraps_managed_state_from_feldera_when_enabled() {
        use actix_web::{patch, HttpResponse};
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        #[derive(Default, Clone)]
        struct Seen {
            pipeline_gets: usize,
            pipeline_creates: usize,
            query_calls: usize,
            ingress_calls: usize,
        }

        #[get("/v0/pipelines/{name}")]
        async fn get_pipeline(seen: web::Data<Arc<Mutex<Seen>>>) -> impl Responder {
            let mut seen = seen.lock().expect("seen lock");
            seen.pipeline_gets += 1;
            HttpResponse::NotFound().finish()
        }

        #[post("/v0/pipelines")]
        async fn create_pipeline(
            seen: web::Data<Arc<Mutex<Seen>>>,
            body: web::Json<crate::feldera::DesiredPipeline>,
        ) -> impl Responder {
            seen.lock().expect("seen lock").pipeline_creates += 1;
            HttpResponse::Ok().json(crate::feldera::PipelineRecord {
                name: body.name.clone(),
                description: Some(body.description.clone()),
                program_code: Some(body.program_code.clone()),
                program_status: Some("SqlCompiled".to_owned()),
                deployment_status: Some("Stopped".to_owned()),
                deployment_resources_status: Some("Stopped".to_owned()),
                deployment_runtime_status: None,
                program_config: body.program_config.clone(),
            })
        }

        #[post("/v0/pipelines/{name}/start")]
        async fn start_pipeline() -> impl Responder {
            HttpResponse::Ok().finish()
        }

        #[patch("/v0/pipelines/{name}")]
        async fn patch_pipeline() -> impl Responder {
            HttpResponse::Ok().finish()
        }

        #[get("/v0/pipelines/{name}/query")]
        async fn query_pipeline(
            seen: web::Data<Arc<Mutex<Seen>>>,
            request: HttpRequest,
        ) -> impl Responder {
            let sql = request
                .query_string()
                .split('&')
                .find_map(|entry| entry.strip_prefix("sql="))
                .unwrap_or_default()
                .replace('+', " ")
                .replace("%20", " ")
                .replace("%28", "(")
                .replace("%29", ")")
                .replace("%2A", "*");
            seen.lock().expect("seen lock").query_calls += 1;

            if sql.contains("COUNT(*)") {
                HttpResponse::Ok().body(r#"[{"count":0}]"#)
            } else if sql.contains("ORDER BY committed_at DESC") {
                HttpResponse::Ok().body(r#"[{"apply_id":"apply-bootstrap"}]"#)
            } else {
                HttpResponse::Ok().body(
                    r#"[
                        {
                            "resource_kind":"action",
                            "resource_key":"tenant:user:read",
                            "scope":"global",
                            "apply_id":"apply-bootstrap",
                            "row_version":1,
                            "valid_from":1,
                            "deleted":false,
                            "payload_json":"{\"name\":\"tenant:user:read\"}"
                        }
                    ]"#,
                )
            }
        }

        #[post("/v0/pipelines/{name}/ingress/{table}")]
        async fn ingress_rows(seen: web::Data<Arc<Mutex<Seen>>>) -> impl Responder {
            seen.lock().expect("seen lock").ingress_calls += 1;
            HttpResponse::Ok().json(serde_json::json!({ "completion_token": "done-1" }))
        }

        #[get("/v0/pipelines/{name}/completion_status")]
        async fn completion_status() -> impl Responder {
            HttpResponse::Ok().json(serde_json::json!({ "completed": true }))
        }

        let seen = Arc::new(Mutex::new(Seen::default()));
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let addr = listener
            .local_addr()
            .expect("listener should have local addr");
        let server_seen = seen.clone();
        let server = actix_web::HttpServer::new(move || {
            App::new()
                .app_data(web::Data::new(server_seen.clone()))
                .service(get_pipeline)
                .service(create_pipeline)
                .service(start_pipeline)
                .service(patch_pipeline)
                .service(query_pipeline)
                .service(ingress_rows)
                .service(completion_status)
        })
        .listen(listener)
        .expect("server should listen")
        .run();
        let handle = server.handle();
        actix_web::rt::spawn(server);
        actix_web::rt::time::sleep(Duration::from_millis(25)).await;

        let mut loaded = LoadedConfig {
            config: AppConfig::default(),
            managed_dir: std::path::PathBuf::from("config"),
            source: "test".to_owned(),
        };
        loaded.config.feldera.enabled = true;
        loaded.config.feldera.base_url = format!("http://{}", addr);
        let managed = conclave_managed_config::LoadedManagedConfig {
            managed: ManagedConfig::load_from_str(
                r#"
catalog {
    actions (
        {name "tenant:user:read"}
    )
}
"#,
            )
            .expect("managed config should parse"),
            source: "bootstrap-managed".to_owned(),
        };
        let signer = JwtSigner::from_seed(
            loaded.config.jwt.signing_key_id.clone(),
            loaded
                .config
                .jwt
                .signing_seed_bytes()
                .expect("seed should decode"),
        );
        let verifier = signer.verifier();
        let state = AppState::from_loaded_config(loaded, managed, signer, verifier)
            .await
            .expect("state should build");
        let catalog = state.current_catalog().expect("catalog should compile");

        handle.stop(true).await;
        assert_eq!(catalog.actions.len(), 1);
        let seen = seen.lock().expect("seen lock");
        assert!(seen.pipeline_creates >= 1);
        assert!(seen.query_calls >= 2);
        assert!(seen.ingress_calls >= 1);
    }

    #[actix_web::test]
    #[ignore = "requires a running Feldera manager via CONCLAVE_COMPONENT_FELDERA_URL"]
    async fn readyz_checks_a_live_feldera_manager() {
        let mut loaded = LoadedConfig {
            config: AppConfig::default(),
            managed_dir: std::path::PathBuf::from("config"),
            source: "test".to_owned(),
        };
        loaded.config.feldera.enabled = true;
        loaded.config.feldera.readiness_probe = true;
        loaded.config.feldera.pipeline_prefix = format!(
            "component-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should be monotonic enough")
                .as_secs()
        );
        loaded.config.feldera.base_url = std::env::var("CONCLAVE_COMPONENT_FELDERA_URL")
            .expect("set CONCLAVE_COMPONENT_FELDERA_URL to run this test");
        let managed = conclave_managed_config::LoadedManagedConfig {
            managed: ManagedConfig::load_from_str(
                r#"
catalog { actions () }
"#,
            )
            .expect("managed config should parse"),
            source: "test-managed".to_owned(),
        };
        let signer = JwtSigner::from_seed(
            loaded.config.jwt.signing_key_id.clone(),
            loaded
                .config
                .jwt
                .signing_seed_bytes()
                .expect("seed should decode"),
        );
        let verifier = signer.verifier();
        let state = AppState::from_loaded_config(loaded, managed, signer, verifier)
            .await
            .expect("state should build");
        let control = test::init_service(
            App::new()
                .app_data(web::Data::new(state))
                .configure(configure_control_plane),
        )
        .await;

        let request = test::TestRequest::get().uri("/readyz").to_request();
        let response = test::call_service(&control, request).await;

        assert_eq!(response.status(), StatusCode::OK);
    }
}
