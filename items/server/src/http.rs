use std::sync::{Arc, RwLock};

use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use conclave_controlplane_api::{
    ActionCatalogResponse, CurrentRevisionsResponse, InviteCreateRequest, InviteCreateResponse,
    LoginRequest, LoginResponse, ManagedApplyRequest, ManagedApplyResponse, ManagedPlanRequest,
    ManagedValidateRequest, ManagedValidateResponse, RedeemInviteRequest, RedeemInviteResponse,
};
use conclave_managed_config::ManagedConfig;
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
            let durable_apply_id = store.load_latest_apply_id().await?;
            let (invites, credentials, sessions) = store.load_runtime_auth_state().await?;
            let mut state = ControlPlaneState::empty();
            if let Some(apply_id) = durable_apply_id {
                state.set_last_apply_id(apply_id);
            }
            state.replace_runtime_auth_state(invites, credentials, sessions);
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

    async fn load_managed_config(&self) -> Result<ManagedConfig, crate::types::DynError> {
        match &self.managed_store {
            Some(store) => store.load_managed().await,
            None => {
                let guard = self.state.read().expect("state lock should not poison");
                Ok(guard.managed().clone())
            }
        }
    }

    async fn current_last_apply_id(&self) -> Result<String, crate::types::DynError> {
        match &self.managed_store {
            Some(store) => Ok(store
                .load_latest_apply_id()
                .await?
                .unwrap_or_else(|| "apply-000000".to_owned())),
            None => {
                let guard = self.state.read().expect("state lock should not poison");
                Ok(guard.last_apply_id.clone())
            }
        }
    }

    // r[impl config.managed.store.feldera-authoritative-reads]
    // r[impl config.managed.store.bounded-derived-cache]
    async fn current_snapshot(
        &self,
    ) -> Result<(CompiledAuthzModel, CompiledTenantModel), crate::types::DynError> {
        let managed = self.load_managed_config().await?;
        let snapshot = ControlPlaneState::snapshot_from_managed(&managed)?;
        Ok((snapshot.authz, snapshot.tenants))
    }

    async fn current_catalog(&self) -> Result<ActionCatalogResponse, crate::types::DynError> {
        let (authz, _) = self.current_snapshot().await?;
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

        let (authz, _) = self.current_snapshot().await?;
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
    let last_apply_id = match state.current_last_apply_id().await {
        Ok(apply_id) => apply_id,
        Err(err) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": err.to_string(),
            }))
        }
    };

    HttpResponse::Ok().json(MetaResponse {
        config_source: (*state.config_source).clone(),
        managed_source: (*state.managed_source).clone(),
        control_plane_bind: state.control_plane_bind_address(),
        subject_bind: state.subject_bind_address(),
        relying_bind: state.relying_bind_address(),
        bootstrap_subject: state.config.bootstrap.subject.clone(),
        last_apply_id,
    })
}

#[post("/v1/managed/validate")]
// r[depends item.controlplane-api.shared-dto-boundary]
// r[depends item.controlplane-api.managed-ops-payloads]
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

    if let Some(store) = &state.managed_store {
        match store.plan(&body.managed).await {
            Ok(plan) => {
                let snapshot = match ControlPlaneState::snapshot_from_managed(&body.managed) {
                    Ok(snapshot) => snapshot,
                    Err(err) => {
                        return HttpResponse::BadRequest().json(serde_json::json!({
                            "error": err.to_string(),
                        }))
                    }
                };
                HttpResponse::Ok().json(conclave_controlplane_api::ManagedPlanResponse {
                    noop: plan.noop,
                    summary: plan.summary,
                    changes: plan.changes,
                    catalog_revision: snapshot.authz.catalog_revision,
                    policy_revision: snapshot.tenants.policy_revision,
                })
            }
            Err(err) => HttpResponse::BadRequest().json(serde_json::json!({
                "error": err.to_string(),
            })),
        }
    } else {
        let current_managed = match state.load_managed_config().await {
            Ok(managed) => managed,
            Err(err) => {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": err.to_string(),
                }))
            }
        };
        match ControlPlaneState::plan_against(&current_managed, &body.managed) {
            Ok(plan) => HttpResponse::Ok().json(plan),
            Err(err) => HttpResponse::BadRequest().json(serde_json::json!({
                "error": err.to_string(),
            })),
        }
    }
}

fn revisions_for_managed(managed: &ManagedConfig) -> Result<(u32, u64), crate::types::DynError> {
    let snapshot = ControlPlaneState::snapshot_from_managed(managed)?;
    Ok((
        snapshot.authz.catalog_revision,
        snapshot.tenants.policy_revision,
    ))
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

    if let Some(store) = &state.managed_store {
        let applied = match store.apply(&body.managed).await {
            Ok(applied) => applied,
            Err(err) => {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": err.to_string(),
                }))
            }
        };
        let (catalog_revision, policy_revision) = match revisions_for_managed(&body.managed) {
            Ok(revisions) => revisions,
            Err(err) => {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": err.to_string(),
                }))
            }
        };
        let mut guard = state.state.write().expect("state lock should not poison");
        guard.set_last_apply_id(applied.apply_id.clone());
        HttpResponse::Ok().json(ManagedApplyResponse {
            applied: true,
            apply_id: applied.apply_id,
            summary: applied.summary,
            catalog_revision,
            policy_revision,
        })
    } else {
        let current_managed = match state.load_managed_config().await {
            Ok(managed) => managed,
            Err(err) => {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": err.to_string(),
                }))
            }
        };
        let planned = match ControlPlaneState::plan_against(&current_managed, &body.managed) {
            Ok(plan) => plan,
            Err(err) => {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": err.to_string(),
                }))
            }
        };

        let mut guard = state.state.write().expect("state lock should not poison");
        match guard.apply_with_id(body.managed.clone(), None) {
            Ok(plan) => HttpResponse::Ok().json(ManagedApplyResponse {
                applied: true,
                apply_id: guard.last_apply_id.clone(),
                summary: if planned.summary == plan.summary {
                    plan.summary
                } else {
                    planned.summary
                },
                catalog_revision: plan.catalog_revision,
                policy_revision: plan.policy_revision,
            }),
            Err(err) => HttpResponse::BadRequest().json(serde_json::json!({
                "error": err.to_string(),
            })),
        }
    }
}

#[post("/v1/invites")]
// r[depends item.controlplane-api.subject-and-relying-dtos]
async fn create_invite(
    state: web::Data<AppState>,
    request: HttpRequest,
    body: web::Json<InviteCreateRequest>,
) -> impl Responder {
    if let Err(response) = state.ensure_bootstrap_token(&request) {
        return response;
    }

    let managed = match state.load_managed_config().await {
        Ok(managed) => managed,
        Err(err) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": err.to_string(),
            }))
        }
    };

    let planned = {
        let guard = state.state.read().expect("state lock should not poison");
        match guard.plan_invite_with_managed(
            &managed,
            &body.subject,
            body.expires_in_seconds.unwrap_or(900),
        ) {
            Ok(planned) => planned,
            Err(err) => {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": err.to_string(),
                }))
            }
        }
    };

    if let Some(store) = &state.managed_store {
        if let Err(err) = store.persist_invite(&planned.invite).await {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": err.to_string(),
            }));
        }
    }

    let mut guard = state.state.write().expect("state lock should not poison");
    let invite_id = planned.invite.invite_id.clone();
    let expires_at = planned.invite.expires_at;
    let redeem_code = planned.redeem_code.clone();
    guard.record_invite(planned.invite);

    HttpResponse::Ok().json(InviteCreateResponse {
        invite_id,
        subject: body.subject.clone(),
        redeem_code,
        expires_at,
    })
}

#[post("/v1/invites/redeem")]
async fn redeem_invite(
    state: web::Data<AppState>,
    body: web::Json<RedeemInviteRequest>,
) -> impl Responder {
    let planned = {
        let guard = state.state.write().expect("state lock should not poison");
        match guard.plan_redeem_invite(&body.redeem_code, &body.password) {
            Ok(planned) => planned,
            Err(err) => {
                return HttpResponse::Forbidden().json(serde_json::json!({
                    "error": err.to_string(),
                }))
            }
        }
    };

    if let Some(store) = &state.managed_store {
        if let Err(err) = store
            .persist_redeemed_invite(
                &planned.invite,
                planned.previous_invite_row_version,
                &planned.credential,
            )
            .await
        {
            return HttpResponse::Forbidden().json(serde_json::json!({
                "error": err.to_string(),
            }));
        }
    }

    let mut guard = state.state.write().expect("state lock should not poison");
    let subject = guard.apply_redeemed_invite(planned);
    HttpResponse::Ok().json(RedeemInviteResponse {
        subject,
        linked: true,
    })
}

#[post("/v1/login")]
// r[depends item.controlplane-api.subject-and-relying-dtos]
async fn login(state: web::Data<AppState>, body: web::Json<LoginRequest>) -> impl Responder {
    let managed = match state.load_managed_config().await {
        Ok(managed) => managed,
        Err(err) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": err.to_string(),
            }))
        }
    };

    let session = {
        let guard = state.state.read().expect("state lock should not poison");
        match guard.plan_login_with_managed(&managed, &body.subject, &body.password, &body.tenant) {
            Ok(session) => session,
            Err(err) => {
                return HttpResponse::Forbidden().json(serde_json::json!({
                    "error": err.to_string(),
                }))
            }
        }
    };

    if let Some(store) = &state.managed_store {
        if let Err(err) = store.persist_session(&session).await {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": err.to_string(),
            }));
        }
    }

    let session_id = {
        let mut guard = state.state.write().expect("state lock should not poison");
        guard.record_session(session)
    };

    let (authz, tenants) = match state.current_snapshot().await {
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
    let (authz, tenants) = match state.current_snapshot().await {
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
    let (authz, tenants) = match state.current_snapshot().await {
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
// r[depends item.controlplane-api.subject-and-relying-dtos]
async fn current_revisions(state: web::Data<AppState>) -> impl Responder {
    match state.current_snapshot().await {
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
// r[depends item.controlplane-api.subject-and-relying-dtos]
async fn action_catalog(state: web::Data<AppState>) -> impl Responder {
    match state.current_catalog().await {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(err) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": err.to_string(),
        })),
    }
}

#[get("/.well-known/jwks.json")]
// r[depends item.relying-auth.ed25519-jwt-boundary]
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
        use std::collections::BTreeMap;
        use std::sync::{Arc, Mutex};
        use std::{net::TcpListener, time::Duration};

        #[derive(Default, Clone)]
        struct Seen {
            gets: usize,
            creates: usize,
            pipelines: BTreeMap<String, crate::feldera::PipelineRecord>,
        }

        #[get("/v0/pipelines/{name}")]
        async fn get_pipeline(
            path: web::Path<String>,
            seen: web::Data<Arc<Mutex<Seen>>>,
        ) -> impl Responder {
            let mut seen = seen.lock().expect("seen lock");
            seen.gets += 1;
            if let Some(pipeline) = seen.pipelines.get(path.as_str()).cloned() {
                HttpResponse::Ok().json(pipeline)
            } else {
                HttpResponse::NotFound().finish()
            }
        }

        #[post("/v0/pipelines")]
        async fn create_pipeline(
            seen: web::Data<Arc<Mutex<Seen>>>,
            body: web::Json<crate::feldera::DesiredPipeline>,
        ) -> impl Responder {
            let record = crate::feldera::PipelineRecord {
                name: body.name.clone(),
                description: Some(body.description.clone()),
                program_code: Some(body.program_code.clone()),
                program_status: Some("SqlCompiled".to_owned()),
                deployment_status: Some("Stopped".to_owned()),
                deployment_resources_status: None,
                deployment_runtime_status: None,
                program_config: body.program_config.clone(),
            };
            let mut seen = seen.lock().expect("seen lock");
            seen.creates += 1;
            seen.pipelines.insert(record.name.clone(), record.clone());
            HttpResponse::Ok().json(record)
        }

        #[patch("/v0/pipelines/{name}")]
        async fn patch_pipeline(
            body: web::Json<serde_json::Value>,
            path: web::Path<String>,
            seen: web::Data<Arc<Mutex<Seen>>>,
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
            seen.lock()
                .expect("seen lock")
                .pipelines
                .insert(record.name.clone(), record.clone());
            HttpResponse::Ok().json(record)
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
            } else if sql.contains("FROM current_action") {
                HttpResponse::Ok().body(
                    r#"[
                        {
                            "action_name":"tenant:user:read",
                            "description":null,
                            "apply_id":"apply-bootstrap",
                            "row_version":1,
                            "valid_from":1,
                            "deleted":false
                        }
                    ]"#,
                )
            } else if sql.contains("FROM current_invite")
                || sql.contains("FROM current_subject_credential")
                || sql.contains("FROM current_session")
                || sql.contains("FROM current_tenant")
                || sql.contains("FROM current_subject")
                || sql.contains("FROM current_membership")
                || sql.contains("FROM current_assumption_grant")
                || sql.contains("FROM current_template")
                || sql.contains("FROM current_role")
            {
                HttpResponse::Ok().body("[]")
            } else {
                HttpResponse::Ok().body("[]")
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
        assert!(matches!(
            result.as_deref(),
            Some("created") | Some("updated")
        ));
        let seen = seen.lock().expect("seen lock");
        assert!(seen.gets >= 2);
        assert!(seen.creates >= 2);
    }

    // r[verify config.managed.feldera-authoritative-store]
    // r[verify config.managed.store.feldera-authoritative-reads]
    // r[verify config.managed.store.bounded-derived-cache]
    #[actix_web::test]
    async fn bootstraps_managed_state_from_feldera_when_enabled() {
        use actix_web::{patch, HttpResponse};
        use std::collections::BTreeMap;
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        #[derive(Default, Clone)]
        struct Seen {
            pipeline_gets: usize,
            pipeline_creates: usize,
            query_calls: usize,
            ingress_calls: usize,
            pipelines: BTreeMap<String, crate::feldera::PipelineRecord>,
        }

        #[get("/v0/pipelines/{name}")]
        async fn get_pipeline(
            path: web::Path<String>,
            seen: web::Data<Arc<Mutex<Seen>>>,
        ) -> impl Responder {
            let mut seen = seen.lock().expect("seen lock");
            seen.pipeline_gets += 1;
            if let Some(pipeline) = seen.pipelines.get(path.as_str()).cloned() {
                HttpResponse::Ok().json(pipeline)
            } else {
                HttpResponse::NotFound().finish()
            }
        }

        #[post("/v0/pipelines")]
        async fn create_pipeline(
            seen: web::Data<Arc<Mutex<Seen>>>,
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
            let mut seen = seen.lock().expect("seen lock");
            seen.pipeline_creates += 1;
            seen.pipelines.insert(record.name.clone(), record.clone());
            HttpResponse::Ok().json(record)
        }

        #[post("/v0/pipelines/{name}/start")]
        async fn start_pipeline() -> impl Responder {
            HttpResponse::Ok().finish()
        }

        #[patch("/v0/pipelines/{name}")]
        async fn patch_pipeline(
            body: web::Json<serde_json::Value>,
            path: web::Path<String>,
            seen: web::Data<Arc<Mutex<Seen>>>,
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
            seen.lock()
                .expect("seen lock")
                .pipelines
                .insert(record.name.clone(), record.clone());
            HttpResponse::Ok().json(record)
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
            } else if sql.contains("FROM current_action") {
                HttpResponse::Ok().body(
                    r#"[
                        {
                            "action_name":"tenant:user:read",
                            "description":null,
                            "apply_id":"apply-bootstrap",
                            "row_version":1,
                            "valid_from":1,
                            "deleted":false
                        }
                    ]"#,
                )
            } else if sql.contains("FROM current_invite")
                || sql.contains("FROM current_subject_credential")
                || sql.contains("FROM current_session")
                || sql.contains("FROM current_tenant")
                || sql.contains("FROM current_subject")
                || sql.contains("FROM current_membership")
                || sql.contains("FROM current_assumption_grant")
                || sql.contains("FROM current_template")
                || sql.contains("FROM current_role")
            {
                HttpResponse::Ok().body("[]")
            } else {
                HttpResponse::Ok().body("[]")
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
        let catalog = state
            .current_catalog()
            .await
            .expect("catalog should compile");
        let catalog_again = state
            .current_catalog()
            .await
            .expect("catalog should compile again");

        handle.stop(true).await;
        assert_eq!(catalog.actions.len(), 1);
        assert_eq!(catalog_again.actions.len(), 1);
        let seen = seen.lock().expect("seen lock");
        assert!(seen.pipeline_creates >= 1);
        assert!(seen.query_calls >= 3);
        assert!(seen.ingress_calls >= 1);
    }

    // r[verify authn.session.persisted-history]
    // r[verify identity.subject.linked-credentials.versioned-history]
    // r[verify identity.subject.invite.audit-history]
    #[actix_web::test]
    async fn reloads_runtime_auth_state_from_feldera_after_restart() {
        use actix_web::{patch, HttpResponse};
        use serde_json::Value;
        use std::collections::BTreeMap;
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        #[derive(Default)]
        struct FakeStore {
            pipelines_created: usize,
            pipeline: Option<crate::feldera::PipelineRecord>,
            tables: BTreeMap<String, Vec<Value>>,
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
            let mut store = store.lock().expect("store lock");
            store.pipelines_created += 1;
            store.pipeline = Some(record.clone());
            HttpResponse::Ok().json(record)
        }

        #[post("/v0/pipelines/{name}/start")]
        async fn start_pipeline() -> impl Responder {
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

        #[post("/v0/pipelines/{name}/ingress/{table}")]
        async fn ingress_rows(
            path: web::Path<(String, String)>,
            store: web::Data<Arc<Mutex<FakeStore>>>,
            body: web::Json<Vec<Value>>,
        ) -> impl Responder {
            let table = &path.1;
            let mut store = store.lock().expect("store lock");
            store
                .tables
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

            if sql.contains("FROM apply_commit") && sql.contains("COUNT(*)") {
                let count = store
                    .tables
                    .get("apply_commit")
                    .map(Vec::as_slice)
                    .unwrap_or(&[])
                    .iter()
                    .filter(|row| row.get("committed").and_then(Value::as_bool) == Some(true))
                    .count();
                HttpResponse::Ok().json(vec![serde_json::json!({ "count": count })])
            } else if sql.contains("ORDER BY committed_at DESC") {
                let apply_id = store
                    .tables
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
                let max = store
                    .tables
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
                let rows = store
                    .tables
                    .get(table_name)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);
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
                .service(patch_pipeline)
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

        let loaded_config = || {
            let mut loaded = LoadedConfig {
                config: AppConfig::default(),
                managed_dir: std::path::PathBuf::from("config"),
                source: "test".to_owned(),
            };
            loaded.config.feldera.enabled = true;
            loaded.config.feldera.base_url = format!("http://{}", addr);
            loaded
        };
        let managed_config = || conclave_managed_config::LoadedManagedConfig {
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

        let loaded = loaded_config();
        let signer = JwtSigner::from_seed(
            loaded.config.jwt.signing_key_id.clone(),
            loaded
                .config
                .jwt
                .signing_seed_bytes()
                .expect("seed should decode"),
        );
        let verifier = signer.verifier();
        let state = AppState::from_loaded_config(loaded, managed_config(), signer, verifier)
            .await
            .expect("state should build");
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
        let _: RedeemInviteResponse = test::call_and_read_body_json(&subject, redeem_request).await;

        let reloaded_loaded = loaded_config();
        let reloaded_signer = JwtSigner::from_seed(
            reloaded_loaded.config.jwt.signing_key_id.clone(),
            reloaded_loaded
                .config
                .jwt
                .signing_seed_bytes()
                .expect("seed should decode"),
        );
        let reloaded_verifier = reloaded_signer.verifier();
        let reloaded_state = AppState::from_loaded_config(
            reloaded_loaded,
            managed_config(),
            reloaded_signer,
            reloaded_verifier,
        )
        .await
        .expect("reloaded state should build");
        let reloaded_subject = test::init_service(
            App::new()
                .app_data(web::Data::new(reloaded_state.clone()))
                .configure(configure_subject),
        )
        .await;

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
            test::call_and_read_body_json(&reloaded_subject, login_request).await;

        handle.stop(true).await;
        assert_eq!(login_response.claims.sub, "doctor-1");
        let store = store.lock().expect("store lock");
        let runtime_row_count = store.tables.get("invite").map(Vec::len).unwrap_or(0)
            + store
                .tables
                .get("subject_credential")
                .map(Vec::len)
                .unwrap_or(0)
            + store.tables.get("session_state").map(Vec::len).unwrap_or(0);
        assert!(runtime_row_count >= 3);
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
