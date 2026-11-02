//! The control-plane surface for tenancy and authorization: the catalog,
//! tenants, memberships, templates, roles and role assignments.

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use diesel_async::AsyncConnection;
use konklav_authz::{Policy, Scope};
use konklav_core::{MembershipId, SubjectId, TenantId};
use konklav_store::catalog::{self, CatalogDocument, FactTarget};
use konklav_store::memberships::{self, Membership};
use konklav_store::roles::{self, Role, RoleAssignment, RoleDefinition};
use konklav_store::sessions::{self, SessionFilter};
use konklav_store::templates::{self, Template};
use konklav_store::tenants::{self, Tenant, TenantState};
use konklav_store::{StoreError, compile_input, events};
use serde::{Deserialize, Serialize};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::capabilities::Operator;
use crate::control_api::{Written, guard, parse_id};
use crate::error::{ApiError, ApiJson};
use crate::import::{self, not_found_as, validate_facts};
use crate::{AppState, capabilities};

/// Tenants and memberships, with the `OpenAPI` description of each route
/// taken from its handler's `#[utoipa::path]`.
pub(crate) fn tenancy() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_tenants))
        .routes(routes!(create_tenant, get_tenant))
        .routes(routes!(set_tenant_facts))
        .routes(routes!(set_tenant_state))
        .routes(routes!(list_memberships))
        .routes(routes!(create_membership, get_membership))
        .routes(routes!(set_membership_facts))
        .routes(routes!(end_membership))
}

pub fn routes(state: &AppState) -> Router<AppState> {
    let (tenancy, _) = tenancy()
        .route_layer(guard(state, capabilities::TENANTS))
        .split_for_parts();
    let authz = Router::new()
        .route("/catalog", get(get_catalog).put(put_catalog))
        .route("/tenants/{id}/roles", get(list_roles))
        .route(
            "/tenants/{id}/roles/{key}",
            put(put_role).get(get_role).delete(delete_role),
        )
        .route(
            "/memberships/{id}/assignments",
            post(assign_membership_role),
        )
        .route(
            "/subjects/{id}/global-assignments",
            post(assign_global_role).get(list_global_assignments),
        )
        .route("/subjects/{id}/entitlements", get(subject_entitlements))
        .route("/subjects/{id}/explain", get(explain_entitlement))
        .route("/assignments/{id}", delete(unassign))
        .route("/templates", get(list_templates))
        .route("/templates/{key}", put(put_template).get(get_template))
        .route_layer(guard(state, capabilities::AUTHZ));
    tenancy.merge(authz)
}

fn tenant_ref(value: &str) -> Result<TenantId, ApiError> {
    tenants::parse_reference(value)
        .ok_or_else(|| ApiError::invalid_request("tenant must be a UUID or `root`"))
}

// --- Catalog ----------------------------------------------------------------

async fn get_catalog(State(state): State<AppState>) -> Result<Json<CatalogDocument>, ApiError> {
    let mut conn = state.pool.get().await?;
    Ok(Json(catalog::load(&mut conn).await?))
}

/// `PUT /v1/catalog`: replaces the whole catalog.
async fn put_catalog(
    State(state): State<AppState>,
    ApiJson(document): ApiJson<CatalogDocument>,
) -> Result<Json<Written<CatalogDocument>>, ApiError> {
    let mut conn = state.pool.get().await?;
    let cursor = conn
        .transaction::<_, ApiError, _>(async |conn| {
            import::replace_catalog(conn, &document).await?;
            Ok(events::last_in_transaction(conn).await?)
        })
        .await?;
    Ok(Json(Written {
        value: catalog::load(&mut conn).await?,
        cursor,
    }))
}

// --- Tenants ----------------------------------------------------------------

#[derive(Deserialize, utoipa::ToSchema)]
struct CreateTenant {
    /// The parent tenant (a UUID or `root`); `root` when absent.
    parent: Option<String>,
    #[serde(default = "empty_object")]
    #[schema(value_type = Object)]
    facts: serde_json::Value,
    /// Templates to instantiate roles from, atomically with the tenant.
    #[serde(default)]
    templates: Vec<String>,
}

fn empty_object() -> serde_json::Value {
    serde_json::json!({})
}

/// `PUT /v1/tenants/{id}`: idempotent on the id.
#[utoipa::path(put, path = "/tenants/{id}", tag = "tenants",
    params(("id" = TenantId, Path, description = "Chosen by the caller")),
    request_body = CreateTenant,
    responses(
        (status = 201, description = "Created", body = Written<Tenant>),
        (status = 200, description = "Already existed with the same content", body = Written<Tenant>),
    ))]
async fn create_tenant(
    State(state): State<AppState>,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<CreateTenant>,
) -> Result<Response, ApiError> {
    let id: TenantId = parse_id(&id, "tenant id")?;
    let parent = body
        .parent
        .as_deref()
        .map_or(Ok(tenants::ROOT), tenant_ref)?;
    let mut conn = state.pool.get().await?;
    let (tenant, created, cursor) = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let (tenant, created) =
                import::create_tenant(conn, id, parent, &body.facts, &body.templates).await?;
            Ok((tenant, created, events::last_in_transaction(conn).await?))
        })
        .await?;
    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((
        status,
        Json(Written {
            value: tenant,
            cursor,
        }),
    )
        .into_response())
}

#[utoipa::path(get, path = "/tenants/{id}", tag = "tenants", params(("id" = String, Path, description = "The tenant: a UUID or `root`")),
    responses((status = 200, body = Tenant)))]
async fn get_tenant(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Tenant>, ApiError> {
    let id = tenant_ref(&id)?;
    let mut conn = state.pool.get().await?;
    Ok(Json(
        tenants::get(&mut conn, id)
            .await
            .map_err(not_found_as("tenant"))?,
    ))
}

#[utoipa::path(put, path = "/tenants/{id}/facts", tag = "tenants", params(("id" = String, Path, description = "The tenant: a UUID or `root`")),
    request_body(content = Object, description = "The tenant's new facts"),
    responses((status = 200, body = Written<Tenant>)))]
async fn set_tenant_facts(
    State(state): State<AppState>,
    Path(id): Path<String>,
    ApiJson(facts): ApiJson<serde_json::Value>,
) -> Result<Json<Written<Tenant>>, ApiError> {
    let id = tenant_ref(&id)?;
    let mut conn = state.pool.get().await?;
    let (tenant, cursor) = conn
        .transaction::<_, ApiError, _>(async |conn| {
            validate_facts(conn, FactTarget::Tenant, &facts).await?;
            let tenant = tenants::set_facts(conn, id, &facts)
                .await
                .map_err(not_found_as("tenant"))?;
            Ok((tenant, events::last_in_transaction(conn).await?))
        })
        .await?;
    Ok(Json(Written {
        value: tenant,
        cursor,
    }))
}

#[derive(Deserialize, utoipa::ToSchema)]
struct SetTenantState {
    state: TenantState,
}

/// `PUT /v1/tenants/{id}/state`: leaving `active` ends every session
/// targeting the tenant.
// r[impl tenant.lifecycle.suspend-revokes]
#[utoipa::path(put, path = "/tenants/{id}/state", tag = "tenants", params(("id" = String, Path, description = "The tenant: a UUID or `root`")),
    request_body = SetTenantState,
    responses((status = 200, body = Written<Tenant>)))]
async fn set_tenant_state(
    State(state): State<AppState>,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<SetTenantState>,
) -> Result<Json<Written<Tenant>>, ApiError> {
    let id = tenant_ref(&id)?;
    let mut conn = state.pool.get().await?;
    let (tenant, cursor) = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let tenant = tenants::set_state(conn, id, body.state)
                .await
                .map_err(not_found_as("tenant"))?;
            if body.state != TenantState::Active {
                let filter = SessionFilter {
                    tenant: Some(id),
                    ..Default::default()
                };
                sessions::revoke(conn, &filter, None, "tenant_inactive").await?;
            }
            Ok((tenant, events::last_in_transaction(conn).await?))
        })
        .await?;
    Ok(Json(Written {
        value: tenant,
        cursor,
    }))
}

// --- Memberships ------------------------------------------------------------

#[derive(Deserialize, utoipa::ToSchema)]
struct CreateMembership {
    subject: SubjectId,
    /// The tenant (a UUID or `root`).
    tenant: String,
    #[serde(default = "empty_object")]
    #[schema(value_type = Object)]
    facts: serde_json::Value,
}

/// `PUT /v1/memberships/{id}`: idempotent on the id.
#[utoipa::path(put, path = "/memberships/{id}", tag = "memberships",
    params(("id" = MembershipId, Path, description = "Chosen by the caller")),
    request_body = CreateMembership,
    responses(
        (status = 201, description = "Created", body = Written<Membership>),
        (status = 200, description = "Already existed with the same content", body = Written<Membership>),
    ))]
async fn create_membership(
    State(state): State<AppState>,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<CreateMembership>,
) -> Result<Response, ApiError> {
    let id: MembershipId = parse_id(&id, "membership id")?;
    let tenant = tenant_ref(&body.tenant)?;
    let mut conn = state.pool.get().await?;
    let (membership, created, cursor) = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let (membership, created) =
                import::create_membership(conn, id, body.subject, tenant, &body.facts).await?;
            Ok((
                membership,
                created,
                events::last_in_transaction(conn).await?,
            ))
        })
        .await?;
    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((
        status,
        Json(Written {
            value: membership,
            cursor,
        }),
    )
        .into_response())
}

#[derive(Serialize, utoipa::ToSchema)]
struct MembershipDetail {
    #[serde(flatten)]
    membership: Membership,
    assignments: Vec<RoleAssignment>,
}

#[utoipa::path(get, path = "/memberships/{id}", tag = "memberships", params(("id" = MembershipId, Path)),
    responses((status = 200, body = MembershipDetail)))]
async fn get_membership(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MembershipDetail>, ApiError> {
    let id: MembershipId = parse_id(&id, "membership id")?;
    let mut conn = state.pool.get().await?;
    let membership = memberships::get(&mut conn, id)
        .await
        .map_err(not_found_as("membership"))?;
    let assignments = roles::assignments_of_membership(&mut conn, id).await?;
    Ok(Json(MembershipDetail {
        membership,
        assignments,
    }))
}

#[utoipa::path(put, path = "/memberships/{id}/facts", tag = "memberships", params(("id" = MembershipId, Path)),
    request_body(content = Object, description = "The membership's new facts"),
    responses((status = 200, body = Written<Membership>)))]
async fn set_membership_facts(
    State(state): State<AppState>,
    Path(id): Path<String>,
    ApiJson(facts): ApiJson<serde_json::Value>,
) -> Result<Json<Written<Membership>>, ApiError> {
    let id: MembershipId = parse_id(&id, "membership id")?;
    let mut conn = state.pool.get().await?;
    let (membership, cursor) = conn
        .transaction::<_, ApiError, _>(async |conn| {
            validate_facts(conn, FactTarget::Membership, &facts).await?;
            let membership = memberships::set_facts(conn, id, &facts)
                .await
                .map_err(not_found_as("membership"))?;
            Ok((membership, events::last_in_transaction(conn).await?))
        })
        .await?;
    Ok(Json(Written {
        value: membership,
        cursor,
    }))
}

/// `POST /v1/memberships/{id}/end`: ends the membership and the sessions
/// targeting it.
#[utoipa::path(post, path = "/memberships/{id}/end", tag = "memberships", params(("id" = MembershipId, Path)),
    responses((status = 200, body = Written<Membership>)))]
async fn end_membership(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Written<Membership>>, ApiError> {
    let id: MembershipId = parse_id(&id, "membership id")?;
    let mut conn = state.pool.get().await?;
    let (membership, cursor) = conn
        .transaction::<_, ApiError, _>(async |conn| {
            memberships::end(conn, id)
                .await
                .map_err(not_found_as("membership"))?;
            let filter = SessionFilter {
                membership: Some(id),
                ..Default::default()
            };
            sessions::revoke(conn, &filter, None, "membership_ended").await?;
            let membership = memberships::get(conn, id).await?;
            Ok((membership, events::last_in_transaction(conn).await?))
        })
        .await?;
    Ok(Json(Written {
        value: membership,
        cursor,
    }))
}

// --- Templates and roles ----------------------------------------------------

#[derive(Deserialize)]
struct TemplateBody {
    #[serde(default)]
    description: String,
    #[serde(default = "empty_object")]
    metadata: serde_json::Value,
    #[serde(default)]
    policies: Vec<Policy>,
}

async fn list_templates(State(state): State<AppState>) -> Result<Json<Vec<Template>>, ApiError> {
    let mut conn = state.pool.get().await?;
    Ok(Json(templates::list(&mut conn).await?))
}

async fn get_template(
    State(state): State<AppState>,
    Path(key): Path<String>,
) -> Result<Json<Template>, ApiError> {
    let mut conn = state.pool.get().await?;
    Ok(Json(
        templates::get(&mut conn, &key)
            .await
            .map_err(not_found_as("template"))?,
    ))
}

/// `PUT /v1/templates/{key}`: creates or replaces a template.
async fn put_template(
    State(state): State<AppState>,
    Extension(operator): Extension<Operator>,
    Path(key): Path<String>,
    ApiJson(body): ApiJson<TemplateBody>,
) -> Result<Json<Written<Template>>, ApiError> {
    let mut conn = state.pool.get().await?;
    let (template, cursor) = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let granted = match templates::get(conn, &key).await {
                Ok(old) => capabilities::granted_by(&old.policies),
                Err(StoreError::NotFound) => false,
                Err(error) => return Err(error.into()),
            };
            if granted || capabilities::granted_by(&body.policies) {
                operator.require_all("a template with control-plane capabilities")?;
            }
            let template = import::put_template(
                conn,
                &key,
                &body.description,
                &body.metadata,
                &body.policies,
            )
            .await?;
            Ok((template, events::last_in_transaction(conn).await?))
        })
        .await?;
    Ok(Json(Written {
        value: template,
        cursor,
    }))
}

#[derive(Deserialize)]
struct RoleBody {
    template: Option<String>,
    #[serde(default)]
    priority: i32,
    #[serde(default = "empty_object")]
    metadata: serde_json::Value,
    #[serde(default)]
    policies: Vec<Policy>,
}

async fn list_roles(
    State(state): State<AppState>,
    Path(tenant): Path<String>,
) -> Result<Json<Vec<Role>>, ApiError> {
    let tenant = tenant_ref(&tenant)?;
    let mut conn = state.pool.get().await?;
    Ok(Json(roles::list(&mut conn, tenant).await?))
}

async fn get_role(
    State(state): State<AppState>,
    Path((tenant, key)): Path<(String, String)>,
) -> Result<Json<Role>, ApiError> {
    let tenant = tenant_ref(&tenant)?;
    let mut conn = state.pool.get().await?;
    Ok(Json(
        roles::get(&mut conn, tenant, &key)
            .await
            .map_err(not_found_as("role"))?,
    ))
}

/// `PUT /v1/tenants/{tenant}/roles/{key}`: creates or replaces a role.
/// Roles of the root tenant are global roles.
async fn put_role(
    State(state): State<AppState>,
    Extension(operator): Extension<Operator>,
    Path((tenant, key)): Path<(String, String)>,
    ApiJson(body): ApiJson<RoleBody>,
) -> Result<Json<Written<Role>>, ApiError> {
    let tenant = tenant_ref(&tenant)?;
    let definition = RoleDefinition {
        template: body.template,
        priority: body.priority,
        metadata: body.metadata,
        policies: body.policies,
    };
    let mut conn = state.pool.get().await?;
    let (role, cursor) = conn
        .transaction::<_, ApiError, _>(async |conn| {
            tenants::get(conn, tenant)
                .await
                .map_err(not_found_as("tenant"))?;
            let granted = match roles::get(conn, tenant, &key).await {
                Ok(old) => capabilities::granted_by_role(conn, &old).await?,
                Err(StoreError::NotFound) => false,
                Err(error) => return Err(error.into()),
            };
            let template_grants = match &definition.template {
                Some(template) => match templates::get(conn, template).await {
                    Ok(template) => capabilities::granted_by(&template.policies),
                    Err(StoreError::NotFound) => false,
                    Err(error) => return Err(error.into()),
                },
                None => false,
            };
            if granted || template_grants || capabilities::granted_by(&definition.policies) {
                operator.require_all("a role with control-plane capabilities")?;
            }
            let role = roles::put(conn, tenant, &key, &definition).await?;
            Ok((role, events::last_in_transaction(conn).await?))
        })
        .await?;
    Ok(Json(Written {
        value: role,
        cursor,
    }))
}

#[derive(Serialize)]
struct Deleted {
    deleted: bool,
}

async fn delete_role(
    State(state): State<AppState>,
    Extension(operator): Extension<Operator>,
    Path((tenant, key)): Path<(String, String)>,
) -> Result<Json<Written<Deleted>>, ApiError> {
    let tenant = tenant_ref(&tenant)?;
    let mut conn = state.pool.get().await?;
    let (deleted, cursor) = conn
        .transaction::<_, ApiError, _>(async |conn| {
            if let Ok(old) = roles::get(conn, tenant, &key).await
                && capabilities::granted_by_role(conn, &old).await?
            {
                operator.require_all("a role with control-plane capabilities")?;
            }
            let deleted = roles::delete(conn, tenant, &key).await?;
            Ok((deleted, events::last_in_transaction(conn).await?))
        })
        .await?;
    Ok(Json(Written {
        value: Deleted { deleted },
        cursor,
    }))
}

// --- Assignments ------------------------------------------------------------

#[derive(Deserialize)]
struct AssignRole {
    /// The role's key in the membership's tenant (or in root for global
    /// assignments).
    role: String,
    scope: Option<Scope>,
}

/// `POST /v1/memberships/{id}/assignments`
async fn assign_membership_role(
    State(state): State<AppState>,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<AssignRole>,
) -> Result<(StatusCode, Json<Written<RoleAssignment>>), ApiError> {
    let id: MembershipId = parse_id(&id, "membership id")?;
    let mut conn = state.pool.get().await?;
    let (assignment, cursor) = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let assignment =
                import::assign_membership_role(conn, id, &body.role, body.scope.as_ref()).await?;
            Ok((assignment, events::last_in_transaction(conn).await?))
        })
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(Written {
            value: assignment,
            cursor,
        }),
    ))
}

/// `POST /v1/subjects/{id}/global-assignments`
// r[impl authz.assignment.capabilities]
async fn assign_global_role(
    State(state): State<AppState>,
    Extension(operator): Extension<Operator>,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<AssignRole>,
) -> Result<(StatusCode, Json<Written<RoleAssignment>>), ApiError> {
    let id: SubjectId = parse_id(&id, "subject id")?;
    if body.scope.is_some() {
        return Err(ApiError::invalid_request(
            "global assignments have no scope",
        ));
    }
    let mut conn = state.pool.get().await?;
    let (assignment, cursor) = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let role = roles::get(conn, tenants::ROOT, &body.role)
                .await
                .map_err(not_found_as("global role"))?;
            if capabilities::granted_by_role(conn, &role).await? {
                operator.require_all("granting control-plane capabilities")?;
            }
            let assignment = import::assign_global_role(conn, id, &role).await?;
            Ok((assignment, events::last_in_transaction(conn).await?))
        })
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(Written {
            value: assignment,
            cursor,
        }),
    ))
}

async fn list_global_assignments(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Vec<RoleAssignment>>, ApiError> {
    let id: SubjectId = parse_id(&id, "subject id")?;
    let mut conn = state.pool.get().await?;
    Ok(Json(roles::global_assignments_of(&mut conn, id).await?))
}

async fn unassign(
    State(state): State<AppState>,
    Extension(operator): Extension<Operator>,
    Path(id): Path<String>,
) -> Result<Json<Written<Deleted>>, ApiError> {
    let id: uuid::Uuid = parse_id(&id, "assignment id")?;
    let mut conn = state.pool.get().await?;
    let (deleted, cursor) = conn
        .transaction::<_, ApiError, _>(async |conn| {
            if let Ok(role) = roles::of_assignment(conn, id).await
                && capabilities::granted_by_role(conn, &role).await?
            {
                operator.require_all("withdrawing control-plane capabilities")?;
            }
            let deleted = roles::unassign(conn, id).await?;
            Ok((deleted, events::last_in_transaction(conn).await?))
        })
        .await?;
    Ok(Json(Written {
        value: Deleted { deleted },
        cursor,
    }))
}

#[derive(Deserialize)]
struct EntitlementQuery {
    tenant: Option<String>,
}

/// `GET /v1/subjects/{id}/entitlements?tenant=`: what a subject is
/// entitled to, for operators.
async fn subject_entitlements(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<EntitlementQuery>,
) -> Result<Json<konklav_authz::Entitlements>, ApiError> {
    let id: SubjectId = parse_id(&id, "subject id")?;
    let tenant = query.tenant.as_deref().map(tenant_ref).transpose()?;
    let mut conn = state.pool.get().await?;
    let input = compile_input::load(&mut conn, id, tenant).await?;
    Ok(Json(input.compile()))
}

#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct TenantQuery {
    parent: Option<String>,
    before: Option<TenantId>,
    limit: Option<i64>,
}

#[derive(Serialize, utoipa::ToSchema)]
struct TenantPage {
    tenants: Vec<Tenant>,
    next: Option<TenantId>,
}

/// `GET /v1/tenants?parent=&before=&limit=`
#[utoipa::path(get, path = "/tenants", tag = "tenants", params(TenantQuery),
    responses((status = 200, body = TenantPage)))]
async fn list_tenants(
    State(state): State<AppState>,
    Query(query): Query<TenantQuery>,
) -> Result<Json<TenantPage>, ApiError> {
    let parent = query.parent.as_deref().map(tenant_ref).transpose()?;
    let limit = query.limit.unwrap_or(50).clamp(1, 500);
    let mut conn = state.pool.get().await?;
    let tenants = tenants::list(&mut conn, parent, query.before, limit).await?;
    let next = (i64::try_from(tenants.len()) == Ok(limit))
        .then(|| tenants.last().map(|t| t.id))
        .flatten();
    Ok(Json(TenantPage { tenants, next }))
}

#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct MembershipQuery {
    #[serde(default)]
    active: bool,
}

/// `GET /v1/tenants/{id}/memberships?active=`
#[utoipa::path(get, path = "/tenants/{id}/memberships", tag = "memberships",
    params(("id" = String, Path, description = "The tenant: a UUID or `root`"), MembershipQuery),
    responses((status = 200, body = Vec<Membership>)))]
async fn list_memberships(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<MembershipQuery>,
) -> Result<Json<Vec<Membership>>, ApiError> {
    let tenant = tenant_ref(&id)?;
    let mut conn = state.pool.get().await?;
    Ok(Json(
        memberships::list_for_tenant(&mut conn, tenant, query.active).await?,
    ))
}

#[derive(Deserialize)]
struct ExplainQuery {
    tenant: Option<String>,
    action: String,
}

/// `GET /v1/subjects/{id}/explain?tenant=&action=`: which assignments and
/// policies bear on an action, and where it ends up granted.
async fn explain_entitlement(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<ExplainQuery>,
) -> Result<Json<konklav_authz::Explanation>, ApiError> {
    let id: SubjectId = parse_id(&id, "subject id")?;
    let tenant = query.tenant.as_deref().map(tenant_ref).transpose()?;
    let mut conn = state.pool.get().await?;
    let input = compile_input::load(&mut conn, id, tenant).await?;
    Ok(Json(konklav_authz::explain(
        &input.catalog,
        &input.assignments,
        &query.action,
    )))
}
