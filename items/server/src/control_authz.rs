//! The control-plane surface for tenancy and authorization: the catalog,
//! tenants, memberships, templates, roles and role assignments.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use conclave_authz::{Policy, Scope, compile};
use conclave_core::{MembershipId, SubjectId, TenantId};
use conclave_store::catalog::{self, CatalogDocument, FactTarget};
use conclave_store::memberships::{self, Membership};
use conclave_store::roles::{self, AssignmentTarget, Role, RoleAssignment, RoleDefinition};
use conclave_store::sessions::{self, SessionFilter};
use conclave_store::templates::{self, Template};
use conclave_store::tenants::{self, Tenant, TenantState};
use conclave_store::{Connection, StoreError, compile_input, events, subjects};
use diesel_async::AsyncConnection;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::control_api::{Written, parse_id, require_control_token};
use crate::error::{ApiError, ApiJson, ErrorCode};

pub fn routes(state: &AppState) -> Router<AppState> {
    Router::new()
        .route("/catalog", get(get_catalog).put(put_catalog))
        .route("/tenants/{id}", put(create_tenant).get(get_tenant))
        .route("/tenants/{id}/facts", put(set_tenant_facts))
        .route("/tenants/{id}/state", put(set_tenant_state))
        .route("/tenants/{id}/roles", get(list_roles))
        .route(
            "/tenants/{id}/roles/{key}",
            put(put_role).get(get_role).delete(delete_role),
        )
        .route(
            "/memberships/{id}",
            put(create_membership).get(get_membership),
        )
        .route("/memberships/{id}/facts", put(set_membership_facts))
        .route("/memberships/{id}/end", post(end_membership))
        .route(
            "/memberships/{id}/assignments",
            post(assign_membership_role),
        )
        .route(
            "/subjects/{id}/global-assignments",
            post(assign_global_role).get(list_global_assignments),
        )
        .route("/subjects/{id}/entitlements", get(subject_entitlements))
        .route("/assignments/{id}", delete(unassign))
        .route("/templates", get(list_templates))
        .route("/templates/{key}", put(put_template).get(get_template))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_control_token,
        ))
}

fn tenant_ref(value: &str) -> Result<TenantId, ApiError> {
    tenants::parse_reference(value)
        .ok_or_else(|| ApiError::invalid_request("tenant must be a UUID or `root`"))
}

fn not_found_as(what: &'static str) -> impl Fn(StoreError) -> ApiError {
    move |error| match error {
        StoreError::NotFound => ApiError::not_found(what),
        other => other.into(),
    }
}

async fn validate_facts(
    conn: &mut Connection,
    target: FactTarget,
    facts: &serde_json::Value,
) -> Result<(), ApiError> {
    let document = catalog::load(conn).await?;
    document
        .validate_facts(target, facts)
        .map_err(ApiError::invalid_request)
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
    document.validate().map_err(ApiError::invalid_request)?;
    let mut conn = state.pool.get().await?;
    let cursor = conn
        .transaction::<_, ApiError, _>(async |conn| {
            catalog::replace(conn, &document).await?;
            Ok(events::last_in_transaction(conn).await?)
        })
        .await?;
    Ok(Json(Written {
        value: catalog::load(&mut conn).await?,
        cursor,
    }))
}

// --- Tenants ----------------------------------------------------------------

#[derive(Deserialize)]
struct CreateTenant {
    /// The parent tenant (a UUID or `root`); `root` when absent.
    parent: Option<String>,
    #[serde(default = "empty_object")]
    facts: serde_json::Value,
    /// Templates to instantiate roles from, atomically with the tenant.
    #[serde(default)]
    templates: Vec<String>,
}

fn empty_object() -> serde_json::Value {
    serde_json::json!({})
}

/// `PUT /v1/tenants/{id}`: idempotent on the id.
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
            validate_facts(conn, FactTarget::Tenant, &body.facts).await?;
            let (tenant, created) = tenants::create(conn, id, parent, &body.facts).await?;
            if created {
                roles::instantiate(conn, id, &body.templates).await?;
            }
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

#[derive(Deserialize)]
struct SetTenantState {
    state: TenantState,
}

/// `PUT /v1/tenants/{id}/state`: leaving `active` ends every session
/// targeting the tenant.
// r[impl tenant.lifecycle.suspend-revokes]
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

#[derive(Deserialize)]
struct CreateMembership {
    subject: SubjectId,
    tenant: String,
    #[serde(default = "empty_object")]
    facts: serde_json::Value,
}

/// `PUT /v1/memberships/{id}`: idempotent on the id.
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
            subjects::get(conn, body.subject)
                .await
                .map_err(not_found_as("subject"))?;
            let target = tenants::get(conn, tenant)
                .await
                .map_err(not_found_as("tenant"))?;
            if target.state == TenantState::Deleted {
                return Err(ApiError::new(ErrorCode::Conflict, "the tenant is deleted"));
            }
            validate_facts(conn, FactTarget::Membership, &body.facts).await?;
            let (membership, created) =
                memberships::create(conn, id, body.subject, tenant, &body.facts).await?;
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

#[derive(Serialize)]
struct MembershipDetail {
    #[serde(flatten)]
    membership: Membership,
    assignments: Vec<RoleAssignment>,
}

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
    Path(key): Path<String>,
    ApiJson(body): ApiJson<TemplateBody>,
) -> Result<Json<Written<Template>>, ApiError> {
    let mut conn = state.pool.get().await?;
    let (template, cursor) = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let template = templates::put(
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
    Path((tenant, key)): Path<(String, String)>,
) -> Result<Json<Written<Deleted>>, ApiError> {
    let tenant = tenant_ref(&tenant)?;
    let mut conn = state.pool.get().await?;
    let (deleted, cursor) = conn
        .transaction::<_, ApiError, _>(async |conn| {
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
            let membership = memberships::get(conn, id)
                .await
                .map_err(not_found_as("membership"))?;
            let role = roles::get(conn, membership.tenant_id, &body.role)
                .await
                .map_err(not_found_as("role"))?;
            let assignment = roles::assign(
                conn,
                role.id,
                AssignmentTarget::Membership(id),
                body.scope.as_ref(),
            )
            .await?;
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
            subjects::get(conn, id)
                .await
                .map_err(not_found_as("subject"))?;
            let role = roles::get(conn, tenants::ROOT, &body.role)
                .await
                .map_err(not_found_as("global role"))?;
            let assignment =
                roles::assign(conn, role.id, AssignmentTarget::Subject(id), None).await?;
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
    Path(id): Path<String>,
) -> Result<Json<Written<Deleted>>, ApiError> {
    let id: uuid::Uuid = parse_id(&id, "assignment id")?;
    let mut conn = state.pool.get().await?;
    let (deleted, cursor) = conn
        .transaction::<_, ApiError, _>(async |conn| {
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
) -> Result<Json<conclave_authz::Entitlements>, ApiError> {
    let id: SubjectId = parse_id(&id, "subject id")?;
    let tenant = query.tenant.as_deref().map(tenant_ref).transpose()?;
    let mut conn = state.pool.get().await?;
    let input = compile_input::load(&mut conn, id, tenant).await?;
    Ok(Json(compile(&input.catalog, &input.assignments)))
}
