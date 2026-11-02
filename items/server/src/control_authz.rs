//! The control-plane surface for tenancy and authorization: the catalog,
//! tenants, memberships, templates, roles and role assignments.

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use diesel_async::AsyncConnection;
use konklav_api::{
    self as api, AssignRole, CatalogDocument, CreateMembership, CreateTenant, Deleted,
    EntitlementQuery, Entitlements, ExplainQuery, Explanation, MembershipDetail, MembershipQuery,
    PutRole, PutTemplate, SetTenantState, TenantPage, TenantQuery,
};
use konklav_core::{MembershipId, SubjectId, TenantId};
use konklav_store::catalog::{self, FactTarget};
use konklav_store::memberships;
use konklav_store::roles;
use konklav_store::sessions::{self, SessionFilter};
use konklav_store::templates;
use konklav_store::tenants::{self, TenantState};
use konklav_store::{StoreError, compile_input, events};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::capabilities::Operator;
use crate::control_api::{Written, guard, parse_id};
use crate::error::{ApiError, ApiJson};
use crate::import::{self, not_found_as, validate_facts};
use crate::{AppState, capabilities, transport};

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

/// The catalog, templates, roles, role assignments and entitlements,
/// described like [`tenancy`].
pub(crate) fn authz() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_catalog, put_catalog))
        .routes(routes!(list_roles))
        .routes(routes!(put_role, get_role, delete_role))
        .routes(routes!(assign_membership_role))
        .routes(routes!(assign_global_role, list_global_assignments))
        .routes(routes!(subject_entitlements))
        .routes(routes!(explain_entitlement))
        .routes(routes!(unassign))
        .routes(routes!(list_templates))
        .routes(routes!(put_template, get_template))
}

pub fn routes(state: &AppState) -> Router<AppState> {
    let (tenancy, _) = tenancy()
        .route_layer(guard(state, capabilities::TENANTS))
        .split_for_parts();
    let (authz, _) = authz()
        .route_layer(guard(state, capabilities::AUTHZ))
        .split_for_parts();
    tenancy.merge(authz)
}

fn tenant_ref(value: &str) -> Result<TenantId, ApiError> {
    tenants::parse_reference(value)
        .ok_or_else(|| ApiError::invalid_request("tenant must be a UUID or `root`"))
}

// --- Catalog ----------------------------------------------------------------

#[utoipa::path(get, path = "/catalog", tag = "catalog",
    responses((status = 200, body = CatalogDocument)))]
async fn get_catalog(State(state): State<AppState>) -> Result<Json<CatalogDocument>, ApiError> {
    let mut conn = state.pool.get().await?;
    Ok(Json(transport::catalog(catalog::load(&mut conn).await?)))
}

/// `PUT /v1/catalog`: replaces the whole catalog.
#[utoipa::path(put, path = "/catalog", tag = "catalog",
    request_body = CatalogDocument,
    responses((status = 200, body = Written<CatalogDocument>)))]
async fn put_catalog(
    State(state): State<AppState>,
    ApiJson(document): ApiJson<CatalogDocument>,
) -> Result<Json<Written<CatalogDocument>>, ApiError> {
    let document = transport::store_catalog(document);
    let mut conn = state.pool.get().await?;
    let cursor = conn
        .transaction::<_, ApiError, _>(async |conn| {
            import::replace_catalog(conn, &document).await?;
            Ok(events::last_in_transaction(conn).await?)
        })
        .await?;
    Ok(Json(Written {
        value: transport::catalog(catalog::load(&mut conn).await?),
        cursor,
    }))
}

// --- Tenants ----------------------------------------------------------------

/// `PUT /v1/tenants/{id}`: idempotent on the id.
#[utoipa::path(put, path = "/tenants/{id}", tag = "tenants",
    params(("id" = TenantId, Path, description = "Chosen by the caller")),
    request_body = CreateTenant,
    responses(
        (status = 201, description = "Created", body = Written<api::Tenant>),
        (status = 200, description = "Already existed with the same content", body = Written<api::Tenant>),
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
            value: transport::tenant(tenant),
            cursor,
        }),
    )
        .into_response())
}

#[utoipa::path(get, path = "/tenants/{id}", tag = "tenants", params(("id" = String, Path, description = "The tenant: a UUID or `root`")),
    responses((status = 200, body = api::Tenant)))]
async fn get_tenant(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<api::Tenant>, ApiError> {
    let id = tenant_ref(&id)?;
    let mut conn = state.pool.get().await?;
    Ok(Json(transport::tenant(
        tenants::get(&mut conn, id)
            .await
            .map_err(not_found_as("tenant"))?,
    )))
}

#[utoipa::path(put, path = "/tenants/{id}/facts", tag = "tenants", params(("id" = String, Path, description = "The tenant: a UUID or `root`")),
    request_body(content = Object, description = "The tenant's new facts"),
    responses((status = 200, body = Written<api::Tenant>)))]
async fn set_tenant_facts(
    State(state): State<AppState>,
    Path(id): Path<String>,
    ApiJson(facts): ApiJson<serde_json::Value>,
) -> Result<Json<Written<api::Tenant>>, ApiError> {
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
        value: transport::tenant(tenant),
        cursor,
    }))
}

/// `PUT /v1/tenants/{id}/state`: leaving `active` ends every session
/// targeting the tenant.
// r[impl tenant.lifecycle.suspend-revokes]
#[utoipa::path(put, path = "/tenants/{id}/state", tag = "tenants", params(("id" = String, Path, description = "The tenant: a UUID or `root`")),
    request_body = SetTenantState,
    responses((status = 200, body = Written<api::Tenant>)))]
async fn set_tenant_state(
    State(state): State<AppState>,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<SetTenantState>,
) -> Result<Json<Written<api::Tenant>>, ApiError> {
    let id = tenant_ref(&id)?;
    let mut conn = state.pool.get().await?;
    let (tenant, cursor) = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let new_state = transport::store_tenant_state(body.state);
            let tenant = tenants::set_state(conn, id, new_state)
                .await
                .map_err(not_found_as("tenant"))?;
            if new_state != TenantState::Active {
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
        value: transport::tenant(tenant),
        cursor,
    }))
}

// --- Memberships ------------------------------------------------------------

/// `PUT /v1/memberships/{id}`: idempotent on the id.
#[utoipa::path(put, path = "/memberships/{id}", tag = "memberships",
    params(("id" = MembershipId, Path, description = "Chosen by the caller")),
    request_body = CreateMembership,
    responses(
        (status = 201, description = "Created", body = Written<api::Membership>),
        (status = 200, description = "Already existed with the same content", body = Written<api::Membership>),
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
            value: transport::membership(membership),
            cursor,
        }),
    )
        .into_response())
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
        membership: transport::membership(membership),
        assignments: assignments
            .into_iter()
            .map(transport::role_assignment)
            .collect(),
    }))
}

#[utoipa::path(put, path = "/memberships/{id}/facts", tag = "memberships", params(("id" = MembershipId, Path)),
    request_body(content = Object, description = "The membership's new facts"),
    responses((status = 200, body = Written<api::Membership>)))]
async fn set_membership_facts(
    State(state): State<AppState>,
    Path(id): Path<String>,
    ApiJson(facts): ApiJson<serde_json::Value>,
) -> Result<Json<Written<api::Membership>>, ApiError> {
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
        value: transport::membership(membership),
        cursor,
    }))
}

/// `POST /v1/memberships/{id}/end`: ends the membership and the sessions
/// targeting it.
#[utoipa::path(post, path = "/memberships/{id}/end", tag = "memberships", params(("id" = MembershipId, Path)),
    responses((status = 200, body = Written<api::Membership>)))]
async fn end_membership(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Written<api::Membership>>, ApiError> {
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
        value: transport::membership(membership),
        cursor,
    }))
}

// --- Templates and roles ----------------------------------------------------

#[utoipa::path(get, path = "/templates", tag = "templates",
    responses((status = 200, body = Vec<api::Template>)))]
async fn list_templates(
    State(state): State<AppState>,
) -> Result<Json<Vec<api::Template>>, ApiError> {
    let mut conn = state.pool.get().await?;
    Ok(Json(
        templates::list(&mut conn)
            .await?
            .into_iter()
            .map(transport::template)
            .collect(),
    ))
}

#[utoipa::path(get, path = "/templates/{key}", tag = "templates", params(("key" = String, Path)),
    responses((status = 200, body = api::Template)))]
async fn get_template(
    State(state): State<AppState>,
    Path(key): Path<String>,
) -> Result<Json<api::Template>, ApiError> {
    let mut conn = state.pool.get().await?;
    Ok(Json(transport::template(
        templates::get(&mut conn, &key)
            .await
            .map_err(not_found_as("template"))?,
    )))
}

/// `PUT /v1/templates/{key}`: creates or replaces a template.
#[utoipa::path(put, path = "/templates/{key}", tag = "templates", params(("key" = String, Path)),
    request_body = PutTemplate,
    responses((status = 200, body = Written<api::Template>)))]
async fn put_template(
    State(state): State<AppState>,
    Extension(operator): Extension<Operator>,
    Path(key): Path<String>,
    ApiJson(body): ApiJson<PutTemplate>,
) -> Result<Json<Written<api::Template>>, ApiError> {
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
        value: transport::template(template),
        cursor,
    }))
}

#[utoipa::path(get, path = "/tenants/{id}/roles", tag = "roles",
    params(("id" = String, Path, description = "The tenant: a UUID or `root`")),
    responses((status = 200, body = Vec<api::Role>)))]
async fn list_roles(
    State(state): State<AppState>,
    Path(tenant): Path<String>,
) -> Result<Json<Vec<api::Role>>, ApiError> {
    let tenant = tenant_ref(&tenant)?;
    let mut conn = state.pool.get().await?;
    Ok(Json(
        roles::list(&mut conn, tenant)
            .await?
            .into_iter()
            .map(transport::role)
            .collect(),
    ))
}

#[utoipa::path(get, path = "/tenants/{id}/roles/{key}", tag = "roles",
    params(("id" = String, Path, description = "The tenant: a UUID or `root`"), ("key" = String, Path)),
    responses((status = 200, body = api::Role)))]
async fn get_role(
    State(state): State<AppState>,
    Path((tenant, key)): Path<(String, String)>,
) -> Result<Json<api::Role>, ApiError> {
    let tenant = tenant_ref(&tenant)?;
    let mut conn = state.pool.get().await?;
    Ok(Json(transport::role(
        roles::get(&mut conn, tenant, &key)
            .await
            .map_err(not_found_as("role"))?,
    )))
}

/// `PUT /v1/tenants/{tenant}/roles/{key}`: creates or replaces a role.
/// Roles of the root tenant are global roles.
#[utoipa::path(put, path = "/tenants/{id}/roles/{key}", tag = "roles",
    params(("id" = String, Path, description = "The tenant: a UUID or `root`"), ("key" = String, Path)),
    request_body = PutRole,
    responses((status = 200, body = Written<api::Role>)))]
async fn put_role(
    State(state): State<AppState>,
    Extension(operator): Extension<Operator>,
    Path((tenant, key)): Path<(String, String)>,
    ApiJson(body): ApiJson<PutRole>,
) -> Result<Json<Written<api::Role>>, ApiError> {
    let tenant = tenant_ref(&tenant)?;
    let definition = transport::role_definition(body);
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
        value: transport::role(role),
        cursor,
    }))
}

#[utoipa::path(delete, path = "/tenants/{id}/roles/{key}", tag = "roles",
    params(("id" = String, Path, description = "The tenant: a UUID or `root`"), ("key" = String, Path)),
    responses((status = 200, body = Written<Deleted>)))]
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

/// `POST /v1/memberships/{id}/assignments`
#[utoipa::path(post, path = "/memberships/{id}/assignments", tag = "assignments",
    params(("id" = MembershipId, Path)),
    request_body = AssignRole,
    responses((status = 201, description = "Assigned", body = Written<api::RoleAssignment>)))]
async fn assign_membership_role(
    State(state): State<AppState>,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<AssignRole>,
) -> Result<(StatusCode, Json<Written<api::RoleAssignment>>), ApiError> {
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
            value: transport::role_assignment(assignment),
            cursor,
        }),
    ))
}

/// `POST /v1/subjects/{id}/global-assignments`
// r[impl authz.assignment.capabilities]
#[utoipa::path(post, path = "/subjects/{id}/global-assignments", tag = "assignments",
    params(("id" = SubjectId, Path)),
    request_body = AssignRole,
    responses((status = 201, description = "Assigned", body = Written<api::RoleAssignment>)))]
async fn assign_global_role(
    State(state): State<AppState>,
    Extension(operator): Extension<Operator>,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<AssignRole>,
) -> Result<(StatusCode, Json<Written<api::RoleAssignment>>), ApiError> {
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
            value: transport::role_assignment(assignment),
            cursor,
        }),
    ))
}

#[utoipa::path(get, path = "/subjects/{id}/global-assignments", tag = "assignments",
    params(("id" = SubjectId, Path)),
    responses((status = 200, body = Vec<api::RoleAssignment>)))]
async fn list_global_assignments(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Vec<api::RoleAssignment>>, ApiError> {
    let id: SubjectId = parse_id(&id, "subject id")?;
    let mut conn = state.pool.get().await?;
    Ok(Json(
        roles::global_assignments_of(&mut conn, id)
            .await?
            .into_iter()
            .map(transport::role_assignment)
            .collect(),
    ))
}

#[utoipa::path(delete, path = "/assignments/{id}", tag = "assignments",
    params(("id" = uuid::Uuid, Path)),
    responses((status = 200, body = Written<Deleted>)))]
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

/// `GET /v1/subjects/{id}/entitlements?tenant=`: what a subject is
/// entitled to, for operators.
#[utoipa::path(get, path = "/subjects/{id}/entitlements", tag = "entitlements",
    params(("id" = SubjectId, Path), EntitlementQuery),
    responses((status = 200, body = Entitlements)))]
async fn subject_entitlements(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<EntitlementQuery>,
) -> Result<Json<Entitlements>, ApiError> {
    let id: SubjectId = parse_id(&id, "subject id")?;
    let tenant = query.tenant.as_deref().map(tenant_ref).transpose()?;
    let mut conn = state.pool.get().await?;
    let input = compile_input::load(&mut conn, id, tenant).await?;
    Ok(Json(input.compile()))
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
    Ok(Json(TenantPage {
        tenants: tenants.into_iter().map(transport::tenant).collect(),
        next,
    }))
}

/// `GET /v1/tenants/{id}/memberships?active=`
#[utoipa::path(get, path = "/tenants/{id}/memberships", tag = "memberships",
    params(("id" = String, Path, description = "The tenant: a UUID or `root`"), MembershipQuery),
    responses((status = 200, body = Vec<api::Membership>)))]
async fn list_memberships(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<MembershipQuery>,
) -> Result<Json<Vec<api::Membership>>, ApiError> {
    let tenant = tenant_ref(&id)?;
    let mut conn = state.pool.get().await?;
    let memberships = memberships::list_for_tenant(&mut conn, tenant, query.active).await?;
    Ok(Json(
        memberships.into_iter().map(transport::membership).collect(),
    ))
}

/// `GET /v1/subjects/{id}/explain?tenant=&action=`: which assignments and
/// policies bear on an action, and where it ends up granted.
#[utoipa::path(get, path = "/subjects/{id}/explain", tag = "explain",
    params(("id" = SubjectId, Path), ExplainQuery),
    responses((status = 200, body = Explanation)))]
async fn explain_entitlement(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<ExplainQuery>,
) -> Result<Json<Explanation>, ApiError> {
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
