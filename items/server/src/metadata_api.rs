//! Merge patches of objects' metadata on the control plane: one route per
//! kind of object, each in the route group (and behind the capability) of
//! the object it patches.

use axum::Json;
use axum::extract::Path;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use diesel_async::AsyncConnection;
use konklav_api as api;
use konklav_core::{CredentialId, MembershipId, ShareId, SubjectId};
use konklav_store::metadata::Object;
use konklav_store::{
    challenges, credentials, events, memberships, oidc_clients, roles, shares, subjects, templates,
    tenants,
};
use serde_json::Value;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::control_api::{Written, parse_id};
use crate::db::Db;
use crate::error::{ApiError, ApiJson};
use crate::import::not_found_as;
use crate::metadata::{self, Limit};
use crate::{AppState, invites, transport};

/// Subjects' and credentials' metadata, behind `konklav:subjects:manage`.
/// Like every metadata write, only on the control plane: the subject-facing
/// and relying surfaces have no route that writes or shows metadata.
// r[impl metadata.control-plane-only]
pub(crate) fn subjects() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(patch_subject))
        .routes(routes!(patch_credential))
}

/// Tenants' and memberships' metadata, behind `konklav:tenants:manage`.
pub(crate) fn tenancy() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(patch_tenant))
        .routes(routes!(patch_membership))
}

/// Templates', roles' and shares' metadata, behind `konklav:authz:manage`.
pub(crate) fn authz() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(patch_template))
        .routes(routes!(patch_role))
        .routes(routes!(patch_share))
}

/// Invites' metadata, behind `konklav:invites:manage`.
pub(crate) fn invites() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(patch_invite))
}

/// OIDC clients' metadata, behind `konklav:clients:manage`.
pub(crate) fn clients() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(patch_oidc_client))
}

/// Answers a patched object with its metadata's entity tag as `ETag`.
fn patched<T: serde::Serialize>(
    metadata: &Value,
    value: T,
    cursor: Option<konklav_core::Cursor>,
) -> Response {
    (
        metadata::etag_header(metadata),
        Json(Written { value, cursor }),
    )
        .into_response()
}

const PATCHED: &str = "The patched object, with its metadata's new entity tag also as `ETag`";
const STALE: &str = "`If-Match` didn't match: the metadata changed since it was read";

/// Merge-patches a subject's metadata.
///
/// An RFC 7396 merge patch: members replace the metadata's, `null` removes
/// one. With `If-Match`, only if the metadata's entity tag still matches.
#[utoipa::path(patch, path = "/subjects/{id}/metadata", operation_id = "patch_subject_metadata", tag = "subjects",
    params(("id" = SubjectId, Path), ("If-Match" = Option<String>, Header, description = "A `metadata_etag`")),
    request_body(content = Object, content_type = "application/merge-patch+json"),
    responses(
        (status = 200, description = PATCHED, body = Written<api::Subject>),
        (status = 412, description = STALE, body = api::ErrorResponse),
    ))]
async fn patch_subject(
    db: Db,
    limit: Limit,
    headers: HeaderMap,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<Value>,
) -> Result<Response, ApiError> {
    let id: SubjectId = parse_id(&id, "subject id")?;
    let mut conn = db.get().await?;
    let (value, written, cursor) = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let written = metadata::patch(
                conn,
                Object::Subject,
                &id.to_string(),
                &headers,
                &body,
                limit,
            )
            .await?;
            let subject = subjects::get(conn, id).await?;
            Ok((
                transport::subject(&subject),
                written,
                events::last_in_transaction(conn).await?,
            ))
        })
        .await?;
    Ok(patched(&written, value, cursor))
}

/// Merge-patches a credential's metadata.
///
/// As for subjects.
#[utoipa::path(patch, path = "/credentials/{id}/metadata", operation_id = "patch_credential_metadata", tag = "credentials",
    params(("id" = CredentialId, Path), ("If-Match" = Option<String>, Header, description = "A `metadata_etag`")),
    request_body(content = Object, content_type = "application/merge-patch+json"),
    responses(
        (status = 200, description = PATCHED, body = Written<api::Credential>),
        (status = 412, description = STALE, body = api::ErrorResponse),
    ))]
async fn patch_credential(
    db: Db,
    limit: Limit,
    headers: HeaderMap,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<Value>,
) -> Result<Response, ApiError> {
    let id: CredentialId = parse_id(&id, "credential id")?;
    let mut conn = db.get().await?;
    let (value, written, cursor) = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let written = metadata::patch(
                conn,
                Object::Credential,
                &id.to_string(),
                &headers,
                &body,
                limit,
            )
            .await?;
            let credential = credentials::get(conn, id).await?;
            Ok((
                transport::credential(credential),
                written,
                events::last_in_transaction(conn).await?,
            ))
        })
        .await?;
    Ok(patched(&written, value, cursor))
}

/// Merge-patches an invite's metadata.
///
/// As for subjects. The patched metadata is what redemption hands over.
#[utoipa::path(patch, path = "/invites/{id}/metadata", operation_id = "patch_invite_metadata", tag = "invites",
    params(("id" = uuid::Uuid, Path), ("If-Match" = Option<String>, Header, description = "A `metadata_etag`")),
    request_body(content = Object, content_type = "application/merge-patch+json"),
    responses(
        (status = 200, description = PATCHED, body = Written<api::Invite>),
        (status = 412, description = STALE, body = api::ErrorResponse),
    ))]
async fn patch_invite(
    db: Db,
    limit: Limit,
    headers: HeaderMap,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<Value>,
) -> Result<Response, ApiError> {
    let id: uuid::Uuid = parse_id(&id, "invite id")?;
    let mut conn = db.get().await?;
    let (value, written, cursor) = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let written = metadata::patch(
                conn,
                Object::Invite,
                &id.to_string(),
                &headers,
                &body,
                limit,
            )
            .await?;
            let invite = challenges::get(conn, id).await?;
            Ok((
                invites::invite(invite),
                written,
                events::last_in_transaction(conn).await?,
            ))
        })
        .await?;
    Ok(patched(&written, value, cursor))
}

/// Merge-patches a tenant's metadata.
///
/// As for subjects.
#[utoipa::path(patch, path = "/tenants/{id}/metadata", operation_id = "patch_tenant_metadata", tag = "tenants",
    params(("id" = String, Path, description = "The tenant: a UUID or `root`"), ("If-Match" = Option<String>, Header, description = "A `metadata_etag`")),
    request_body(content = Object, content_type = "application/merge-patch+json"),
    responses(
        (status = 200, description = PATCHED, body = Written<api::Tenant>),
        (status = 412, description = STALE, body = api::ErrorResponse),
    ))]
async fn patch_tenant(
    db: Db,
    limit: Limit,
    headers: HeaderMap,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<Value>,
) -> Result<Response, ApiError> {
    let id = tenants::parse_reference(&id)
        .ok_or_else(|| ApiError::invalid_request("tenant must be a UUID or `root`"))?;
    let mut conn = db.get().await?;
    let (value, written, cursor) = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let written = metadata::patch(
                conn,
                Object::Tenant,
                &id.to_string(),
                &headers,
                &body,
                limit,
            )
            .await?;
            let tenant = tenants::get(conn, id).await?;
            Ok((
                transport::tenant(tenant),
                written,
                events::last_in_transaction(conn).await?,
            ))
        })
        .await?;
    Ok(patched(&written, value, cursor))
}

/// Merge-patches a membership's metadata.
///
/// As for subjects.
#[utoipa::path(patch, path = "/memberships/{id}/metadata", operation_id = "patch_membership_metadata", tag = "memberships",
    params(("id" = MembershipId, Path), ("If-Match" = Option<String>, Header, description = "A `metadata_etag`")),
    request_body(content = Object, content_type = "application/merge-patch+json"),
    responses(
        (status = 200, description = PATCHED, body = Written<api::Membership>),
        (status = 412, description = STALE, body = api::ErrorResponse),
    ))]
async fn patch_membership(
    db: Db,
    limit: Limit,
    headers: HeaderMap,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<Value>,
) -> Result<Response, ApiError> {
    let id: MembershipId = parse_id(&id, "membership id")?;
    let mut conn = db.get().await?;
    let (value, written, cursor) = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let written = metadata::patch(
                conn,
                Object::Membership,
                &id.to_string(),
                &headers,
                &body,
                limit,
            )
            .await?;
            let membership = memberships::get(conn, id).await?;
            Ok((
                transport::membership(membership),
                written,
                events::last_in_transaction(conn).await?,
            ))
        })
        .await?;
    Ok(patched(&written, value, cursor))
}

/// Merge-patches a template's metadata.
///
/// As for subjects; the template's policies and roles are untouched.
#[utoipa::path(patch, path = "/templates/{key}/metadata", operation_id = "patch_template_metadata", tag = "templates",
    params(("key" = String, Path), ("If-Match" = Option<String>, Header, description = "A `metadata_etag`")),
    request_body(content = Object, content_type = "application/merge-patch+json"),
    responses(
        (status = 200, description = PATCHED, body = Written<api::Template>),
        (status = 412, description = STALE, body = api::ErrorResponse),
    ))]
async fn patch_template(
    db: Db,
    limit: Limit,
    headers: HeaderMap,
    Path(key): Path<String>,
    ApiJson(body): ApiJson<Value>,
) -> Result<Response, ApiError> {
    let id = {
        let mut conn = db.get().await?;
        templates::get(&mut conn, &key)
            .await
            .map_err(not_found_as("template"))?
            .id
    };
    let mut conn = db.get().await?;
    let (value, written, cursor) = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let written = metadata::patch(
                conn,
                Object::Template,
                &id.to_string(),
                &headers,
                &body,
                limit,
            )
            .await?;
            let template = templates::get(conn, &key).await?;
            Ok((
                transport::template(template),
                written,
                events::last_in_transaction(conn).await?,
            ))
        })
        .await?;
    Ok(patched(&written, value, cursor))
}

/// Merge-patches a role's metadata.
///
/// As for subjects; the role's policies are untouched. Built-in roles
/// can't be patched.
#[utoipa::path(patch, path = "/tenants/{id}/roles/{key}/metadata", operation_id = "patch_role_metadata", tag = "roles",
    params(("id" = String, Path, description = "The tenant: a UUID or `root`"), ("key" = String, Path), ("If-Match" = Option<String>, Header, description = "A `metadata_etag`")),
    request_body(content = Object, content_type = "application/merge-patch+json"),
    responses(
        (status = 200, description = PATCHED, body = Written<api::Role>),
        (status = 412, description = STALE, body = api::ErrorResponse),
    ))]
// r[impl authz.role.builtin]
async fn patch_role(
    db: Db,
    limit: Limit,
    headers: HeaderMap,
    Path((tenant, key)): Path<(String, String)>,
    ApiJson(body): ApiJson<Value>,
) -> Result<Response, ApiError> {
    let tenant = tenants::parse_reference(&tenant)
        .ok_or_else(|| ApiError::invalid_request("tenant must be a UUID or `root`"))?;
    let role = {
        let mut conn = db.get().await?;
        roles::get(&mut conn, tenant, &key)
            .await
            .map_err(not_found_as("role"))?
    };
    if role.builtin {
        return Err(ApiError::invalid_request(format!(
            "`{key}` is a built-in role, which can't be written"
        )));
    }
    let mut conn = db.get().await?;
    let (value, written, cursor) = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let written = metadata::patch(
                conn,
                Object::Role,
                &role.id.to_string(),
                &headers,
                &body,
                limit,
            )
            .await?;
            let role = roles::get(conn, tenant, &key).await?;
            Ok((
                transport::role(role),
                written,
                events::last_in_transaction(conn).await?,
            ))
        })
        .await?;
    Ok(patched(&written, value, cursor))
}

/// Merge-patches a share's metadata.
///
/// As for subjects. The share isn't offered again: metadata isn't one of
/// its terms.
#[utoipa::path(patch, path = "/shares/{id}/metadata", operation_id = "patch_share_metadata", tag = "shares",
    params(("id" = ShareId, Path), ("If-Match" = Option<String>, Header, description = "A `metadata_etag`")),
    request_body(content = Object, content_type = "application/merge-patch+json"),
    responses(
        (status = 200, description = PATCHED, body = Written<api::Share>),
        (status = 412, description = STALE, body = api::ErrorResponse),
    ))]
async fn patch_share(
    db: Db,
    limit: Limit,
    headers: HeaderMap,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<Value>,
) -> Result<Response, ApiError> {
    let id: ShareId = parse_id(&id, "share id")?;
    let mut conn = db.get().await?;
    let (value, written, cursor) = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let written =
                metadata::patch(conn, Object::Share, &id.to_string(), &headers, &body, limit)
                    .await?;
            let share = shares::get(conn, id).await?;
            Ok((
                transport::share(share),
                written,
                events::last_in_transaction(conn).await?,
            ))
        })
        .await?;
    Ok(patched(&written, value, cursor))
}

/// Merge-patches an OIDC client's metadata.
///
/// As for subjects; the registration is otherwise untouched.
#[utoipa::path(patch, path = "/oidc/clients/{id}/metadata", operation_id = "patch_oidc_client_metadata", tag = "oidc-clients",
    params(("id" = String, Path, description = "The client id"), ("If-Match" = Option<String>, Header, description = "A `metadata_etag`")),
    request_body(content = Object, content_type = "application/merge-patch+json"),
    responses(
        (status = 200, description = PATCHED, body = Written<api::OidcClient>),
        (status = 412, description = STALE, body = api::ErrorResponse),
    ))]
async fn patch_oidc_client(
    db: Db,
    limit: Limit,
    headers: HeaderMap,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<Value>,
) -> Result<Response, ApiError> {
    let mut conn = db.get().await?;
    let (value, written, cursor) = conn
        .transaction::<_, ApiError, _>(async |conn| {
            let written =
                metadata::patch(conn, Object::OidcClient, &id, &headers, &body, limit).await?;
            let client = oidc_clients::get(conn, &id).await?;
            Ok((
                transport::oidc_client(client),
                written,
                events::last_in_transaction(conn).await?,
            ))
        })
        .await?;
    Ok(patched(&written, value, cursor))
}
