//! Tenant references in requests: a UUID, `root` or a tenant key. Keys are
//! looked up, so resolving one needs the database.

use konklav_core::TenantId;
use konklav_store::Connection;
use konklav_store::tenants::{self, Reference};

use crate::error::ApiError;

/// What a malformed reference is told.
pub(crate) const MUST_BE: &str = "tenant must be a UUID, a tenant key or `root`";

/// Parses `value`, refusing anything that isn't a tenant reference.
pub(crate) fn parse(value: &str) -> Result<Reference, ApiError> {
    tenants::parse_reference(value).ok_or_else(|| ApiError::invalid_request(MUST_BE))
}

/// The tenant `value` names. `None` for a key no tenant has, which callers
/// answer as they answer a UUID of no tenant.
// r[impl tenant.key.reference]
pub(crate) async fn resolve(
    conn: &mut Connection,
    value: &str,
) -> Result<Option<TenantId>, ApiError> {
    Ok(tenants::resolve(conn, &parse(value)?).await?)
}

/// The tenant `value` names; a key no tenant has is not found.
pub(crate) async fn require(conn: &mut Connection, value: &str) -> Result<TenantId, ApiError> {
    resolve(conn, value)
        .await?
        .ok_or_else(|| ApiError::not_found("tenant"))
}

/// [`require`] for an optional reference.
pub(crate) async fn require_some(
    conn: &mut Connection,
    value: Option<&str>,
) -> Result<Option<TenantId>, ApiError> {
    match value {
        Some(value) => require(conn, value).await.map(Some),
        None => Ok(None),
    }
}
