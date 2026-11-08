//! Metadata on the control plane: the size limit, entity tags, merge
//! patches and list filters. Konklav stores metadata and never reads it;
//! nothing here looks inside an object beyond its size and top-level keys.

use axum::extract::FromRequestParts;
use axum::http::HeaderMap;
use axum::http::header::IF_MATCH;
use axum::http::request::Parts;
use konklav_store::Connection;
use konklav_store::metadata::{self as stored, Object};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::AppState;
use crate::error::{ApiError, ErrorCode};

/// The default size limit of an object's metadata, in bytes of compact
/// JSON.
pub const DEFAULT_LIMIT: usize = 16 * 1024;

/// The configured size limit of an object's metadata, for handlers.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limit(pub(crate) usize);

impl FromRequestParts<AppState> for Limit {
    type Rejection = std::convert::Infallible;

    fn from_request_parts(
        _parts: &mut Parts,
        state: &AppState,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Ok(Self(state.auth.metadata_limit)))
    }
}

/// Checks that `metadata` is an object within `limit` bytes of compact JSON.
// r[impl metadata.opaque]
// r[impl metadata.limit]
pub fn check(metadata: &Value, limit: usize) -> Result<(), ApiError> {
    if !metadata.is_object() {
        return Err(ApiError::invalid_request("metadata must be a JSON object"));
    }
    let size = serde_json::to_vec(metadata).map_or(usize::MAX, |bytes| bytes.len());
    if size > limit {
        return Err(ApiError::new(
            ErrorCode::MetadataTooLarge,
            format!("metadata takes {size} bytes, more than the {limit} allowed"),
        ));
    }
    Ok(())
}

impl Limit {
    pub(crate) fn check(self, metadata: &Value) -> Result<(), ApiError> {
        check(metadata, self.0)
    }

    /// `metadata`, checked, as an owned value.
    pub(crate) fn checked(self, metadata: &Value) -> Result<Value, ApiError> {
        self.check(metadata).map(|()| metadata.clone())
    }
}

/// The entity tag of `metadata`: a hash of its canonical JSON (keys sorted
/// at every level), so equal metadata always has the same tag however it
/// was written.
// r[impl metadata.write.precondition]
#[must_use]
pub fn etag(metadata: &Value) -> String {
    fn canonical(value: &Value, out: &mut Vec<u8>) {
        match value {
            Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                out.push(b'{');
                for (index, key) in keys.into_iter().enumerate() {
                    if index > 0 {
                        out.push(b',');
                    }
                    out.extend(serde_json::to_vec(key).unwrap_or_default());
                    out.push(b':');
                    canonical(&map[key], out);
                }
                out.push(b'}');
            }
            Value::Array(items) => {
                out.push(b'[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(b',');
                    }
                    canonical(item, out);
                }
                out.push(b']');
            }
            other => out.extend(serde_json::to_vec(other).unwrap_or_default()),
        }
    }
    let mut bytes = Vec::new();
    canonical(metadata, &mut bytes);
    let digest = Sha256::digest(&bytes);
    digest[..16].iter().fold(String::new(), |mut hex, byte| {
        use std::fmt::Write;
        let _ = write!(hex, "{byte:02x}");
        hex
    })
}

/// Applies a JSON merge patch (RFC 7396) to `target`: members of an object
/// patch are merged recursively, `null` removes a member, and anything
/// else replaces the target.
// r[impl metadata.write.patch]
pub fn merge_patch(target: &mut Value, patch: &Value) {
    let Value::Object(members) = patch else {
        *target = patch.clone();
        return;
    };
    if !target.is_object() {
        *target = Value::Object(serde_json::Map::new());
    }
    let Value::Object(fields) = target else {
        return;
    };
    for (key, value) in members {
        if value.is_null() {
            fields.remove(key);
        } else {
            merge_patch(fields.entry(key.clone()).or_insert(Value::Null), value);
        }
    }
}

/// Parses a list's `metadata` filter: a JSON object whose values are
/// strings, numbers or booleans. With only scalars, containment (`@>`)
/// is equality of each top-level key.
// r[impl metadata.filter]
pub fn filter(parameter: Option<&str>) -> Result<Option<Value>, ApiError> {
    let Some(parameter) = parameter else {
        return Ok(None);
    };
    let invalid = || {
        ApiError::invalid_request(
            "the metadata filter must be a JSON object of strings, numbers and booleans",
        )
    };
    let value: Value = serde_json::from_str(parameter).map_err(|_| invalid())?;
    let Value::Object(members) = &value else {
        return Err(invalid());
    };
    if members
        .values()
        .any(|v| !(v.is_string() || v.is_number() || v.is_boolean()))
    {
        return Err(invalid());
    }
    Ok(Some(value))
}

/// Whether `metadata` passes `filter`, for lists filtered in memory.
#[must_use]
pub fn matches(metadata: &Value, filter: Option<&Value>) -> bool {
    let Some(Value::Object(filter)) = filter else {
        return true;
    };
    filter
        .iter()
        .all(|(key, wanted)| metadata.get(key).is_some_and(|value| same(value, wanted)))
}

/// JSON equality, numbers by value as Postgres compares them.
fn same(value: &Value, wanted: &Value) -> bool {
    match (value, wanted) {
        (Value::Number(a), Value::Number(b)) => a.as_f64() == b.as_f64(),
        _ => value == wanted,
    }
}

/// The entity tags an `If-Match` header lists, unquoted; `None` without the
/// header. `*` matches any tag.
pub(crate) fn if_match(headers: &HeaderMap) -> Result<Option<Vec<String>>, ApiError> {
    let Some(header) = headers.get(IF_MATCH) else {
        return Ok(None);
    };
    let header = header
        .to_str()
        .map_err(|_| ApiError::invalid_request("If-Match must be ASCII"))?;
    Ok(Some(
        header
            .split(',')
            .map(|tag| {
                tag.trim()
                    .trim_start_matches("W/")
                    .trim_matches('"')
                    .to_owned()
            })
            .filter(|tag| !tag.is_empty())
            .collect(),
    ))
}

/// Merge-patches the metadata of `object` `id` in the caller's transaction:
/// locks the row, checks `If-Match` against its current tag, applies
/// `patch`, checks the limit and writes. Returns the new metadata.
// r[impl metadata.write.patch]
// r[impl metadata.write.precondition]
pub(crate) async fn patch(
    conn: &mut Connection,
    object: Object,
    id: &str,
    headers: &HeaderMap,
    patch: &Value,
    limit: Limit,
) -> Result<Value, ApiError> {
    if !patch.is_object() {
        return Err(ApiError::invalid_request(
            "a metadata merge patch must be a JSON object",
        ));
    }
    let expected = if_match(headers)?;
    let mut metadata = stored::lock(conn, object, id)
        .await
        .map_err(|error| match error {
            konklav_store::StoreError::NotFound => ApiError::not_found(object.as_str()),
            other => other.into(),
        })?;
    if let Some(expected) = expected {
        let current = etag(&metadata);
        if !expected.iter().any(|tag| tag == "*" || *tag == current) {
            return Err(ApiError::new(
                ErrorCode::PreconditionFailed,
                format!(
                    "the {}'s metadata changed since it was read",
                    object.as_str()
                ),
            ));
        }
    }
    let before = metadata.clone();
    merge_patch(&mut metadata, patch);
    limit.check(&metadata)?;
    if metadata != before {
        stored::write(conn, object, id, &metadata).await?;
    }
    Ok(metadata)
}

/// The capability that manages `object` on the control plane, and so
/// lets a change-feed consumer see its metadata.
// r[impl metadata.feed]
#[must_use]
pub fn capability(object: Object) -> &'static str {
    use crate::capabilities::{AUTHZ, CLIENTS, INVITES, SUBJECTS, TENANTS};
    match object {
        Object::Subject | Object::Credential => SUBJECTS,
        Object::Tenant | Object::Membership => TENANTS,
        Object::Template | Object::Role | Object::Share => AUTHZ,
        Object::Invite => INVITES,
        Object::OidcClient => CLIENTS,
    }
}

/// The `ETag` header of a response showing `metadata`.
pub(crate) fn etag_header(metadata: &Value) -> [(axum::http::HeaderName, String); 1] {
    [(axum::http::header::ETAG, format!("\"{}\"", etag(metadata)))]
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    // r[verify metadata.write.patch]
    #[test]
    fn merge_patch_follows_rfc_7396() {
        // The examples of RFC 7396, appendix A, that start from an object.
        let cases = [
            (json!({"a": "b"}), json!({"a": "c"}), json!({"a": "c"})),
            (
                json!({"a": "b"}),
                json!({"b": "c"}),
                json!({"a": "b", "b": "c"}),
            ),
            (json!({"a": "b"}), json!({"a": null}), json!({})),
            (
                json!({"a": "b", "b": "c"}),
                json!({"a": null}),
                json!({"b": "c"}),
            ),
            (json!({"a": ["b"]}), json!({"a": "c"}), json!({"a": "c"})),
            (json!({"a": "c"}), json!({"a": ["b"]}), json!({"a": ["b"]})),
            (
                json!({"a": {"b": "c"}}),
                json!({"a": {"b": "d", "c": null}}),
                json!({"a": {"b": "d"}}),
            ),
            (
                json!({"a": [{"b": "c"}]}),
                json!({"a": [1]}),
                json!({"a": [1]}),
            ),
            (
                json!({"e": null}),
                json!({"a": 1}),
                json!({"e": null, "a": 1}),
            ),
            (
                json!({}),
                json!({"a": {"bb": {"ccc": null}}}),
                json!({"a": {"bb": {}}}),
            ),
        ];
        for (mut target, patch, expected) in cases {
            merge_patch(&mut target, &patch);
            assert_eq!(target, expected, "{patch}");
        }
    }

    // r[verify metadata.limit]
    #[test]
    fn the_limit_counts_compact_json() {
        let metadata = json!({"k": "x".repeat(10)});
        let size = serde_json::to_vec(&metadata).unwrap().len();
        assert!(check(&metadata, size).is_ok());
        let error = check(&metadata, size - 1).unwrap_err();
        assert_eq!(error.code, ErrorCode::MetadataTooLarge);
        assert_eq!(
            check(&json!([1]), 100).unwrap_err().code,
            ErrorCode::InvalidRequest
        );
    }

    #[test]
    fn equal_metadata_has_one_tag() {
        let a: Value = serde_json::from_str(r#"{"b": 1, "a": {"y": 2, "x": [1, 2]}}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"a": {"x": [1, 2], "y": 2}, "b": 1}"#).unwrap();
        assert_eq!(etag(&a), etag(&b));
        assert_ne!(etag(&a), etag(&json!({})));
        assert_eq!(etag(&a).len(), 32);
    }

    // r[verify metadata.filter]
    #[test]
    fn filters_take_only_scalars() {
        assert!(filter(Some(r#"{"tenant_id": "t", "n": 1, "b": true}"#)).is_ok());
        for refused in ["[]", r#"{"a": null}"#, r#"{"a": [1]}"#, r#"{"a": {}}"#, "x"] {
            assert!(filter(Some(refused)).is_err(), "{refused}");
        }
        let wanted = json!({"tenant_id": "t", "n": 1});
        assert!(matches(
            &json!({"tenant_id": "t", "n": 1.0, "x": 2}),
            Some(&wanted)
        ));
        assert!(!matches(
            &json!({"tenant_id": ["t"], "n": 1}),
            Some(&wanted)
        ));
        assert!(!matches(&json!({"n": 1}), Some(&wanted)));
    }
}
