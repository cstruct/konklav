//! Metadata: an opaque JSON object a relying system stores on an object.
//! Konklav never reads it. Each object's own module reads and writes it
//! with the rest of the row; this module locks and writes it alone, for
//! merge patches, and builds list filters.

use diesel::sql_types::{Jsonb, Text};
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use crate::{StoreError, StoreResult};

/// The kinds of object that carry metadata, named as `metadata.changed`
/// events name them. The `add_metadata` migration's triggers emit those
/// events for every write, whatever its path.
// r[impl metadata.objects]
// r[impl metadata.events]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Object {
    Subject,
    Credential,
    Invite,
    Tenant,
    Membership,
    Share,
    OidcClient,
    Template,
    Role,
}

impl Object {
    pub const ALL: [Self; 9] = [
        Self::Subject,
        Self::Credential,
        Self::Invite,
        Self::Tenant,
        Self::Membership,
        Self::Share,
        Self::OidcClient,
        Self::Template,
        Self::Role,
    ];

    /// The name events and errors use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Subject => "subject",
            Self::Credential => "credential",
            Self::Invite => "invite",
            Self::Tenant => "tenant",
            Self::Membership => "membership",
            Self::Share => "share",
            Self::OidcClient => "oidc_client",
            Self::Template => "template",
            Self::Role => "role",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|object| object.as_str() == value)
    }

    /// The table, and the condition selecting one row by `$1`.
    fn row(self) -> (&'static str, &'static str) {
        match self {
            Self::Subject => ("subject", "id = $1::uuid"),
            Self::Credential => ("credential", "id = $1::uuid"),
            Self::Invite => ("challenge", "id = $1::uuid and purpose = 'invite'"),
            Self::Tenant => ("tenant", "id = $1::uuid"),
            Self::Membership => ("membership", "id = $1::uuid"),
            Self::Share => ("share", "id = $1::uuid"),
            Self::OidcClient => ("oidc_client", "id = $1"),
            Self::Template => ("template", "id = $1::uuid"),
            Self::Role => ("role", "id = $1::uuid"),
        }
    }

    /// Whether writing the row stamps `updated_at`; challenges have none.
    fn stamps_update(self) -> bool {
        self != Self::Invite
    }
}

#[derive(diesel::QueryableByName)]
struct Row {
    #[diesel(sql_type = Jsonb)]
    metadata: serde_json::Value,
}

/// Locks the object's row until the transaction ends and returns its
/// metadata, so that checking a precondition and writing are atomic.
/// `id` is the object's id as text.
// r[impl metadata.write.precondition]
pub async fn lock(
    conn: &mut AsyncPgConnection,
    object: Object,
    id: &str,
) -> StoreResult<serde_json::Value> {
    let (table, condition) = object.row();
    diesel::sql_query(format!(
        "select metadata from {table} where {condition} for update"
    ))
    .bind::<Text, _>(id)
    .get_result::<Row>(conn)
    .await
    .map(|row| row.metadata)
    .map_err(|error| match error {
        diesel::result::Error::NotFound => StoreError::NotFound,
        // Not a UUID: no such object.
        diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::Unknown,
            ref info,
        ) if info.message().contains("invalid input syntax") => StoreError::NotFound,
        other => StoreError::Database(other),
    })
}

/// Replaces the object's metadata and nothing else (apart from when it was
/// last updated). History's triggers record the row version it replaces,
/// metadata included, as for any other write to a row history keeps.
// r[impl metadata.history]
pub async fn write(
    conn: &mut AsyncPgConnection,
    object: Object,
    id: &str,
    metadata: &serde_json::Value,
) -> StoreResult<()> {
    let (table, condition) = object.row();
    let stamp = if object.stamps_update() {
        ", updated_at = now()"
    } else {
        ""
    };
    let updated = diesel::sql_query(format!(
        "update {table} set metadata = $2{stamp} where {condition}"
    ))
    .bind::<Text, _>(id)
    .bind::<Jsonb, _>(metadata)
    .execute(conn)
    .await
    .map_err(StoreError::from_constraint)?;
    if updated == 0 {
        Err(StoreError::NotFound)
    } else {
        Ok(())
    }
}

/// An empty metadata object.
#[must_use]
pub fn empty() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}
