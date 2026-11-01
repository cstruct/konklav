//! OIDC clients: registrations at Konklav's OpenID provider.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde::{Deserialize, Serialize};

use konklav_core::SubjectId;

use crate::schema::oidc_client;
use crate::{StoreError, StoreResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientKind {
    /// Can keep a secret (a server).
    Confidential,
    /// Can't (a single-page or native app); PKCE alone protects it.
    Public,
}

impl ClientKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Confidential => "confidential",
            Self::Public => "public",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum IdTokenAlgorithm {
    #[default]
    #[serde(rename = "ES256")]
    Es256,
    #[serde(rename = "EdDSA")]
    EdDsa,
    #[serde(rename = "RS256")]
    Rs256,
}

impl IdTokenAlgorithm {
    fn as_str(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::EdDsa => "EdDSA",
            Self::Rs256 => "RS256",
        }
    }
}

/// What a client registration says, as written by the control plane.
// r[impl oidc.provider.clients]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientDefinition {
    pub kind: ClientKind,
    pub redirect_uris: Vec<String>,
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    pub audience: String,
    #[serde(default)]
    pub visible_groups: Vec<String>,
    #[serde(default)]
    pub login_url: Option<String>,
    #[serde(default)]
    pub id_token_alg: IdTokenAlgorithm,
    #[serde(default = "yes")]
    pub refresh: bool,
    /// The service principal the client gets tokens for with the client
    /// credentials grant.
    #[serde(default)]
    pub service_subject: Option<SubjectId>,
    /// Public keys for `private_key_jwt` client authentication, as a JWKS.
    #[serde(default)]
    pub jwks: Option<serde_json::Value>,
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    #[serde(default)]
    pub backchannel_logout_uri: Option<String>,
    /// Whether authorization requests must use PKCE. Only a confidential
    /// client may be registered without it.
    #[serde(default = "yes")]
    pub require_pkce: bool,
}

fn default_scopes() -> Vec<String> {
    vec!["openid".into()]
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OidcClient {
    pub id: String,
    #[serde(flatten)]
    pub definition: ClientDefinition,
    #[serde(skip)]
    pub secret_hash: Option<Vec<u8>>,
    pub has_secret: bool,
    pub disabled_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl std::ops::Deref for OidcClient {
    type Target = ClientDefinition;

    fn deref(&self) -> &ClientDefinition {
        &self.definition
    }
}

impl OidcClient {
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.disabled_at.is_none()
    }

    /// Registered redirect URIs match exactly.
    #[must_use]
    pub fn allows_redirect(&self, uri: &str) -> bool {
        self.redirect_uris.iter().any(|allowed| allowed == uri)
    }

    /// Whether `scope` may be requested. `tenant:<id>` needs `tenant`.
    #[must_use]
    pub fn allows_scope(&self, scope: &str) -> bool {
        let registered = if scope.starts_with("tenant:") {
            "tenant"
        } else {
            scope
        };
        self.scopes.iter().any(|s| s == registered)
    }

    /// Whether a global role key may appear in the client's `groups`.
    #[must_use]
    pub fn may_see_group(&self, key: &str) -> bool {
        self.visible_groups
            .iter()
            .any(|pattern| match pattern.strip_suffix('*') {
                Some(prefix) => key.starts_with(prefix),
                None => pattern == key,
            })
    }
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = oidc_client)]
struct Row {
    id: String,
    kind: String,
    secret_hash: Option<Vec<u8>>,
    redirect_uris: Vec<Option<String>>,
    scopes: Vec<Option<String>>,
    audience: String,
    visible_groups: Vec<Option<String>>,
    login_url: Option<String>,
    id_token_alg: String,
    refresh: bool,
    disabled_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    service_subject_id: Option<uuid::Uuid>,
    jwks: Option<serde_json::Value>,
    post_logout_redirect_uris: Vec<Option<String>>,
    backchannel_logout_uri: Option<String>,
    require_pkce: bool,
}

impl From<Row> for OidcClient {
    fn from(row: Row) -> Self {
        let list = |values: Vec<Option<String>>| values.into_iter().flatten().collect();
        Self {
            id: row.id,
            definition: ClientDefinition {
                kind: if row.kind == "public" {
                    ClientKind::Public
                } else {
                    ClientKind::Confidential
                },
                redirect_uris: list(row.redirect_uris),
                scopes: list(row.scopes),
                audience: row.audience,
                visible_groups: list(row.visible_groups),
                login_url: row.login_url,
                id_token_alg: match row.id_token_alg.as_str() {
                    "EdDSA" => IdTokenAlgorithm::EdDsa,
                    "RS256" => IdTokenAlgorithm::Rs256,
                    _ => IdTokenAlgorithm::Es256,
                },
                refresh: row.refresh,
                service_subject: row.service_subject_id.map(Into::into),
                jwks: row.jwks,
                post_logout_redirect_uris: list(row.post_logout_redirect_uris),
                backchannel_logout_uri: row.backchannel_logout_uri,
                require_pkce: row.require_pkce,
            },
            has_secret: row.secret_hash.is_some(),
            secret_hash: row.secret_hash,
            disabled_at: row.disabled_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

fn nullable(values: &[String]) -> Vec<Option<String>> {
    values.iter().cloned().map(Some).collect()
}

/// Creates or replaces a client's registration, keeping its secret and
/// re-enabling it.
pub async fn put(
    conn: &mut AsyncPgConnection,
    id: &str,
    definition: &ClientDefinition,
) -> StoreResult<OidcClient> {
    let values = (
        oidc_client::kind.eq(definition.kind.as_str()),
        oidc_client::redirect_uris.eq(nullable(&definition.redirect_uris)),
        oidc_client::scopes.eq(nullable(&definition.scopes)),
        oidc_client::audience.eq(&definition.audience),
        oidc_client::visible_groups.eq(nullable(&definition.visible_groups)),
        oidc_client::login_url.eq(&definition.login_url),
        oidc_client::id_token_alg.eq(definition.id_token_alg.as_str()),
        oidc_client::refresh.eq(definition.refresh),
        oidc_client::service_subject_id.eq(definition.service_subject.map(uuid::Uuid::from)),
        oidc_client::jwks.eq(&definition.jwks),
        oidc_client::post_logout_redirect_uris.eq(nullable(&definition.post_logout_redirect_uris)),
        oidc_client::backchannel_logout_uri.eq(&definition.backchannel_logout_uri),
        oidc_client::require_pkce.eq(definition.require_pkce),
    );
    diesel::insert_into(oidc_client::table)
        .values((oidc_client::id.eq(id), values.clone()))
        .on_conflict(oidc_client::id)
        .do_update()
        .set((
            values,
            oidc_client::disabled_at.eq(None::<DateTime<Utc>>),
            oidc_client::updated_at.eq(diesel::dsl::now),
        ))
        .returning(Row::as_returning())
        .get_result(conn)
        .await
        .map(OidcClient::from)
        .map_err(StoreError::from_constraint)
}

pub async fn get(conn: &mut AsyncPgConnection, id: &str) -> StoreResult<OidcClient> {
    oidc_client::table
        .find(id)
        .select(Row::as_select())
        .first(conn)
        .await
        .optional()?
        .map(OidcClient::from)
        .ok_or(StoreError::NotFound)
}

pub async fn list(conn: &mut AsyncPgConnection) -> StoreResult<Vec<OidcClient>> {
    Ok(oidc_client::table
        .order(oidc_client::id.asc())
        .select(Row::as_select())
        .load(conn)
        .await?
        .into_iter()
        .map(OidcClient::from)
        .collect())
}

pub async fn set_secret_hash(
    conn: &mut AsyncPgConnection,
    id: &str,
    hash: &[u8],
) -> StoreResult<()> {
    let updated = diesel::update(oidc_client::table.find(id))
        .set((
            oidc_client::secret_hash.eq(hash),
            oidc_client::updated_at.eq(diesel::dsl::now),
        ))
        .execute(conn)
        .await?;
    if updated == 0 {
        return Err(StoreError::NotFound);
    }
    Ok(())
}

/// Disables a client. Returns whether it was enabled.
pub async fn disable(conn: &mut AsyncPgConnection, id: &str) -> StoreResult<bool> {
    let updated = diesel::update(oidc_client::table.find(id))
        .filter(oidc_client::disabled_at.is_null())
        .set(oidc_client::disabled_at.eq(diesel::dsl::now))
        .execute(conn)
        .await?;
    Ok(updated > 0)
}
