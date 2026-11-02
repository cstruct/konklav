use chrono::{DateTime, Utc};
use konklav_core::SubjectId;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum OidcClientKind {
    /// Can keep a secret (a server).
    Confidential,
    /// Can't (a single-page or native app); PKCE alone protects it.
    Public,
}

/// The algorithm a client's ID tokens are signed with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub enum IdTokenAlgorithm {
    #[default]
    #[serde(rename = "ES256")]
    Es256,
    #[serde(rename = "EdDSA")]
    EdDsa,
    /// Needs an RSA key (`oidc_provider.rsa_key_file`).
    #[serde(rename = "RS256")]
    Rs256,
}

/// What a client registration says.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct OidcClientDefinition {
    pub kind: OidcClientKind,
    /// Matched exactly; no fragments.
    pub redirect_uris: Vec<String>,
    /// Scopes the client may request; must include `openid`.
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    /// The audience of the client's access tokens; not Konklav's own.
    pub audience: String,
    /// Global role keys that may appear in the client's `groups` claim;
    /// a trailing `*` matches a prefix.
    #[serde(default)]
    pub visible_groups: Vec<String>,
    /// The client's own login page, instead of the provider's.
    #[serde(default)]
    pub login_url: Option<String>,
    #[serde(default)]
    pub id_token_alg: IdTokenAlgorithm,
    /// Whether the client may use the refresh token grant.
    #[serde(default = "yes")]
    pub refresh: bool,
    /// The service principal the client gets tokens for with the client
    /// credentials grant. Confidential clients only.
    #[serde(default)]
    pub service_subject: Option<SubjectId>,
    /// Public keys for `private_key_jwt` client authentication, as a JWKS.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
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

/// A registered OIDC client, without its secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct OidcClient {
    pub id: String,
    #[serde(flatten)]
    pub definition: OidcClientDefinition,
    /// Whether a secret has been issued.
    pub has_secret: bool,
    pub disabled_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A confidential client's new secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct OidcClientSecret {
    /// Shown only once; the previous secret stops working.
    pub client_secret: String,
}
