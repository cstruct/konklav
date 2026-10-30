//! Konklav as an OpenID provider: the ID-token key, ID tokens and the
//! claims Konklav can serve.

use std::path::Path;

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use konklav_core::SubjectId;
use konklav_store::credentials::{self, Credential, CredentialData};
use konklav_store::oidc_clients::{IdTokenAlgorithm, OidcClient};
use konklav_store::sessions::Session;
use konklav_store::{Connection, roles, tenants};
use konklav_token::Jwk;
use p256::pkcs8::DecodePrivateKey;
use serde::Serialize;
use tracing::Instrument;

use crate::AuthContext;
use crate::config::OidcProvider as OidcProviderConfig;
use crate::error::{ApiError, ErrorCode};

/// `acr` for sessions authenticated with one method, and with two or more.
pub const ACR_SINGLE: &str = "urn:konklav:acr:1";
pub const ACR_MULTI: &str = "urn:konklav:acr:2";

pub struct OpenIdProvider {
    key: EncodingKey,
    pub jwk: Jwk,
    /// The RSA key for `RS256`, when one is configured.
    rsa: Option<(EncodingKey, Jwk)>,
    pub login_url: String,
    pub jwks_uri: String,
}

impl OpenIdProvider {
    /// Loads the provider from configuration and the ID-token key file.
    // r[impl oidc.provider.algorithms]
    pub fn load(config: &OidcProviderConfig, issuer: &str) -> Result<Self, String> {
        let pem = std::fs::read_to_string(Path::new(&config.id_token_key_file))
            .map_err(|error| format!("reading {}: {error}", config.id_token_key_file))?;
        let provider = Self::from_pem(
            &pem,
            config.login_url.clone(),
            config.jwks_uri.clone().unwrap_or_else(|| {
                format!("{}/.well-known/jwks.json", issuer.trim_end_matches('/'))
            }),
        )?;
        match &config.rsa_key_file {
            Some(file) => {
                let pem = std::fs::read_to_string(Path::new(file))
                    .map_err(|error| format!("reading {file}: {error}"))?;
                provider.with_rsa_pem(&pem)
            }
            None => Ok(provider),
        }
    }

    /// Adds an RSA key for `RS256` ID tokens, from PKCS#8 PEM.
    // r[impl oidc.provider.algorithms]
    pub fn with_rsa_pem(mut self, pem: &str) -> Result<Self, String> {
        let invalid = |error: &dyn std::fmt::Display| {
            format!("the RSA key must be a PKCS#8 RSA key of at least 2048 bits: {error}")
        };
        let (label, der) =
            p256::pkcs8::der::SecretDocument::from_pem(pem).map_err(|error| invalid(&error))?;
        if label != "PRIVATE KEY" {
            return Err(invalid(&format!("a `{label}` PEM block")));
        }
        let pair =
            aws_lc_rs::rsa::KeyPair::from_pkcs8(der.as_bytes()).map_err(|error| invalid(&error))?;
        if pair.public_modulus_len() < 256 {
            return Err(invalid(&format!(
                "it has {} bits",
                pair.public_modulus_len() * 8
            )));
        }
        let public = aws_lc_rs::rsa::PublicKeyComponents::<Vec<u8>>::from(
            aws_lc_rs::signature::KeyPair::public_key(&pair),
        );
        let key = EncodingKey::from_rsa_pem(pem.as_bytes()).map_err(|error| invalid(&error))?;
        self.rsa = Some((key, Jwk::rs256(&public.n, &public.e)));
        Ok(self)
    }

    /// The `alg`s of the ID-token keys this provider has.
    #[must_use]
    pub fn algorithms(&self) -> Vec<&'static str> {
        let mut algorithms = vec!["ES256", "EdDSA"];
        if self.rsa.is_some() {
            algorithms.push("RS256");
        }
        algorithms
    }

    /// The keys this provider signs with besides access-token keys, for
    /// JWKS.
    #[must_use]
    pub fn jwks(&self) -> Vec<Jwk> {
        std::iter::once(self.jwk.clone())
            .chain(self.rsa.as_ref().map(|(_, jwk)| jwk.clone()))
            .collect()
    }

    pub fn from_pem(pem: &str, login_url: String, jwks_uri: String) -> Result<Self, String> {
        let secret = p256::SecretKey::from_pkcs8_pem(pem)
            .map_err(|error| format!("the ID-token key must be a PKCS#8 P-256 key: {error}"))?;
        let point = p256::EncodedPoint::from(secret.public_key());
        let (x, y) = point
            .x()
            .zip(point.y())
            .ok_or("the ID-token key has no coordinates")?;
        Ok(Self {
            key: EncodingKey::from_ec_pem(pem.as_bytes()).map_err(|error| error.to_string())?,
            jwk: Jwk::es256(x, y),
            rsa: None,
            login_url,
            jwks_uri,
        })
    }
}

/// The `acr` of a session: how many authentication methods it holds,
/// counting an identity-provider login with what the provider was credited.
#[must_use]
pub fn acr(session: &Session) -> &'static str {
    let methods = session
        .amr
        .iter()
        .filter(|method| *method != crate::federation::FEDERATED_METHOD)
        .count();
    if methods >= 2 { ACR_MULTI } else { ACR_SINGLE }
}

/// Whether a session satisfies the `acr_values` a client asked for: any of
/// the requested levels at or below the session's.
#[must_use]
pub fn satisfies_acr(session: &Session, requested: &str) -> bool {
    let level = acr(session);
    requested
        .split_whitespace()
        .any(|value| value == ACR_SINGLE || (value == ACR_MULTI && level == ACR_MULTI))
}

/// The claims Konklav holds for a session's subject, for the scopes
/// granted.
// r[impl oidc.provider.claims]
#[derive(Default, Serialize)]
pub struct Claims {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<String>>,
}

pub async fn claims(
    conn: &mut Connection,
    client: &OidcClient,
    scopes: &[String],
    subject: SubjectId,
    credential: &Credential,
) -> Result<Claims, ApiError> {
    let wants = |scope: &str| scopes.iter().any(|s| s == scope);
    let mut claims = Claims::default();
    // The credential signed in with first, then the subject's others, so a
    // phone number reaches a client after a password sign-in too.
    let others = if (wants("email") && email_of(credential).is_none())
        || (wants("phone") && phone_of(credential).is_none())
    {
        credentials::list_for_subject(conn, subject)
            .await?
            .into_iter()
            .filter(|c| c.is_active() && c.id != credential.id)
            .collect()
    } else {
        Vec::new()
    };
    let candidates = || std::iter::once(credential).chain(others.iter());
    if wants("email") {
        // A verified address wins, then the sign-in credential's.
        let found = candidates()
            .filter_map(email_of)
            .find(|(_, verified)| *verified)
            .or_else(|| candidates().find_map(email_of));
        if let Some((email, verified)) = found {
            claims.email = Some(email);
            claims.email_verified = Some(verified);
        }
    }
    if wants("phone")
        && let Some(phone) = candidates().find_map(phone_of)
    {
        claims.phone_number = Some(phone);
        claims.phone_number_verified = Some(true);
    }
    if wants("groups") {
        claims.groups = Some(groups(conn, client, subject).await?);
    }
    Ok(claims)
}

/// The email a credential holds and whether it was verified.
fn email_of(credential: &Credential) -> Option<(String, bool)> {
    match &credential.data {
        CredentialData::EmailLink => Some((credential.identifier.clone(), true)),
        CredentialData::Password(_) => Some((credential.identifier.clone(), false)),
        CredentialData::Federated(data) => data
            .email
            .clone()
            .map(|email| (email, data.email_verified == Some(true))),
        _ => None,
    }
}

/// The verified phone number of a phone-code credential.
fn phone_of(credential: &Credential) -> Option<String> {
    matches!(credential.data, CredentialData::PhoneOtp).then(|| credential.identifier.clone())
}

/// The subject's global roles that the client may see.
// r[impl oidc.provider.groups]
async fn groups(
    conn: &mut Connection,
    client: &OidcClient,
    subject: SubjectId,
) -> Result<Vec<String>, ApiError> {
    let assigned: Vec<uuid::Uuid> = roles::global_assignments_of(conn, subject)
        .await?
        .into_iter()
        .map(|a| a.role_id)
        .collect();
    let mut groups: Vec<String> = roles::list(conn, tenants::ROOT)
        .await?
        .into_iter()
        .filter(|role| assigned.contains(&role.id))
        .map(|role| role.key)
        .filter(|key| client.may_see_group(key))
        .collect();
    groups.sort();
    groups.dedup();
    Ok(groups)
}

#[derive(Serialize)]
struct IdTokenClaims<'a> {
    iss: &'a str,
    sub: SubjectId,
    aud: &'a str,
    azp: &'a str,
    exp: i64,
    iat: i64,
    auth_time: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<&'a str>,
    amr: &'a [String],
    acr: &'static str,
    sid: konklav_core::SessionId,
    #[serde(flatten)]
    claims: &'a Claims,
}

/// Signs an ID token for `session` with the client's algorithm.
///
/// # Panics
///
/// Never in practice: the claims always serialize and the key always signs.
// r[impl oidc.provider.id-token]
pub fn id_token(
    auth: &AuthContext,
    provider: &OpenIdProvider,
    client: &OidcClient,
    session: &Session,
    nonce: Option<&str>,
    claims: &Claims,
) -> Result<String, ApiError> {
    let now = chrono::Utc::now();
    let expires = (now + auth.access_ttl).min(session.expires_at);
    let token = IdTokenClaims {
        iss: &auth.issuer,
        sub: session.subject_id,
        aud: &client.id,
        azp: &client.id,
        exp: expires.timestamp(),
        iat: now.timestamp(),
        auth_time: session.auth_time.timestamp(),
        nonce,
        amr: &session.amr,
        acr: acr(session),
        sid: session.id,
        claims,
    };
    sign_for(auth, provider, client, &token, None)
}

/// Signs `claims` with the client's algorithm, with an optional `typ`.
fn sign_for<T: Serialize>(
    auth: &AuthContext,
    provider: &OpenIdProvider,
    client: &OidcClient,
    claims: &T,
    typ: Option<&str>,
) -> Result<String, ApiError> {
    Ok(match client.id_token_alg {
        IdTokenAlgorithm::EdDsa => auth.signer.sign_json(claims),
        IdTokenAlgorithm::Es256 => {
            let mut header = Header::new(Algorithm::ES256);
            header.kid = Some(provider.jwk.kid.clone());
            if let Some(typ) = typ {
                header.typ = Some(typ.to_owned());
            }
            jsonwebtoken::encode(&header, claims, &provider.key).expect("tokens sign")
        }
        IdTokenAlgorithm::Rs256 => {
            // The key may have been removed from the configuration since
            // the client was registered for it.
            let Some((key, jwk)) = &provider.rsa else {
                return Err(ApiError::new(
                    ErrorCode::SigningKeyUnavailable,
                    "the client is registered for RS256, and no RSA key is configured",
                ));
            };
            let mut header = Header::new(Algorithm::RS256);
            header.kid = Some(jwk.kid.clone());
            if let Some(typ) = typ {
                header.typ = Some(typ.to_owned());
            }
            jsonwebtoken::encode(&header, claims, key).map_err(ApiError::internal)?
        }
    })
}

/// A back-channel logout token (OpenID Connect Back-Channel Logout 1.0).
pub fn logout_token(
    auth: &AuthContext,
    provider: &OpenIdProvider,
    client: &OidcClient,
    subject: SubjectId,
    session: konklav_core::SessionId,
) -> Result<String, ApiError> {
    let claims = serde_json::json!({
        "iss": auth.issuer,
        "aud": client.id,
        "iat": chrono::Utc::now().timestamp(),
        "exp": chrono::Utc::now().timestamp() + 120,
        "jti": uuid::Uuid::now_v7(),
        "sub": subject,
        "sid": session,
        "events": {"http://schemas.openid.net/event/backchannel-logout": {}},
    });
    sign_for(auth, provider, client, &claims, Some("logout+jwt"))
}

/// Attempts before an undeliverable logout token is dropped.
const LOGOUT_ATTEMPTS: i32 = 8;

/// Delivers due back-channel logout tokens. Returns how many were tried.
// r[impl oidc.provider.logout]
pub async fn deliver_logouts(
    state: &crate::AppState,
    http: &reqwest::Client,
) -> Result<usize, ApiError> {
    let Some(provider) = state.auth.oidc.as_ref() else {
        return Ok(0);
    };
    let mut conn = state.pool.get().await?;
    let pending = konklav_store::backchannel::lease(&mut conn, 50).await?;
    if pending.is_empty() {
        return Ok(0);
    }
    let span = tracing::info_span!("backchannel_logouts", count = pending.len());
    deliver_leased(state, provider, http, &mut conn, &pending)
        .instrument(span)
        .await?;
    Ok(pending.len())
}

async fn deliver_leased(
    state: &crate::AppState,
    provider: &OpenIdProvider,
    http: &reqwest::Client,
    conn: &mut konklav_store::Connection,
    pending: &[konklav_store::backchannel::Pending],
) -> Result<(), ApiError> {
    let delivered = |outcome| {
        crate::telemetry::metrics::count(
            &crate::telemetry::metrics::METRICS.logout_deliveries,
            "konklav.outcome",
            outcome,
        );
    };
    for logout in pending {
        let client = konklav_store::oidc_clients::get(conn, &logout.client_id).await?;
        let Some(uri) = &client.backchannel_logout_uri else {
            konklav_store::backchannel::complete(conn, logout.id).await?;
            continue;
        };
        let token = logout_token(
            &state.auth,
            provider,
            &client,
            logout.subject_id,
            logout.session_id,
        )?;
        let sent = crate::telemetry::http::send(
            http.post(uri).form(&[("logout_token", token)]),
            "backchannel_logout",
        )
        .await
        .and_then(reqwest::Response::error_for_status);
        match sent {
            Ok(_) => {
                delivered("delivered");
                konklav_store::backchannel::complete(conn, logout.id).await?;
            }
            Err(error) if logout.attempts + 1 >= LOGOUT_ATTEMPTS => {
                delivered("abandoned");
                tracing::warn!(client = %client.id, session = %logout.session_id, %error, "giving up on a back-channel logout");
                konklav_store::backchannel::complete(conn, logout.id).await?;
            }
            Err(error) => {
                delivered("retried");
                let backoff =
                    chrono::Duration::seconds(10 * 2_i64.pow(logout.attempts.unsigned_abs()));
                let retry_at = chrono::Utc::now() + backoff.min(chrono::Duration::hours(1));
                konklav_store::backchannel::retry(conn, logout.id, &error.to_string(), retry_at)
                    .await?;
            }
        }
    }
    Ok(())
}

/// Runs [`deliver_logouts`] forever.
///
/// # Panics
///
/// If the HTTP client can't be built, which only happens without TLS roots.
pub async fn deliver_logouts_forever(state: crate::AppState) {
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("an HTTP client");
    loop {
        if let Err(error) = deliver_logouts(&state, &http).await {
            tracing::warn!(?error, "delivering back-channel logouts failed");
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

/// The client (`aud`) and session (`sid`) of an ID token Konklav signed,
/// expired or not, as presented in `id_token_hint`.
pub async fn verify_own_id_token(
    conn: &mut Connection,
    auth: &AuthContext,
    provider: &OpenIdProvider,
    token: &str,
) -> Result<Option<(String, konklav_core::SessionId)>, ApiError> {
    #[derive(serde::Deserialize)]
    struct Hint {
        aud: String,
        sid: konklav_core::SessionId,
    }
    let now = chrono::Utc::now();
    let mut keys: Vec<Jwk> = konklav_store::signing_keys::list(conn)
        .await?
        .iter()
        .filter(|key| crate::keys::is_publishable(key, now, auth.access_ttl))
        .filter_map(crate::keys::to_verifying_key)
        .map(|key| Jwk::from_verifying_key(&key))
        .collect();
    keys.extend(provider.jwks());
    let Ok(header) = jsonwebtoken::decode_header(token) else {
        return Ok(None);
    };
    // The key decides the algorithm, not the token.
    let Some(jwk) = keys.iter().find(|key| {
        Some(&key.kid) == header.kid.as_ref()
            && serde_json::to_value(header.alg).is_ok_and(|alg| alg == key.alg.as_str())
    }) else {
        return Ok(None);
    };
    let Some(key) = serde_json::to_value(jwk)
        .ok()
        .and_then(|value| serde_json::from_value::<jsonwebtoken::jwk::Jwk>(value).ok())
        .and_then(|jwk| jsonwebtoken::DecodingKey::from_jwk(&jwk).ok())
    else {
        return Ok(None);
    };
    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.set_issuer(&[&auth.issuer]);
    validation.validate_aud = false;
    validation.validate_exp = false;
    validation.set_required_spec_claims(&["iss", "aud", "sid"]);
    Ok(jsonwebtoken::decode::<Hint>(token, &key, &validation)
        .ok()
        .map(|data| (data.claims.aud, data.claims.sid)))
}
