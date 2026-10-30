//! Signing in through OpenID providers (identity providers).
//!
//! Each configured provider gets a [`Provider`]: it discovers the provider's
//! endpoints, keeps its keys, builds authorization requests, exchanges
//! authorization codes and validates ID tokens. The HTTP flow around it is
//! in `federation_api`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

use crate::config::BrowserConfig;

/// How long discovery documents are trusted before being fetched again.
const METADATA_TTL: Duration = Duration::from_secs(3600);
/// The soonest the provider's keys are fetched again for an unknown `kid`.
const KEYS_MIN_REFRESH: Duration = Duration::from_secs(60);
/// Clock skew tolerated on `exp`, `iat` and `auth_time`.
const LEEWAY_SECONDS: u64 = 60;
/// The authentication method every federated session gets, whatever else
/// the provider's `amr` and `acr` are mapped to.
pub const FEDERATED_METHOD: &str = "fed";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FederationError {
    #[error("the identity provider could not be reached or answered badly: {0}")]
    Provider(String),
    #[error("the ID token is invalid: {0}")]
    InvalidIdToken(String),
    #[error("the login doesn't meet the provider's requirements: {0}")]
    RequirementsNotMet(&'static str),
}

/// A configured identity provider.
#[derive(Clone, Debug, Default)]
pub struct Settings {
    pub id: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub return_urls: Vec<String>,
    /// Provider `amr`/`acr` values and the Konklav methods they credit.
    pub methods: Vec<(String, String)>,
    pub require_acr: Option<String>,
    pub max_age: Option<u32>,
    pub session_lifetime: Option<chrono::Duration>,
    pub provisioning: Provisioning,
    /// Domains whose verified emails may link to the subject with that
    /// login identifier.
    pub link_verified_email_domains: Vec<String>,
    pub grants: Vec<crate::claim_mapping::Rule>,
    /// Keys used instead of the discovered ones.
    pub pinned_keys: Option<Arc<JwkSet>>,
    pub peering: bool,
    pub workloads: bool,
}

/// What happens when an account nobody linked signs in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Provisioning {
    /// Refuse it.
    #[default]
    Link,
    /// Create a subject for it.
    Create,
}

#[derive(Clone, Debug, Deserialize)]
struct Metadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    /// Only Konklav upstreams have these.
    #[serde(default)]
    konklav_peer_events_endpoint: Option<String>,
    #[serde(default)]
    konklav_peer_subjects_endpoint: Option<String>,
}

/// A page of an upstream's peer feed.
#[derive(Clone, Debug, Deserialize)]
pub struct PeerPage {
    pub events: Vec<PeerEvent>,
    pub next: i64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PeerEvent {
    pub cursor: i64,
    pub kind: String,
    /// The upstream subject; absent when every subject may be affected.
    #[serde(default)]
    pub subject: Option<String>,
}

/// The claims Konklav uses from a validated ID token.
#[derive(Clone, Debug, Deserialize)]
pub struct IdClaims {
    pub sub: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(default)]
    pub amr: Vec<String>,
    #[serde(default)]
    pub acr: Option<String>,
    #[serde(default)]
    pub auth_time: Option<i64>,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    azp: Option<String>,
    aud: serde_json::Value,
    /// Every claim, for claim mapping.
    #[serde(skip)]
    pub raw: serde_json::Value,
}

/// The values a login keeps between redirecting to the provider and the
/// provider redirecting back.
pub struct LoginRequest {
    pub nonce: String,
    pub code_verifier: String,
}

impl LoginRequest {
    #[must_use]
    pub fn generate() -> Self {
        Self {
            nonce: konklav_authn::generate_secret(),
            code_verifier: konklav_authn::generate_secret(),
        }
    }
}

pub struct Provider {
    pub settings: Settings,
    http: reqwest::Client,
    metadata: RwLock<Option<(Arc<Metadata>, Instant)>>,
    keys: RwLock<Option<(Arc<JwkSet>, Instant)>>,
}

impl Provider {
    #[must_use]
    pub fn new(settings: Settings, http: reqwest::Client) -> Self {
        Self {
            settings,
            http,
            metadata: RwLock::new(None),
            keys: RwLock::new(None),
        }
    }

    async fn metadata(&self) -> Result<Arc<Metadata>, FederationError> {
        if let Some((metadata, fetched)) = &*self.metadata.read().await
            && fetched.elapsed() < METADATA_TTL
        {
            return Ok(metadata.clone());
        }
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.settings.issuer.trim_end_matches('/')
        );
        let metadata: Metadata = self.get_json(&url).await?;
        if metadata.issuer != self.settings.issuer {
            return Err(FederationError::Provider(format!(
                "discovery names issuer {}, not {}",
                metadata.issuer, self.settings.issuer
            )));
        }
        let metadata = Arc::new(metadata);
        *self.metadata.write().await = Some((metadata.clone(), Instant::now()));
        Ok(metadata)
    }

    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
    ) -> Result<T, FederationError> {
        self.http
            .get(url)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|error| FederationError::Provider(error.to_string()))?
            .json()
            .await
            .map_err(|error| FederationError::Provider(error.to_string()))
    }

    /// The provider's keys, fetched again when `refresh` is set (an ID token
    /// named a key that isn't known yet).
    // r[impl federation.peer.pinning]
    async fn keys(&self, refresh: bool) -> Result<Arc<JwkSet>, FederationError> {
        if let Some(pinned) = &self.settings.pinned_keys {
            return Ok(pinned.clone());
        }
        if !refresh && let Some((keys, _)) = &*self.keys.read().await {
            return Ok(keys.clone());
        }
        // Refreshes wait for each other and happen at most once per
        // KEYS_MIN_REFRESH, so tokens naming unknown keys can't make
        // Konklav fetch the provider's keys on every request.
        // r[impl federation.jwks-refresh]
        let mut cached = self.keys.write().await;
        if let Some((keys, fetched)) = &*cached
            && (!refresh || fetched.elapsed() < KEYS_MIN_REFRESH)
        {
            return Ok(keys.clone());
        }
        let metadata = self.metadata().await?;
        let keys: Arc<JwkSet> = Arc::new(self.get_json(&metadata.jwks_uri).await?);
        *cached = Some((keys.clone(), Instant::now()));
        Ok(keys)
    }

    /// The URL to send the browser to.
    // r[impl federation.idp.code-flow]
    pub async fn authorization_url(
        &self,
        state: &str,
        request: &LoginRequest,
    ) -> Result<String, FederationError> {
        let metadata = self.metadata().await?;
        let scopes = if self.settings.scopes.is_empty() {
            "openid email".to_owned()
        } else {
            self.settings.scopes.join(" ")
        };
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(request.code_verifier.as_bytes()));
        let mut params = vec![
            ("response_type", "code".to_owned()),
            ("client_id", self.settings.client_id.clone()),
            ("redirect_uri", self.settings.redirect_uri.clone()),
            ("scope", scopes),
            ("state", state.to_owned()),
            ("nonce", request.nonce.clone()),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256".to_owned()),
        ];
        if let Some(acr) = &self.settings.require_acr {
            params.push(("acr_values", acr.clone()));
        }
        if let Some(max_age) = self.settings.max_age {
            params.push(("max_age", max_age.to_string()));
        }
        reqwest::Url::parse_with_params(&metadata.authorization_endpoint, &params)
            .map(String::from)
            .map_err(|error| FederationError::Provider(error.to_string()))
    }

    /// Exchanges an authorization code for the provider's ID token.
    pub async fn exchange(
        &self,
        code: &str,
        code_verifier: &str,
    ) -> Result<String, FederationError> {
        #[derive(Deserialize)]
        struct Tokens {
            id_token: String,
        }
        let metadata = self.metadata().await?;
        let tokens: Tokens = self
            .http
            .post(&metadata.token_endpoint)
            .basic_auth(&self.settings.client_id, Some(&self.settings.client_secret))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", &self.settings.redirect_uri),
                ("code_verifier", code_verifier),
            ])
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|error| FederationError::Provider(error.to_string()))?
            .json()
            .await
            .map_err(|error| FederationError::Provider(error.to_string()))?;
        Ok(tokens.id_token)
    }

    /// Posts to a peer endpoint as this instance's client.
    async fn peer_post(
        &self,
        endpoint: Option<&String>,
        form: &[(&str, &str)],
    ) -> Result<reqwest::Response, FederationError> {
        let endpoint = endpoint.ok_or_else(|| {
            FederationError::Provider("the provider doesn't offer peering".into())
        })?;
        self.http
            .post(endpoint)
            .basic_auth(&self.settings.client_id, Some(&self.settings.client_secret))
            .form(form)
            .send()
            .await
            .map_err(|error| FederationError::Provider(error.to_string()))
    }

    /// The upstream's peer feed after `after`.
    pub async fn peer_events(&self, after: i64) -> Result<PeerPage, FederationError> {
        let metadata = self.metadata().await?;
        let after = after.to_string();
        self.peer_post(
            metadata.konklav_peer_events_endpoint.as_ref(),
            &[("after", &after)],
        )
        .await?
        .error_for_status()
        .map_err(|error| FederationError::Provider(error.to_string()))?
        .json()
        .await
        .map_err(|error| FederationError::Provider(error.to_string()))
    }

    /// The upstream subject's current claims, with `active`, or None if the
    /// upstream doesn't know it for this client.
    pub async fn peer_subject(
        &self,
        subject: &str,
    ) -> Result<Option<serde_json::Value>, FederationError> {
        let metadata = self.metadata().await?;
        let response = self
            .peer_post(
                metadata.konklav_peer_subjects_endpoint.as_ref(),
                &[("subject", subject)],
            )
            .await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        response
            .error_for_status()
            .map_err(|error| FederationError::Provider(error.to_string()))?
            .json()
            .await
            .map(Some)
            .map_err(|error| FederationError::Provider(error.to_string()))
    }

    /// Validates an ID token issued for this login.
    // r[impl federation.idp.id-token]
    pub async fn verify(&self, id_token: &str, nonce: &str) -> Result<IdClaims, FederationError> {
        let invalid = |reason: &str| FederationError::InvalidIdToken(reason.to_owned());
        let header = jsonwebtoken::decode_header(id_token).map_err(|e| invalid(&e.to_string()))?;
        if !matches!(
            header.alg,
            Algorithm::RS256
                | Algorithm::RS384
                | Algorithm::RS512
                | Algorithm::PS256
                | Algorithm::PS384
                | Algorithm::PS512
                | Algorithm::ES256
                | Algorithm::ES384
                | Algorithm::EdDSA
        ) {
            return Err(invalid("only asymmetric algorithms are accepted"));
        }
        let kid = header.kid.as_deref();
        let mut keys = self.keys(false).await?;
        if kid.is_some_and(|kid| keys.find(kid).is_none()) {
            keys = self.keys(true).await?;
        }
        let jwk = match kid {
            Some(kid) => keys.find(kid),
            // Without a kid, only a provider with a single key is unambiguous.
            None if keys.keys.len() == 1 => keys.keys.first(),
            None => None,
        }
        .ok_or_else(|| invalid("signed with an unknown key"))?;
        let key = DecodingKey::from_jwk(jwk).map_err(|e| invalid(&e.to_string()))?;
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&self.settings.issuer]);
        validation.set_audience(&[&self.settings.client_id]);
        validation.set_required_spec_claims(&["exp", "iat", "iss", "aud", "sub"]);
        validation.leeway = LEEWAY_SECONDS;
        let raw = jsonwebtoken::decode::<serde_json::Value>(id_token, &key, &validation)
            .map_err(|e| invalid(&e.to_string()))?
            .claims;
        let mut claims: IdClaims =
            serde_json::from_value(raw.clone()).map_err(|e| invalid(&e.to_string()))?;
        claims.raw = raw;
        let audiences = match &claims.aud {
            serde_json::Value::Array(values) => values.len(),
            _ => 1,
        };
        // A token for several audiences must name this client as its party.
        if (audiences > 1 || claims.azp.is_some())
            && claims.azp.as_deref() != Some(&self.settings.client_id)
        {
            return Err(invalid("issued to another party"));
        }
        if claims.nonce.as_deref() != Some(nonce) {
            return Err(invalid("the nonce doesn't match this login"));
        }
        Ok(claims)
    }

    /// Validates a token the provider issued to a workload, for the JWT
    /// bearer grant: signed with the provider's keys, issued by it, for one
    /// of `audiences`, unexpired. Returns its `sub`.
    pub async fn verify_assertion(
        &self,
        token: &str,
        audiences: &[String],
    ) -> Result<String, FederationError> {
        #[derive(Deserialize)]
        struct Assertion {
            sub: String,
        }
        let invalid = |reason: &str| FederationError::InvalidIdToken(reason.to_owned());
        let header = jsonwebtoken::decode_header(token).map_err(|e| invalid(&e.to_string()))?;
        if matches!(
            header.alg,
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
        ) {
            return Err(invalid("only asymmetric algorithms are accepted"));
        }
        let kid = header.kid.as_deref();
        let mut keys = self.keys(false).await?;
        if kid.is_some_and(|kid| keys.find(kid).is_none()) {
            keys = self.keys(true).await?;
        }
        let jwk = match kid {
            Some(kid) => keys.find(kid),
            None if keys.keys.len() == 1 => keys.keys.first(),
            None => None,
        }
        .ok_or_else(|| invalid("signed with an unknown key"))?;
        let key = DecodingKey::from_jwk(jwk).map_err(|e| invalid(&e.to_string()))?;
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&self.settings.issuer]);
        validation.set_audience(audiences);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.leeway = LEEWAY_SECONDS;
        Ok(jsonwebtoken::decode::<Assertion>(token, &key, &validation)
            .map_err(|e| invalid(&e.to_string()))?
            .claims
            .sub)
    }

    /// Checks `acr` and authentication recency against the provider's
    /// requirements.
    // r[impl federation.methods]
    pub fn check_requirements(&self, claims: &IdClaims, now: i64) -> Result<(), FederationError> {
        if let Some(required) = &self.settings.require_acr
            && claims.acr.as_ref() != Some(required)
        {
            return Err(FederationError::RequirementsNotMet("acr"));
        }
        if let Some(max_age) = self.settings.max_age {
            let fresh = claims.auth_time.is_some_and(|auth_time| {
                now - auth_time <= i64::from(max_age) + LEEWAY_SECONDS.cast_signed()
            });
            if !fresh {
                return Err(FederationError::RequirementsNotMet("max_age"));
            }
        }
        Ok(())
    }

    /// The Konklav authentication methods a login is credited with: the
    /// federated marker, plus whatever the provider's `amr` and `acr` map
    /// to. Unmapped values are ignored.
    #[must_use]
    pub fn methods(&self, claims: &IdClaims) -> Vec<String> {
        let mut methods = vec![FEDERATED_METHOD.to_owned()];
        let reported = claims.amr.iter().chain(claims.acr.iter());
        for value in reported {
            for (from, to) in &self.settings.methods {
                if from == value && !methods.contains(to) {
                    methods.push(to.clone());
                }
            }
        }
        methods
    }
}

/// The start of every federated credential identifier for `provider`.
#[must_use]
pub fn federated_prefix(provider: &str) -> String {
    format!("{provider}|")
}

/// The configured identity providers, by id.
#[derive(Default)]
pub struct Providers(HashMap<String, Arc<Provider>>);

impl Providers {
    /// Builds the providers from configuration. Every provider needs a
    /// client secret.
    // r[impl federation.idp.config]
    pub fn from_config(config: &BrowserConfig) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|error| error.to_string())?;
        let mut providers = HashMap::new();
        for provider in &config.identity_providers {
            let secret = config
                .identity_provider_secrets
                .iter()
                .find(|secret| secret.provider == provider.id)
                .ok_or_else(|| {
                    format!("identity provider `{}` has no client secret", provider.id)
                })?;
            if provider.return_urls.is_empty() {
                return Err(format!(
                    "identity provider `{}` has no return URLs",
                    provider.id
                ));
            }
            let settings = Settings {
                id: provider.id.clone(),
                issuer: provider.issuer.clone(),
                client_id: provider.client_id.clone(),
                client_secret: secret.client_secret.clone(),
                redirect_uri: provider.redirect_uri.clone(),
                scopes: provider.scopes.clone(),
                return_urls: provider.return_urls.clone(),
                methods: provider
                    .methods
                    .iter()
                    .map(|m| (m.from.clone(), m.to.clone()))
                    .collect(),
                require_acr: provider.require_acr.clone(),
                max_age: provider.max_age_seconds,
                session_lifetime: provider
                    .session_lifetime_seconds
                    .map(|s| chrono::Duration::seconds(i64::from(s))),
                provisioning: match provider.provisioning.as_deref() {
                    None | Some("link") => Provisioning::Link,
                    Some("create") => Provisioning::Create,
                    Some(other) => {
                        return Err(format!(
                            "identity provider `{}`: provisioning must be `link` or `create`, not `{other}`",
                            provider.id
                        ));
                    }
                },
                link_verified_email_domains: provider
                    .link_verified_email_domains
                    .iter()
                    .map(|domain| domain.to_lowercase())
                    .collect(),
                pinned_keys: provider
                    .pinned_jwks_file
                    .as_ref()
                    .map(|file| {
                        let text = std::fs::read_to_string(file)
                            .map_err(|error| format!("reading {file}: {error}"))?;
                        serde_json::from_str::<JwkSet>(&text)
                            .map(Arc::new)
                            .map_err(|error| format!("{file} is not a JWKS: {error}"))
                    })
                    .transpose()?,
                peering: provider.peering,
                workloads: provider.workloads,
                grants: provider
                    .grants
                    .iter()
                    .map(crate::claim_mapping::Rule::from_config)
                    .collect::<Result<_, _>>()
                    .map_err(|error| format!("identity provider `{}`: {error}", provider.id))?,
            };
            providers.insert(
                provider.id.clone(),
                Arc::new(Provider::new(settings, http.clone())),
            );
        }
        Ok(Self(providers))
    }

    /// Providers from settings already built, for tests and embedding.
    #[must_use]
    pub fn from_settings(settings: impl IntoIterator<Item = Settings>) -> Self {
        let http = reqwest::Client::new();
        Self(
            settings
                .into_iter()
                .map(|s| (s.id.clone(), Arc::new(Provider::new(s, http.clone()))))
                .collect(),
        )
    }

    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Arc<Provider>> {
        self.0.get(id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Arc<Provider>> {
        self.0.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(methods: &[(&str, &str)]) -> Provider {
        Provider::new(
            Settings {
                id: "ops".into(),
                issuer: "https://ops.example".into(),
                client_id: "prod".into(),
                client_secret: "secret".into(),
                redirect_uri: "https://prod.example/v1/login/oidc/ops/callback".into(),
                scopes: vec![],
                return_urls: vec!["https://app.example/".into()],
                methods: methods
                    .iter()
                    .map(|(a, b)| ((*a).into(), (*b).into()))
                    .collect(),
                require_acr: Some("urn:hwk".into()),
                max_age: Some(300),
                ..Settings::default()
            },
            reqwest::Client::new(),
        )
    }

    fn claims(amr: &[&str], acr: Option<&str>, auth_time: Option<i64>) -> IdClaims {
        IdClaims {
            sub: "a".into(),
            email: None,
            email_verified: None,
            amr: amr.iter().map(|s| (*s).into()).collect(),
            acr: acr.map(Into::into),
            auth_time,
            nonce: None,
            azp: None,
            aud: serde_json::json!("prod"),
            raw: serde_json::Value::Null,
        }
    }

    #[test]
    fn only_mapped_methods_are_credited() {
        let provider = provider(&[("hwk", "hwk"), ("urn:hwk", "hwk"), ("pwd", "pwd")]);
        assert_eq!(
            provider.methods(&claims(&["pwd", "face"], Some("urn:hwk"), None)),
            ["fed", "pwd", "hwk"]
        );
        assert_eq!(provider.methods(&claims(&["face"], None, None)), ["fed"]);
    }

    #[test]
    fn requirements_need_the_acr_and_a_recent_authentication() {
        let provider = provider(&[]);
        let now = 10_000;
        assert_eq!(
            provider.check_requirements(&claims(&[], Some("urn:hwk"), Some(now - 100)), now),
            Ok(())
        );
        assert_eq!(
            provider.check_requirements(&claims(&[], Some("urn:pwd"), Some(now)), now),
            Err(FederationError::RequirementsNotMet("acr"))
        );
        assert_eq!(
            provider.check_requirements(&claims(&[], Some("urn:hwk"), Some(now - 1000)), now),
            Err(FederationError::RequirementsNotMet("max_age"))
        );
        assert_eq!(
            provider.check_requirements(&claims(&[], Some("urn:hwk"), None), now),
            Err(FederationError::RequirementsNotMet("max_age"))
        );
    }
}
