//! The claims hook: a relying system's endpoint that userinfo asks for
//! profile claims Konklav doesn't hold, such as `name`.
//!
//! Konklav never stores what the hook answers. Answers may be cached in
//! memory for a bounded time and number of entries, so a relying system
//! stays the system of record for profile data.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use konklav_core::{MembershipId, SubjectId, TenantId};
use reqwest::{StatusCode, header};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::config::{ClaimsHook as ClaimsHookConfig, ClaimsHookFailure};
use crate::error::{ApiError, ErrorCode};
use crate::oidc::OpenIdProvider;

/// The `typ` of a claims request.
pub const REQUEST_TYPE: &str = "konklav-claims-request+jwt";
/// How long a claims request is valid.
const REQUEST_LIFETIME_SECONDS: i64 = 60;

/// Scopes Konklav serves itself, which a hook can't take over.
const RESERVED_SCOPES: &[&str] = &[
    "openid",
    "email",
    "phone",
    "groups",
    "tenant",
    "offline_access",
];
/// Claims Konklav serves itself or that carry protocol meaning, which a
/// hook can't supply.
const RESERVED_CLAIMS: &[&str] = &[
    "iss",
    "sub",
    "aud",
    "azp",
    "exp",
    "iat",
    "nbf",
    "jti",
    "auth_time",
    "nonce",
    "amr",
    "acr",
    "sid",
    "at_hash",
    "c_hash",
    "email",
    "email_verified",
    "phone_number",
    "phone_number_verified",
    "groups",
    "active",
];

/// Refuses scopes and claims Konklav serves itself among `scopes`, claims
/// by scope that a hook or an identity provider would supply.
pub(crate) fn check_served(
    section: &str,
    scopes: &HashMap<String, Vec<String>>,
) -> Result<(), String> {
    for (scope, claims) in scopes {
        if RESERVED_SCOPES.contains(&scope.as_str()) || scope.starts_with("tenant:") {
            return Err(format!(
                "{section}: Konklav serves the `{scope}` scope itself"
            ));
        }
        if let Some(claim) = claims
            .iter()
            .find(|c| RESERVED_CLAIMS.contains(&c.as_str()))
        {
            return Err(format!(
                "{section}.{scope}: Konklav serves the `{claim}` claim itself"
            ));
        }
    }
    Ok(())
}

pub struct ClaimsHook {
    url: String,
    /// The claims of each scope the hook serves.
    scopes: BTreeMap<String, Vec<String>>,
    on_failure: ClaimsHookFailure,
    ttl: Duration,
    capacity: usize,
    http: reqwest::Client,
    cache: Mutex<HashMap<Key, Entry>>,
}

/// Who the claims are for, and which scopes.
pub struct ClaimsFor<'a> {
    pub subject: SubjectId,
    pub client: &'a str,
    pub tenant: Option<TenantId>,
    pub membership: Option<MembershipId>,
    /// The scopes granted to the client, of which the hook's are asked for.
    pub granted: &'a [String],
    /// Single claims the client asked for with the `claims` parameter.
    pub requested: &'a [String],
}

#[derive(Clone, Hash, PartialEq, Eq)]
struct Key {
    subject: SubjectId,
    client: String,
    tenant: Option<TenantId>,
    membership: Option<MembershipId>,
    scopes: Vec<String>,
    /// Single claims asked for beyond the scopes'.
    claims: Vec<String>,
}

struct Entry {
    claims: Map<String, Value>,
    inserted: Instant,
    expires: Instant,
}

// r[impl oidc.provider.claims-hook.request]
#[derive(Serialize)]
struct Request<'a> {
    iss: &'a str,
    aud: &'a str,
    iat: i64,
    exp: i64,
    jti: String,
    sub: SubjectId,
    client_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant: Option<TenantId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    membership: Option<MembershipId>,
    scopes: &'a [String],
    claims: Vec<&'a str>,
}

impl ClaimsHook {
    /// Builds the hook from configuration, refusing scopes and claims that
    /// Konklav serves itself.
    pub fn from_config(config: &ClaimsHookConfig) -> Result<Self, String> {
        reqwest::Url::parse(&config.url)
            .map_err(|error| format!("claims_hook.url `{}`: {error}", config.url))?;
        check_served("claims_hook.scopes", &config.scopes)?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms.into()))
            .build()
            .map_err(|error| error.to_string())?;
        Ok(Self {
            url: config.url.clone(),
            scopes: config.scopes.clone().into_iter().collect(),
            on_failure: config.on_failure.clone(),
            ttl: Duration::from_secs(config.cache_ttl_seconds.into()),
            capacity: config.cache_entries as usize,
            http,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// The scopes the hook serves, for discovery.
    pub fn scopes(&self) -> impl Iterator<Item = &str> {
        self.scopes.keys().map(String::as_str)
    }

    /// The scope `claim` is served under, if the hook serves it.
    pub fn scope_of(&self, claim: &str) -> Option<&str> {
        self.scopes
            .iter()
            .find(|(_, claims)| claims.iter().any(|c| c == claim))
            .map(|(scope, _)| scope.as_str())
    }

    /// The claims the hook can supply, for discovery.
    pub fn claims(&self) -> impl Iterator<Item = &str> {
        self.scopes.values().flatten().map(String::as_str)
    }

    /// The hook's claims for the granted scopes it serves: empty when none
    /// are granted, or when the hook fails and failures are omitted.
    // r[impl oidc.provider.claims-hook]
    // r[impl oidc.provider.claims-hook.failure]
    pub async fn fetch(
        &self,
        provider: &OpenIdProvider,
        issuer: &str,
        request: &ClaimsFor<'_>,
    ) -> Result<Map<String, Value>, ApiError> {
        let scopes: Vec<String> = request
            .granted
            .iter()
            .filter(|scope| self.scopes.contains_key(*scope))
            .cloned()
            .collect();
        let claims: Vec<String> = request
            .requested
            .iter()
            .filter(|claim| self.scope_of(claim).is_some())
            .filter(|claim| !self.claims_of(&scopes).any(|c| c == claim.as_str()))
            .cloned()
            .collect();
        if scopes.is_empty() && claims.is_empty() {
            return Ok(Map::new());
        }
        let key = Key {
            subject: request.subject,
            client: request.client.to_owned(),
            tenant: request.tenant,
            membership: request.membership,
            scopes,
            claims,
        };
        if let Some(claims) = self.cached(&key) {
            return Ok(claims);
        }
        match self.call(provider, issuer, &key).await {
            Ok((claims, max_age)) => {
                self.remember(key, &claims, max_age);
                Ok(claims)
            }
            Err(reason) => match self.on_failure {
                ClaimsHookFailure::Omit => {
                    tracing::warn!(%reason, "the claims hook failed; serving userinfo without its claims");
                    Ok(Map::new())
                }
                ClaimsHookFailure::Fail => {
                    tracing::warn!(%reason, "the claims hook failed; refusing userinfo");
                    Err(ApiError::new(
                        ErrorCode::ClaimsHookUnavailable,
                        "profile claims are unavailable",
                    ))
                }
            },
        }
    }

    /// Asks the hook, returning the claims it may supply and how long the
    /// answer may be cached for, if the hook limited it.
    async fn call(
        &self,
        provider: &OpenIdProvider,
        issuer: &str,
        key: &Key,
    ) -> Result<(Map<String, Value>, Option<Duration>), String> {
        let now = chrono::Utc::now().timestamp();
        let body = provider.sign_es256(
            &Request {
                iss: issuer,
                aud: &self.url,
                iat: now,
                exp: now + REQUEST_LIFETIME_SECONDS,
                jti: konklav_authn::generate_secret(),
                sub: key.subject,
                client_id: &key.client,
                tenant: key.tenant,
                membership: key.membership,
                scopes: &key.scopes,
                claims: self.wanted(key).collect(),
            },
            REQUEST_TYPE,
        );
        let call = self
            .http
            .post(&self.url)
            .header(header::CONTENT_TYPE, "application/jwt")
            .body(body);
        let response = crate::telemetry::http::send(call, "claims_hook")
            .await
            .map_err(|error| error.to_string())?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok((Map::new(), cache_limit(response.headers())));
        }
        if !response.status().is_success() {
            return Err(format!("answered {}", response.status()));
        }
        let max_age = cache_limit(response.headers());
        let Value::Object(answer) = response
            .json::<Value>()
            .await
            .map_err(|error| error.to_string())?
        else {
            return Err("the answer isn't a JSON object".into());
        };
        Ok((self.allowed(key, answer), max_age))
    }

    fn claims_of<'a>(&'a self, scopes: &'a [String]) -> impl Iterator<Item = &'a str> {
        scopes
            .iter()
            .filter_map(|scope| self.scopes.get(scope))
            .flatten()
            .map(String::as_str)
    }

    /// The claims of the key's scopes, then its single claims.
    fn wanted<'a>(&'a self, key: &'a Key) -> impl Iterator<Item = &'a str> {
        self.claims_of(&key.scopes)
            .chain(key.claims.iter().map(String::as_str))
    }

    /// Only the configured claims of granted scopes, and the single claims
    /// asked for.
    // r[impl oidc.provider.claims-hook.scopes]
    fn allowed(&self, key: &Key, answer: Map<String, Value>) -> Map<String, Value> {
        let allowed: Vec<&str> = self.wanted(key).collect();
        answer
            .into_iter()
            .filter(|(name, _)| allowed.contains(&name.as_str()))
            .collect()
    }

    // r[impl oidc.provider.claims-hook.cache]
    fn cached(&self, key: &Key) -> Option<Map<String, Value>> {
        let cache = self.cache.lock().ok()?;
        cache
            .get(key)
            .filter(|entry| entry.expires > Instant::now())
            .map(|entry| entry.claims.clone())
    }

    /// Caches an answer for the configured time to live, or less when the
    /// hook said so, making room by dropping expired entries and then the
    /// oldest.
    fn remember(&self, key: Key, claims: &Map<String, Value>, max_age: Option<Duration>) {
        let ttl = max_age.map_or(self.ttl, |max_age| max_age.min(self.ttl));
        if ttl.is_zero() || self.capacity == 0 {
            return;
        }
        let Ok(mut cache) = self.cache.lock() else {
            return;
        };
        let now = Instant::now();
        if cache.len() >= self.capacity && !cache.contains_key(&key) {
            cache.retain(|_, entry| entry.expires > now);
        }
        while cache.len() >= self.capacity && !cache.contains_key(&key) {
            let Some(oldest) = cache
                .iter()
                .min_by_key(|(_, entry)| entry.inserted)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            cache.remove(&oldest);
        }
        cache.insert(
            key,
            Entry {
                claims: claims.clone(),
                inserted: now,
                expires: now + ttl,
            },
        );
    }
}

/// How long `Cache-Control` lets an answer be cached: zero for `no-store`
/// or `no-cache`, `max-age` when given, and no limit otherwise.
fn cache_limit(headers: &header::HeaderMap) -> Option<Duration> {
    let value = headers.get(header::CACHE_CONTROL)?.to_str().ok()?;
    let mut limit = None;
    for directive in value.split(',').map(str::trim) {
        let directive = directive.to_ascii_lowercase();
        if directive == "no-store" || directive == "no-cache" {
            return Some(Duration::ZERO);
        }
        if let Some(seconds) = directive.strip_prefix("max-age=") {
            // An unreadable max-age is treated as no caching at all.
            limit = Some(Duration::from_secs(
                seconds.trim_matches('"').parse().unwrap_or(0),
            ));
        }
    }
    limit
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(value: &str) -> header::HeaderMap {
        let mut headers = header::HeaderMap::new();
        headers.insert(header::CACHE_CONTROL, value.parse().unwrap());
        headers
    }

    #[test]
    fn cache_control_can_limit_or_forbid_caching() {
        assert_eq!(cache_limit(&header::HeaderMap::new()), None);
        assert_eq!(
            cache_limit(&headers("private, max-age=30")),
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            cache_limit(&headers("max-age=30, no-store")),
            Some(Duration::ZERO)
        );
        assert_eq!(cache_limit(&headers("No-Cache")), Some(Duration::ZERO));
        assert_eq!(cache_limit(&headers("max-age=soon")), Some(Duration::ZERO));
    }

    fn hook(ttl: u32, entries: u32) -> ClaimsHook {
        ClaimsHook::from_config(&ClaimsHookConfig {
            url: "https://profiles.example/claims".into(),
            scopes: HashMap::from([("profile".into(), vec!["name".into()])]),
            timeout_ms: 1000,
            on_failure: ClaimsHookFailure::Omit,
            cache_ttl_seconds: ttl,
            cache_entries: entries,
        })
        .unwrap()
    }

    fn key(n: u128) -> Key {
        Key {
            subject: SubjectId::from(uuid::Uuid::from_u128(n)),
            client: "console".into(),
            tenant: None,
            membership: None,
            scopes: vec!["profile".into()],
            claims: Vec::new(),
        }
    }

    fn claims(name: &str) -> Map<String, Value> {
        Map::from_iter([("name".to_owned(), Value::from(name))])
    }

    #[test]
    fn hooks_cannot_take_over_konklavs_scopes_or_claims() {
        let config = |scope: &str, claim: &str| ClaimsHookConfig {
            url: "https://profiles.example/claims".into(),
            scopes: HashMap::from([(scope.into(), vec![claim.into()])]),
            timeout_ms: 1000,
            on_failure: ClaimsHookFailure::Omit,
            cache_ttl_seconds: 0,
            cache_entries: 1,
        };
        assert!(ClaimsHook::from_config(&config("email", "name")).is_err());
        assert!(ClaimsHook::from_config(&config("profile", "email")).is_err());
        assert!(ClaimsHook::from_config(&config("profile", "sub")).is_err());
        assert!(ClaimsHook::from_config(&config("profile", "name")).is_ok());
    }

    // r[verify oidc.provider.claims-hook.cache]
    #[test]
    fn the_cache_honours_its_ttl_the_answer_and_its_size() {
        let off = hook(0, 10);
        off.remember(key(1), &claims("Ada"), None);
        assert!(off.cached(&key(1)).is_none(), "a zero TTL caches nothing");

        let hook = hook(60, 2);
        hook.remember(key(1), &claims("Ada"), Some(Duration::ZERO));
        assert!(hook.cached(&key(1)).is_none(), "no-store isn't cached");
        hook.remember(key(1), &claims("Ada"), Some(Duration::from_secs(3600)));
        let expires = hook.cache.lock().unwrap()[&key(1)].expires;
        assert!(
            expires <= Instant::now() + Duration::from_secs(60),
            "an answer can't lengthen the TTL"
        );
        assert_eq!(hook.cached(&key(1)), Some(claims("Ada")));

        hook.remember(key(2), &claims("Bo"), None);
        hook.remember(key(3), &claims("Cy"), None);
        assert_eq!(hook.cache.lock().unwrap().len(), 2, "the size is bounded");
        assert!(hook.cached(&key(1)).is_none(), "the oldest goes first");
        assert_eq!(hook.cached(&key(3)), Some(claims("Cy")));
    }
}
