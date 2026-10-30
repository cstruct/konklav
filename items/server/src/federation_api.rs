//! Federated login and linking through identity providers.
//!
//! 1. `start` (login) or `link` (a signed-in subject adding an account)
//!    keeps `state`, `nonce` and the PKCE verifier as a challenge, binds it
//!    to the browser with a cookie, and sends the browser to the provider.
//! 2. The provider redirects to `callback`, which consumes the challenge,
//!    exchanges the code, validates the ID token and then either starts a
//!    session or links the account, redirecting to the return URL. Failures
//!    redirect there too, with an `error` parameter.

use axum::Json;
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use chrono::{Duration, Utc};
use diesel_async::AsyncConnection;
use konklav_authn::{generate_secret, hash_challenge_secret};
use konklav_core::{CredentialId, SubjectId};
use konklav_store::challenges::{self, Challenge, NewChallenge, Purpose};
use konklav_store::credentials::{
    self, CredentialData, CredentialKind, FederatedData, NewCredential, federated_identifier,
};
use konklav_store::subjects::{self, SubjectKind, SubjectState};
use konklav_store::{Connection, StoreError, sessions::Stage};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::claim_mapping;
use crate::error::{ApiError, ErrorCode};
use crate::federation::{FederationError, LoginRequest, Provider, Provisioning};
use crate::subject_api::{self, Client, Started};
use crate::{AppState, BrowserSettings};

const STATE_COOKIE: &str = "konklav_oidc";
const STATE_COOKIE_PATH: &str = "/v1/login/oidc";
/// Carries a partial session's access token from the callback to the page,
/// when the provider's sign-ins need local MFA.
const PARTIAL_COOKIE: &str = "konklav_partial";
const PARTIAL_COOKIE_PATH: &str = "/v1/login/oidc/partial";
const LOGIN_MINUTES: i64 = 10;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/login/oidc/{provider}/start", get(start))
        .route("/login/oidc/{provider}/callback", get(callback))
        .route("/login/oidc/partial", post(take_partial))
        .route("/credentials/oidc/{provider}/link", post(link))
}

#[derive(Serialize, Deserialize)]
struct Details {
    provider: String,
    nonce: String,
    code_verifier: String,
    return_to: String,
}

fn provider<'a>(state: &'a AppState, id: &str) -> Result<&'a Provider, ApiError> {
    state
        .auth
        .identity_providers
        .get(id)
        .map(AsRef::as_ref)
        .ok_or_else(|| ApiError::not_found("identity provider"))
}

fn browser(state: &AppState) -> Result<&BrowserSettings, ApiError> {
    state
        .auth
        .browser
        .as_ref()
        .ok_or_else(|| ApiError::invalid_request("browser clients are not enabled"))
}

/// The requested return URL if it is one of the provider's, else the first.
fn return_to(provider: &Provider, requested: Option<&str>) -> Result<String, ApiError> {
    let urls = &provider.settings.return_urls;
    match requested {
        None => Ok(urls[0].clone()),
        Some(url) if urls.iter().any(|allowed| allowed == url) => Ok(url.to_owned()),
        Some(_) => Err(ApiError::invalid_request("return_to is not allowed")),
    }
}

fn state_cookie(browser: &BrowserSettings, value: &str, max_age: i64) -> HeaderValue {
    let secure = if browser.secure_cookies {
        "; Secure"
    } else {
        ""
    };
    // Lax, because the provider's redirect back is a cross-site navigation.
    HeaderValue::from_str(&format!(
        "{STATE_COOKIE}={value}; Path={STATE_COOKIE_PATH}; Max-Age={max_age}; HttpOnly; SameSite=Lax{secure}"
    ))
    .expect("cookie header is ASCII")
}

fn partial_cookie(browser: &BrowserSettings, value: &str, max_age: i64) -> HeaderValue {
    let secure = if browser.secure_cookies {
        "; Secure"
    } else {
        ""
    };
    HeaderValue::from_str(&format!(
        "{PARTIAL_COOKIE}={value}; Path={PARTIAL_COOKIE_PATH}; Max-Age={max_age}; HttpOnly; SameSite=Strict{secure}"
    ))
    .expect("cookie header is ASCII")
}

/// `POST /v1/login/oidc/partial`: hands the page the partial access token a
/// federated sign-in left in a cookie, once, so it can complete MFA with
/// `POST /v1/login/mfa` as after a password login.
// r[impl federation.local-mfa]
async fn take_partial(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let browser = subject_api::check_browser_request(&state.auth, &headers)?.clone();
    let token = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .find_map(|pair| {
            let (name, value) = pair.trim().split_once('=')?;
            (name == PARTIAL_COOKIE).then(|| value.to_owned())
        })
        .ok_or_else(|| ApiError::new(ErrorCode::Unauthenticated, "no partial sign-in"))?;
    let mut conn = state.pool.get().await?;
    let (_, session) = subject_api::verify_access_token(&state, &mut conn, &token).await?;
    if session.stage != Stage::Partial {
        return Err(ApiError::invalid_request("the session has no pending MFA"));
    }
    let token = crate::issue::access_token(&mut conn, &state.auth, &session).await?;
    let mut response = Json(token).into_response();
    response
        .headers_mut()
        .append(header::SET_COOKIE, partial_cookie(&browser, "", 0));
    Ok(response)
}

fn read_state_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .find_map(|pair| {
            let (name, value) = pair.trim().split_once('=')?;
            (name == STATE_COOKIE).then(|| value.to_owned())
        })
}

/// Creates the login challenge and returns the provider URL and the
/// `state` the browser must bring back.
async fn begin(
    conn: &mut Connection,
    provider: &Provider,
    purpose: Purpose,
    subject: Option<SubjectId>,
    return_to: String,
) -> Result<(String, String), ApiError> {
    let id = uuid::Uuid::now_v7();
    let secret = generate_secret();
    let request = LoginRequest::generate();
    let details = Details {
        provider: provider.settings.id.clone(),
        nonce: request.nonce.clone(),
        code_verifier: request.code_verifier.clone(),
        return_to,
    };
    challenges::create(
        conn,
        NewChallenge {
            id,
            purpose,
            subject_id: subject,
            credential_id: None,
            mfa_factor_id: None,
            session_id: None,
            recipient: provider.settings.id.clone(),
            secret_hash: hash_challenge_secret(&id.to_string(), &secret),
            details: serde_json::to_value(&details).map_err(ApiError::internal)?,
            expires_at: Utc::now() + Duration::minutes(LOGIN_MINUTES),
        },
    )
    .await?;
    let state = format!("{id}.{secret}");
    let url = provider
        .authorization_url(&state, &request)
        .await
        .map_err(|error| ApiError::new(ErrorCode::Internal, error.to_string()))?;
    Ok((url, state))
}

#[derive(Deserialize)]
struct StartQuery {
    return_to: Option<String>,
}

/// `GET /v1/login/oidc/{provider}/start`
async fn start(
    State(state): State<AppState>,
    Path(provider_id): Path<String>,
    Query(query): Query<StartQuery>,
) -> Result<Response, ApiError> {
    let provider = provider(&state, &provider_id)?;
    let browser = browser(&state)?;
    let return_to = return_to(provider, query.return_to.as_deref())?;
    let mut conn = state.pool.get().await?;
    let (url, login) = begin(&mut conn, provider, Purpose::OidcLogin, None, return_to).await?;
    let mut response = Redirect::to(&url).into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        state_cookie(browser, &login, LOGIN_MINUTES * 60),
    );
    Ok(response)
}

#[derive(Deserialize)]
struct LinkRequest {
    return_to: Option<String>,
}

#[derive(Serialize)]
struct LinkStarted {
    authorization_url: String,
}

/// `POST /v1/credentials/oidc/{provider}/link`: for a signed-in subject. The
/// browser then navigates to `authorization_url`.
// r[impl federation.linking]
async fn link(
    State(state): State<AppState>,
    Path(provider_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<LinkRequest>,
) -> Result<Response, ApiError> {
    let provider = provider(&state, &provider_id)?;
    let browser = subject_api::check_browser_request(&state.auth, &headers)?;
    let return_to = return_to(provider, body.return_to.as_deref())?;
    let mut conn = state.pool.get().await?;
    let (_, session) = subject_api::authenticate(&state, &mut conn, &headers).await?;
    if session.stage == Stage::Partial {
        return Err(ApiError::new(ErrorCode::Forbidden, "complete MFA first"));
    }
    let (url, login) = begin(
        &mut conn,
        provider,
        Purpose::OidcLink,
        Some(session.subject_id),
        return_to,
    )
    .await?;
    let mut response = Json(LinkStarted {
        authorization_url: url,
    })
    .into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        state_cookie(browser, &login, LOGIN_MINUTES * 60),
    );
    Ok(response)
}

#[derive(Deserialize)]
struct CallbackQuery {
    state: Option<String>,
    code: Option<String>,
    error: Option<String>,
}

/// Why a federated login or link failed, as the `error` parameter of the
/// redirect back to the return URL.
#[derive(Clone, Copy, Debug)]
enum Failure {
    /// The provider reported an error, or couldn't be used.
    Provider,
    InvalidIdToken,
    RequirementsNotMet,
    /// No subject has this account, and the provider doesn't create them.
    NotLinked,
    /// The account is already linked to another subject.
    LinkedElsewhere,
}

impl Failure {
    fn code(self) -> &'static str {
        match self {
            Self::Provider => "provider_error",
            Self::InvalidIdToken => "invalid_id_token",
            Self::RequirementsNotMet => "requirements_not_met",
            Self::NotLinked => "account_not_linked",
            Self::LinkedElsewhere => "account_linked_elsewhere",
        }
    }
}

impl From<FederationError> for Failure {
    fn from(error: FederationError) -> Self {
        tracing::info!(%error, "federated login failed");
        match error {
            FederationError::Provider(_) => Self::Provider,
            FederationError::InvalidIdToken(_) => Self::InvalidIdToken,
            FederationError::RequirementsNotMet(_) => Self::RequirementsNotMet,
        }
    }
}

fn redirect(return_to: &str, param: (&str, &str), cookies: Vec<HeaderValue>) -> Response {
    let url = reqwest::Url::parse_with_params(return_to, [param])
        .map_or_else(|_| return_to.to_owned(), String::from);
    // 303 so the return page is fetched with GET.
    let mut response = (StatusCode::SEE_OTHER, [(header::LOCATION, url)]).into_response();
    for cookie in cookies {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    response
}

/// Finds and consumes the challenge `state` names, checking that this
/// browser started it.
async fn take_challenge(
    conn: &mut Connection,
    headers: &HeaderMap,
    provider_id: &str,
    state: Option<&str>,
) -> Result<(Challenge, Details), ApiError> {
    let invalid = || ApiError::invalid_request("unknown, expired or foreign login state");
    let state = state.ok_or_else(invalid)?;
    let cookie = read_state_cookie(headers).ok_or_else(invalid)?;
    if !bool::from(cookie.as_bytes().ct_eq(state.as_bytes())) {
        return Err(invalid());
    }
    let (id, secret) = state.split_once('.').ok_or_else(invalid)?;
    let id: uuid::Uuid = id.parse().map_err(|_| invalid())?;
    let challenge = challenges::get(conn, id).await.map_err(|_| invalid())?;
    let matches: bool = hash_challenge_secret(&id.to_string(), secret)
        .ct_eq(&challenge.secret_hash)
        .into();
    let purpose_ok = [Purpose::OidcLogin.as_str(), Purpose::OidcLink.as_str()]
        .contains(&challenge.purpose.as_str());
    if !matches || !purpose_ok || !challenge.is_usable(Utc::now()) {
        return Err(invalid());
    }
    let details: Details =
        serde_json::from_value(challenge.details.clone()).map_err(|_| invalid())?;
    if details.provider != provider_id || !challenges::consume(conn, id, Utc::now()).await? {
        return Err(invalid());
    }
    Ok((challenge, details))
}

/// `GET /v1/login/oidc/{provider}/callback`
// r[impl federation.session]
async fn callback(
    State(state): State<AppState>,
    Path(provider_id): Path<String>,
    Query(query): Query<CallbackQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let provider = provider(&state, &provider_id)?;
    let browser = browser(&state)?;
    let mut conn = state.pool.get().await?;
    let (challenge, details) =
        take_challenge(&mut conn, &headers, &provider_id, query.state.as_deref()).await?;
    let clear = state_cookie(browser, "", 0);
    let outcome = finish(&state, &mut conn, provider, &challenge, &details, &query).await;
    Ok(match outcome {
        Ok((param, mut cookies)) => {
            cookies.push(clear);
            redirect(&details.return_to, param, cookies)
        }
        Err(failure) => redirect(&details.return_to, ("error", failure.code()), vec![clear]),
    })
}

async fn finish(
    state: &AppState,
    conn: &mut Connection,
    provider: &Provider,
    challenge: &Challenge,
    details: &Details,
    query: &CallbackQuery,
) -> Result<((&'static str, &'static str), Vec<HeaderValue>), Failure> {
    if let Some(error) = &query.error {
        tracing::info!(provider = %provider.settings.id, %error, "identity provider refused the login");
        return Err(Failure::Provider);
    }
    let code = query.code.as_deref().ok_or(Failure::Provider)?;
    let id_token = provider.exchange(code, &details.code_verifier).await?;
    let claims = provider.verify(&id_token, &details.nonce).await?;
    provider.check_requirements(&claims, Utc::now().timestamp())?;
    let identifier = federated_identifier(&provider.settings.id, &claims.sub);
    let existing = credentials::find_active(conn, CredentialKind::Federated, &identifier)
        .await
        .map_err(|_| Failure::Provider)?;

    if challenge.purpose == Purpose::OidcLink.as_str() {
        let subject = challenge.subject_id.ok_or(Failure::Provider)?;
        match existing {
            Some(credential) if credential.subject_id != subject => {
                return Err(Failure::LinkedElsewhere);
            }
            Some(_) => {}
            None => {
                credentials::insert(
                    conn,
                    NewCredential {
                        id: CredentialId::new_v7(),
                        subject_id: subject,
                        identifier,
                        data: CredentialData::Federated(FederatedData {
                            provider: provider.settings.id.clone(),
                            subject: claims.sub.clone(),
                            email: claims.email.clone(),
                            email_verified: claims.email_verified,
                        }),
                        // r[impl federation.local-mfa]
                        mfa_factors_required: provider.settings.local_mfa_factors,
                        replaces: None,
                    },
                )
                .await
                .map_err(|_| Failure::LinkedElsewhere)?;
            }
        }
        return Ok((("linked", "true"), Vec::new()));
    }

    let credential = match existing {
        Some(credential) => credential,
        None => provision(conn, provider, &claims, identifier)
            .await
            .map_err(|error| {
                tracing::warn!(%error, "provisioning a federated subject failed");
                Failure::Provider
            })?
            .ok_or(Failure::NotLinked)?,
    };
    let subject = subjects::get(conn, credential.subject_id)
        .await
        .map_err(|_| Failure::NotLinked)?;
    if subject.state != SubjectState::Active || subject.kind != SubjectKind::Human {
        return Err(Failure::NotLinked);
    }
    let desired = claim_mapping::evaluate(&provider.settings.grants, &claims.raw);
    conn.transaction::<_, StoreError, _>(async |conn| {
        claim_mapping::apply(conn, &provider.settings.id, subject.id, &desired).await
    })
    .await
    .map_err(|error| {
        tracing::warn!(%error, "applying claim mapping failed");
        Failure::Provider
    })?;
    // r[impl federation.session-lifetime]
    let lifetime = provider
        .settings
        .session_lifetime
        .unwrap_or(state.auth.session_lifetime);
    let Started {
        session, refresh, ..
    } = subject_api::create_session(
        state,
        conn,
        &credential,
        provider.methods(&claims),
        Client::Browser,
        &[],
        lifetime,
    )
    .await
    .map_err(|_| Failure::Provider)?;
    signed_in(state, conn, &session, &refresh).await
}

/// The redirect parameter and cookies for a new federated session. One
/// that still needs MFA gets no refresh token: the page picks its partial
/// access token up from `POST /v1/login/oidc/partial`.
async fn signed_in(
    state: &AppState,
    conn: &mut Connection,
    session: &konklav_store::sessions::Session,
    refresh: &konklav_authn::RefreshToken,
) -> Result<((&'static str, &'static str), Vec<HeaderValue>), Failure> {
    let browser = state.auth.browser.as_ref().ok_or(Failure::Provider)?;
    if session.stage == Stage::Partial {
        let token = crate::issue::access_token(conn, &state.auth, session)
            .await
            .map_err(|_| Failure::Provider)?;
        let max_age = state.auth.access_ttl.num_seconds();
        return Ok((
            ("signed_in", "mfa_required"),
            vec![partial_cookie(browser, &token.access_token, max_age)],
        ));
    }
    let max_age = (session.expires_at - Utc::now()).num_seconds();
    Ok((
        ("signed_in", "true"),
        subject_api::refresh_cookies(browser, refresh.as_str(), max_age),
    ))
}

/// A subject for an account nobody linked yet, if the provider's policy
/// allows one: the subject whose login identifier is the account's verified
/// email, in a domain the provider may link, or else a new subject when the
/// provider creates them. Both kinds of failure look the same to the
/// browser, so existing identifiers aren't revealed.
// r[impl federation.provisioning]
// r[impl federation.linking]
async fn provision(
    conn: &mut Connection,
    provider: &Provider,
    claims: &crate::federation::IdClaims,
    identifier: String,
) -> Result<Option<credentials::Credential>, StoreError> {
    let settings = &provider.settings;
    conn.transaction::<_, StoreError, _>(async |conn| {
        let mut subject = None;
        if let (Some(email), Some(true)) = (&claims.email, claims.email_verified) {
            let domain = email.rsplit_once('@').map(|(_, d)| d.to_lowercase());
            if domain.is_some_and(|d| settings.link_verified_email_domains.contains(&d)) {
                for kind in [CredentialKind::Password, CredentialKind::EmailLink] {
                    if let Some(found) = credentials::find_active(conn, kind, email).await? {
                        subject = Some(found.subject_id);
                        break;
                    }
                }
            }
        }
        if subject.is_none() && settings.provisioning == Provisioning::Create {
            let id = SubjectId::new_v7();
            subjects::create(conn, id, SubjectKind::Human).await?;
            subject = Some(id);
        }
        let Some(subject) = subject else {
            return Ok(None);
        };
        let credential = credentials::insert(
            conn,
            NewCredential {
                id: CredentialId::new_v7(),
                subject_id: subject,
                identifier,
                data: CredentialData::Federated(FederatedData {
                    provider: settings.id.clone(),
                    subject: claims.sub.clone(),
                    email: claims.email.clone(),
                    email_verified: claims.email_verified,
                }),
                mfa_factors_required: settings.local_mfa_factors,
                replaces: None,
            },
        )
        .await?;
        Ok(Some(credential))
    })
    .await
}
