//! The operator CLI (`konklav-cli`) against a real server: every session it
//! starts is bound to its DPoP key, and its tokens are useless without it.

mod common;

use std::sync::Arc;

use axum::http::{Method, StatusCode};
use common::TestApp;
use diesel_async::RunQueryDsl;
use konklav_authn::TotpSecret;
use konklav_cli::profile::Profile;
use konklav_cli::store::{MemoryStore, SecretStore};
use konklav_cli::{Context, Error, PasswordLogin, Session, Surface, session};
use serde_json::json;

const EMAIL: &str = "operator@example.com";
const PASSWORD: &str = "correct horse battery";

async fn operator(app: &TestApp) -> String {
    let subject = app.human(EMAIL, PASSWORD).await;
    let assigned = app
        .control(
            Method::POST,
            &format!("/v1/subjects/{subject}/global-assignments"),
            Some(json!({"role": "konklav.admin"})),
        )
        .await;
    assert_eq!(assigned.status, StatusCode::CREATED, "{:?}", assigned.body);
    subject
}

fn context(base: &str, store: &Arc<MemoryStore>, lock_dir: Option<&std::path::Path>) -> Context {
    Context::new(
        "test",
        Profile::new(base, None).unwrap(),
        store.clone(),
        lock_dir.map(std::path::Path::to_owned),
    )
    .unwrap()
}

async fn password_login(base: &str, store: &Arc<MemoryStore>) -> Session {
    match session::login_password(context(base, store, None), EMAIL, PASSWORD)
        .await
        .unwrap()
    {
        PasswordLogin::Done(session) => session,
        PasswordLogin::Mfa(_) => panic!("no MFA was required"),
    }
}

fn stored(store: &MemoryStore) -> konklav_cli::store::StoredSession {
    store.get("test").unwrap().unwrap()
}

/// Whether an access token is sender-constrained. The signature is
/// Konklav's own concern here; the CLI only needs `cnf`.
fn bound(token: &str) -> bool {
    konklav_token::decode_claims_unverified(token)
        .unwrap()
        .cnf
        .is_some()
}

/// Makes the stored access token look expired, so the next request
/// refreshes.
fn expire(store: &MemoryStore) {
    let mut record = stored(store);
    record.access_expires_at = 0;
    store.set("test", &record).unwrap();
}

// r[verify item.cli.dpop-every-request]
#[tokio::test(flavor = "multi_thread")]
async fn a_password_login_binds_the_session_and_reaches_the_control_plane() {
    let (app, base) = TestApp::serving(|_, _| {}).await;
    let subject = operator(&app).await;
    let store = Arc::new(MemoryStore::default());
    let mut session = password_login(&base, &store).await;
    let record = stored(&store);
    assert!(bound(&record.access_token));

    let capabilities = session
        .send(Method::GET, Surface::Subject, "/v1/capabilities", None)
        .await
        .unwrap()
        .ok()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(capabilities["subject"], json!(subject));
    let tenants = session
        .send(Method::GET, Surface::Control, "/v1/tenants", None)
        .await
        .unwrap();
    assert_eq!(tenants.status, StatusCode::OK);

    // Copied off the machine, neither token works without the key.
    let http = reqwest::Client::new();
    let bearer = http
        .get(format!("{base}/v1/tenants"))
        .bearer_auth(&record.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(bearer.status(), StatusCode::UNAUTHORIZED);
    let refresh = http
        .post(format!("{base}/v1/refresh"))
        .json(&json!({"refresh_token": record.refresh_token}))
        .send()
        .await
        .unwrap();
    assert_eq!(refresh.status(), StatusCode::UNAUTHORIZED);

    // The refused refresh left the session usable, and the CLI refreshes
    // it with its key, rotating the refresh token.
    expire(&store);
    let mut session = Session::load(context(&base, &store, None)).unwrap();
    let again = session
        .send(Method::GET, Surface::Control, "/v1/tenants", None)
        .await
        .unwrap();
    assert_eq!(again.status, StatusCode::OK);
    assert_ne!(stored(&store).refresh_token, record.refresh_token);
}

// r[verify item.cli.logout]
#[tokio::test(flavor = "multi_thread")]
async fn logout_revokes_the_session_and_forgets_it() {
    let (app, base) = TestApp::serving(|_, _| {}).await;
    operator(&app).await;
    let store = Arc::new(MemoryStore::default());
    let session = password_login(&base, &store).await;
    let record = stored(&store);
    assert!(session.logout().await.unwrap().is_none());
    assert!(store.get("test").unwrap().is_none());
    let reloaded = Session::load(context(&base, &store, None));
    assert!(matches!(reloaded, Err(Error::NotSignedIn(_))));

    // The session is revoked at Konklav: putting the record back fails to
    // refresh, and the CLI forgets it again.
    store.set("test", &record).unwrap();
    expire(&store);
    let mut session = Session::load(context(&base, &store, None)).unwrap();
    let refused = session
        .send(Method::GET, Surface::Control, "/v1/tenants", None)
        .await;
    assert!(matches!(refused, Err(Error::NotSignedIn(_))), "{refused:?}");
    assert!(store.get("test").unwrap().is_none());
}

/// Gives `EMAIL` an active TOTP factor and makes its password need it.
/// Returns the code for a step from now; each code works once.
async fn require_totp(app: &TestApp) -> impl Fn(i64) -> String + use<> {
    let token = app.login(EMAIL, PASSWORD).await.body["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let auth = format!("Bearer {token}");
    let enrolled = app
        .send(
            Method::POST,
            "/v1/mfa/totp",
            &[("authorization", &auth)],
            Some(json!({})),
        )
        .await;
    let secret = enrolled.body["secret"].as_str().unwrap().to_owned();
    let factor = enrolled.body["factor_id"].as_str().unwrap().to_owned();
    let code = move |offset: i64| {
        let decoded = base32_decode(&secret);
        TotpSecret::from_bytes(decoded).code_at_step(chrono::Utc::now().timestamp() / 30 + offset)
    };
    let activated = app
        .send(
            Method::POST,
            &format!("/v1/mfa/{factor}/activate"),
            &[("authorization", &auth)],
            Some(json!({"code": code(0)})),
        )
        .await;
    assert_eq!(activated.body["active"], true, "{:?}", activated.body);
    let mut conn = app.db.pool().get().await.unwrap();
    diesel::sql_query("update credential set mfa_factors_required = 1")
        .execute(&mut conn)
        .await
        .unwrap();
    code
}

#[tokio::test(flavor = "multi_thread")]
async fn a_password_login_completes_mfa() {
    let (app, base) = TestApp::serving(|_, _| {}).await;
    operator(&app).await;
    let code = require_totp(&app).await;

    let store = Arc::new(MemoryStore::default());
    let login = session::login_password(context(&base, &store, None), EMAIL, PASSWORD)
        .await
        .unwrap();
    let PasswordLogin::Mfa(pending) = login else {
        panic!("MFA is required");
    };
    assert!(store.get("test").unwrap().is_none(), "nothing stored yet");
    let factors = pending.factors().await.unwrap();
    assert_eq!(factors.len(), 1);
    assert_eq!(factors[0].kind, "totp");
    let PasswordLogin::Done(mut session) = pending.complete(factors[0].id, &code(1)).await.unwrap()
    else {
        panic!("one factor is enough");
    };
    let tenants = session
        .send(Method::GET, Surface::Control, "/v1/tenants", None)
        .await
        .unwrap();
    assert_eq!(tenants.status, StatusCode::OK);
    assert!(bound(&stored(&store).access_token));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_secret_key_login_binds_the_session() {
    let (app, base) = TestApp::serving(|_, _| {}).await;
    let id = uuid::Uuid::now_v7();
    app.control(
        Method::PUT,
        &format!("/v1/subjects/{id}"),
        Some(json!({"kind": "service"})),
    )
    .await;
    let created = app
        .control(
            Method::POST,
            &format!("/v1/subjects/{id}/credentials"),
            Some(json!({"kind": "secret_key"})),
        )
        .await;
    let (key_id, secret) = created.body["secret_keys"]["a"]
        .as_str()
        .unwrap()
        .split_once('.')
        .unwrap();
    let store = Arc::new(MemoryStore::default());
    let mut session = session::login_secret_key(context(&base, &store, None), key_id, secret)
        .await
        .unwrap();
    assert!(bound(&stored(&store).access_token));
    let capabilities = session
        .send(Method::GET, Surface::Subject, "/v1/capabilities", None)
        .await
        .unwrap();
    assert_eq!(capabilities.status, StatusCode::OK);
}

/// Commands run at the same time take turns refreshing, so neither presents
/// a refresh token the other already rotated, which would end the session.
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_commands_share_one_refresh() {
    let (app, base) = TestApp::serving(|_, _| {}).await;
    operator(&app).await;
    let store = Arc::new(MemoryStore::default());
    let locks = tempfile::tempdir().unwrap();
    password_login(&base, &store).await;
    expire(&store);
    let run = || {
        let mut session = Session::load(context(&base, &store, Some(locks.path()))).unwrap();
        async move {
            session
                .send(Method::GET, Surface::Control, "/v1/tenants", None)
                .await
                .unwrap()
                .status
        }
    };
    let (first, second) = tokio::join!(run(), run());
    assert_eq!((first, second), (StatusCode::OK, StatusCode::OK));
    let mut session = Session::load(context(&base, &store, None)).unwrap();
    let after = session
        .send(Method::GET, Surface::Control, "/v1/tenants", None)
        .await
        .unwrap();
    assert_eq!(after.status, StatusCode::OK, "the session is still alive");
}

fn base32_decode(input: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut buffer, mut bits, mut out) = (0u32, 0, Vec::new());
    for c in input.bytes() {
        buffer =
            (buffer << 5) | u32::try_from(ALPHABET.iter().position(|a| *a == c).unwrap()).unwrap();
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xff).unwrap());
        }
    }
    out
}

/// What the login page does for a native request: it reads the request,
/// signs in with the password and a TOTP `code`, and accepts. Returns the
/// page's access token and where it sends the browser.
async fn play_login_page(
    browser: &reqwest::Client,
    base: &str,
    request: &str,
    code: &str,
) -> (String, String) {
    // The login page: it sees a native request, signs in, and accepts.
    let page = |method: Method, path: &str| {
        browser
            .request(method, format!("{base}/v1{path}"))
            .header("origin", common::ORIGIN)
            .header("x-konklav-client", "web")
    };
    let viewed: serde_json::Value = page(Method::GET, &format!("/login-requests/{request}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(viewed["kind"], "native");
    assert_eq!(viewed["app"], konklav_cli::browser::APP);
    let partial: serde_json::Value = page(Method::POST, "/login/password")
        .json(&json!({"identifier": EMAIL, "password": PASSWORD, "client": "browser"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(partial["token_kind"], "partial", "{partial}");
    let partial = partial["access_token"].as_str().unwrap();
    let factors: serde_json::Value = page(Method::GET, "/mfa")
        .bearer_auth(partial)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let full: serde_json::Value = page(Method::POST, "/login/mfa")
        .bearer_auth(partial)
        .json(&json!({"factor_id": factors[0]["id"], "code": code}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let full = full["access_token"].as_str().unwrap();
    // Here the page asks the person to confirm.
    let accepted: serde_json::Value =
        page(Method::POST, &format!("/login-requests/{request}/accept"))
            .bearer_auth(full)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    (
        full.to_owned(),
        accepted["redirect_to"].as_str().unwrap().to_owned(),
    )
}

/// The browser in a browser sign-in: it follows Konklav's redirects by
/// hand, and plays the login application with the calls the login page
/// makes, through password and MFA.
// r[verify item.cli.loopback]
// r[verify session.native-handoff.session]
#[tokio::test(flavor = "multi_thread")]
async fn a_browser_login_ends_in_a_bound_session() {
    let (app, base) = TestApp::serving(|auth, base| {
        auth.native_handoff = Some(konklav_server::native_handoff::Settings {
            login_url: format!("{base}/login/"),
            apps: vec![konklav_cli::browser::APP.into()],
            session_lifetime: chrono::Duration::hours(12),
        });
    })
    .await;
    operator(&app).await;
    let code = require_totp(&app).await;
    let store = Arc::new(MemoryStore::default());
    let login = konklav_cli::BrowserLogin::start(context(&base, &store, None))
        .await
        .unwrap();
    let browser = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let started = browser.get(login.url()).send().await.unwrap();
    assert_eq!(started.status(), StatusCode::SEE_OTHER);
    let to_page = started.headers()["location"].to_str().unwrap().to_owned();
    assert!(to_page.starts_with(&format!("{base}/login/?login_request=")));
    let request = to_page.rsplit('=').next().unwrap().to_owned();
    // The cookie is `Secure`, which a client won't send over plain HTTP by
    // itself.
    let cookie = started.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let finishing = tokio::spawn(login.finish(std::time::Duration::from_secs(30)));

    let (full, resume) = play_login_page(&browser, &base, &request, &code(1)).await;
    let resumed = browser
        .get(&resume)
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resumed.status(), StatusCode::SEE_OTHER);
    let to_cli = resumed.headers()["location"].to_str().unwrap().to_owned();
    assert!(to_cli.starts_with("http://127.0.0.1:"), "{to_cli}");
    let closed = browser.get(&to_cli).send().await.unwrap();
    assert_eq!(closed.status(), StatusCode::OK);
    assert!(closed.text().await.unwrap().contains("close this tab"));

    let mut session = finishing.await.unwrap().unwrap();
    assert!(bound(&stored(&store).access_token));
    let tenants = session
        .send(Method::GET, Surface::Control, "/v1/tenants", None)
        .await
        .unwrap();
    assert_eq!(tenants.status, StatusCode::OK);
    // The browser's sign-out leaves the CLI's session.
    let signed_out = browser
        .post(format!("{base}/v1/sign-out"))
        .header("origin", common::ORIGIN)
        .header("x-konklav-client", "web")
        .bearer_auth(&full)
        .send()
        .await
        .unwrap();
    assert!(signed_out.status().is_success());
    expire(&store);
    let mut session = Session::load(context(&base, &store, None)).unwrap();
    let tenants = session
        .send(Method::GET, Surface::Control, "/v1/tenants", None)
        .await
        .unwrap();
    assert_eq!(tenants.status, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_browser_login_says_when_the_server_does_not_offer_it() {
    let (_app, base) = TestApp::serving(|_, _| {}).await;
    let store = Arc::new(MemoryStore::default());
    let refused = konklav_cli::BrowserLogin::start(context(&base, &store, None)).await;
    assert!(
        matches!(refused, Err(Error::Usage(_))),
        "{:?}",
        refused.err()
    );
}
