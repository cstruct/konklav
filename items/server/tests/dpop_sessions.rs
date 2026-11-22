//! DPoP for Konklav's own sessions: binding at login, and every surface
//! taking bound tokens only with proofs.

mod common;

use axum::http::{Method, StatusCode, header};
use common::{ISSUER, ORIGIN, TestApp};
use diesel_async::RunQueryDsl;
use konklav_test_support::DpopKey;
use serde_json::json;

const EMAIL: &str = "ada@example.com";
const PASSWORD: &str = "correct horse battery";
/// Where a proxy mounts the control-plane surface, as the console does.
const CONTROL_BASE: &str = "https://admin.example/control";

fn url(path: &str) -> String {
    format!("{ISSUER}{path}")
}

fn challenge(reply: &common::Reply) -> String {
    reply.headers[header::WWW_AUTHENTICATE]
        .to_str()
        .unwrap()
        .to_owned()
}

async fn bound_login(app: &TestApp, key: &DpopKey) -> common::Reply {
    let proof = key.proof("POST", &url("/v1/login/password"), None);
    app.send(
        Method::POST,
        "/v1/login/password",
        &[("dpop", &proof)],
        Some(json!({"identifier": EMAIL, "password": PASSWORD})),
    )
    .await
}

async fn capabilities(app: &TestApp, headers: &[(&str, &str)]) -> common::Reply {
    app.send(Method::GET, "/v1/capabilities", headers, None)
        .await
}

// r[verify session.dpop.bind]
// r[verify session.dpop.surfaces]
// r[verify token.dpop.scheme]
// r[verify token.refresh.dpop-bound]
#[tokio::test(flavor = "multi_thread")]
async fn a_login_with_a_proof_binds_the_session_to_its_key() {
    let app = TestApp::new().await;
    app.human(EMAIL, PASSWORD).await;
    let key = DpopKey::new(1);
    let login = bound_login(&app, &key).await;
    assert_eq!(login.status, StatusCode::OK, "{:?}", login.body);
    let access = login.body["access_token"].as_str().unwrap().to_owned();
    assert_eq!(app.verify(&access).await.cnf.unwrap().jkt, key.jkt());

    // The access token works only under DPoP, with a proof for the request.
    let dpop_auth = format!("DPoP {access}");
    let proof = key.proof("GET", &url("/v1/capabilities"), Some(&access));
    let served = capabilities(&app, &[("authorization", &dpop_auth), ("dpop", &proof)]).await;
    assert_eq!(served.status, StatusCode::OK, "{:?}", served.body);
    let bearer = format!("Bearer {access}");
    let refused = capabilities(&app, &[("authorization", &bearer)]).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    assert!(challenge(&refused).starts_with("DPoP error=\"invalid_dpop_proof\""));
    let replayed = capabilities(&app, &[("authorization", &dpop_auth), ("dpop", &proof)]).await;
    assert_eq!(replayed.status, StatusCode::UNAUTHORIZED);
    let other = DpopKey::new(2).proof("GET", &url("/v1/capabilities"), Some(&access));
    let stolen = capabilities(&app, &[("authorization", &dpop_auth), ("dpop", &other)]).await;
    assert_eq!(stolen.status, StatusCode::UNAUTHORIZED);

    // The refresh token needs the key too; a refused refresh changes nothing.
    let refresh = login.body["refresh_token"].as_str().unwrap();
    let body = json!({"refresh_token": refresh});
    let without = app.post("/v1/refresh", body.clone()).await;
    assert_eq!(
        without.status,
        StatusCode::UNAUTHORIZED,
        "{:?}",
        without.body
    );
    let proof = key.proof("POST", &url("/v1/refresh"), None);
    let refreshed = app
        .send(Method::POST, "/v1/refresh", &[("dpop", &proof)], Some(body))
        .await;
    assert_eq!(refreshed.status, StatusCode::OK, "{:?}", refreshed.body);
    let access = refreshed.body["access_token"].as_str().unwrap();
    assert_eq!(app.verify(access).await.cnf.unwrap().jkt, key.jkt());

    // A login without a proof still gets bearer tokens.
    let unbound = app.login(EMAIL, PASSWORD).await;
    let access = unbound.body["access_token"].as_str().unwrap();
    assert!(app.verify(access).await.cnf.is_none());
    let bearer = format!("Bearer {access}");
    assert_eq!(
        capabilities(&app, &[("authorization", &bearer)])
            .await
            .status,
        StatusCode::OK
    );
}

/// A login whose binding proof carries a `jti` of `length` bytes.
async fn login_with_jti(app: &TestApp, key: &DpopKey, length: usize) -> common::Reply {
    let proof = key.sign(&json!({
        "jti": "j".repeat(length),
        "htm": "POST",
        "htu": url("/v1/login/password"),
        "iat": chrono::Utc::now().timestamp(),
    }));
    app.send(
        Method::POST,
        "/v1/login/password",
        &[("dpop", &proof)],
        Some(json!({"identifier": EMAIL, "password": PASSWORD})),
    )
    .await
}

// r[verify token.dpop.proof]
// r[verify token.dpop.replay]
#[tokio::test(flavor = "multi_thread")]
async fn a_proof_with_an_overlong_jti_is_refused_and_not_remembered() {
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        count: i64,
    }
    let app = TestApp::new().await;
    app.human(EMAIL, PASSWORD).await;
    let key = DpopKey::new(1);
    let refused = login_with_jti(&app, &key, 129).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    assert!(challenge(&refused).starts_with("DPoP error=\"invalid_dpop_proof\""));
    let remembered = async || {
        let mut conn = app.db.pool().get().await.unwrap();
        let rows: Count = diesel::sql_query("select count(*) as count from dpop_proof")
            .get_result(&mut conn)
            .await
            .unwrap();
        rows.count
    };
    assert_eq!(remembered().await, 0);

    let accepted = login_with_jti(&app, &key, 128).await;
    assert_eq!(accepted.status, StatusCode::OK, "{:?}", accepted.body);
    assert_eq!(remembered().await, 1);
}

// r[verify session.dpop.surfaces]
#[tokio::test(flavor = "multi_thread")]
async fn proofs_may_name_a_configured_base_url_such_as_a_proxy_prefix() {
    let app = TestApp::with_auth(|auth| {
        auth.dpop_urls = vec![ISSUER.into(), CONTROL_BASE.into()];
    })
    .await;
    let subject = app.human(EMAIL, PASSWORD).await;
    let assigned = app
        .control(
            Method::POST,
            &format!("/v1/subjects/{subject}/global-assignments"),
            Some(json!({"role": "konklav.admin"})),
        )
        .await;
    assert_eq!(assigned.status, StatusCode::CREATED, "{:?}", assigned.body);
    let key = DpopKey::new(1);
    let access = bound_login(&app, &key).await.body["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let auth = format!("DPoP {access}");
    // The console's proof names `/control/v1/…`; Konklav sees `/v1/…`.
    let proof = key.proof("GET", &format!("{CONTROL_BASE}/v1/subjects"), Some(&access));
    let listed = app
        .send(
            Method::GET,
            "/v1/subjects",
            &[("authorization", &auth), ("dpop", &proof)],
            None,
        )
        .await;
    assert_eq!(listed.status, StatusCode::OK, "{:?}", listed.body);
    let elsewhere = key.proof(
        "GET",
        "https://evil.example/control/v1/subjects",
        Some(&access),
    );
    let refused = app
        .send(
            Method::GET,
            "/v1/subjects",
            &[("authorization", &auth), ("dpop", &elsewhere)],
            None,
        )
        .await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
}

// r[verify session.dpop.required]
#[tokio::test(flavor = "multi_thread")]
async fn a_deployment_can_require_bound_browser_sessions() {
    let app = TestApp::with_auth(|auth| {
        if let Some(browser) = &mut auth.browser {
            browser.require_dpop = true;
        }
    })
    .await;
    app.human(EMAIL, PASSWORD).await;
    let body = json!({"identifier": EMAIL, "password": PASSWORD, "client": "browser"});
    let browser = [("origin", ORIGIN), ("x-konklav-client", "web")];
    let refused = app
        .send(
            Method::POST,
            "/v1/login/password",
            &browser,
            Some(body.clone()),
        )
        .await;
    assert_eq!(
        refused.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        refused.body
    );

    let key = DpopKey::new(1);
    let proof = key.proof("POST", &url("/v1/login/password"), None);
    let mut headers = browser.to_vec();
    headers.push(("dpop", &proof));
    let login = app
        .send(Method::POST, "/v1/login/password", &headers, Some(body))
        .await;
    assert_eq!(login.status, StatusCode::OK, "{:?}", login.body);
    let cookie = login
        .set_cookies()
        .into_iter()
        .find(|c| c.contains("konklav_refresh"))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();

    // The cookie refresh needs the session's key as well.
    let mut refresh = browser.to_vec();
    refresh.push(("cookie", &cookie));
    let without = app.send(Method::POST, "/v1/refresh", &refresh, None).await;
    assert_eq!(
        without.status,
        StatusCode::UNAUTHORIZED,
        "{:?}",
        without.body
    );
    let proof = key.proof("POST", &url("/v1/refresh"), None);
    refresh.push(("dpop", &proof));
    let refreshed = app.send(Method::POST, "/v1/refresh", &refresh, None).await;
    assert_eq!(refreshed.status, StatusCode::OK, "{:?}", refreshed.body);

    // Native logins aren't affected.
    assert_eq!(app.login(EMAIL, PASSWORD).await.status, StatusCode::OK);
}

// r[verify session.dpop.bind]
#[tokio::test(flavor = "multi_thread")]
async fn impersonation_keeps_the_operators_binding() {
    let app = TestApp::new().await;
    let support = app.human(EMAIL, PASSWORD).await;
    let target = app.human("grace@example.com", PASSWORD).await;
    app.control(
        Method::PUT,
        "/v1/tenants/root/roles/SUPPORT",
        Some(json!({"policies": [{"action": "konklav:subject:impersonate", "effect": "allow"}]})),
    )
    .await;
    let assigned = app
        .control(
            Method::POST,
            &format!("/v1/subjects/{support}/global-assignments"),
            Some(json!({"role": "SUPPORT"})),
        )
        .await;
    assert_eq!(assigned.status, StatusCode::CREATED, "{:?}", assigned.body);
    let key = DpopKey::new(1);
    let access = bound_login(&app, &key).await.body["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let auth = format!("DPoP {access}");
    let proof = key.proof("POST", &url("/v1/impersonate"), Some(&access));
    let impersonating = app
        .send(
            Method::POST,
            "/v1/impersonate",
            &[("authorization", &auth), ("dpop", &proof)],
            Some(json!({"subject": target})),
        )
        .await;
    assert_eq!(
        impersonating.status,
        StatusCode::OK,
        "{:?}",
        impersonating.body
    );
    let as_target = impersonating.body["access_token"].as_str().unwrap();
    let claims = app.verify(as_target).await;
    assert_eq!(claims.sub.to_string(), target);
    assert_eq!(claims.cnf.unwrap().jkt, key.jkt());
}

// r[verify session.dpop.surfaces]
#[tokio::test(flavor = "multi_thread")]
async fn a_console_on_an_allowed_origin_needs_no_dpop_urls() {
    let app = TestApp::new().await;
    let subject = app.human(EMAIL, PASSWORD).await;
    app.control(
        Method::POST,
        &format!("/v1/subjects/{subject}/global-assignments"),
        Some(json!({"role": "konklav.admin"})),
    )
    .await;
    let key = DpopKey::new(1);
    // The console signs for its own origin, not the issuer.
    let proof = key.proof("POST", &format!("{ORIGIN}/v1/login/password"), None);
    let login = app
        .send(
            Method::POST,
            "/v1/login/password",
            &[("dpop", &proof)],
            Some(json!({"identifier": EMAIL, "password": PASSWORD})),
        )
        .await;
    assert_eq!(login.status, StatusCode::OK, "{:?}", login.body);
    let access = login.body["access_token"].as_str().unwrap();
    let auth = format!("DPoP {access}");
    let proof = key.proof(
        "GET",
        &format!("{ORIGIN}/control/v1/subjects"),
        Some(access),
    );
    let listed = app
        .send(
            Method::GET,
            "/v1/subjects",
            &[("authorization", &auth), ("dpop", &proof)],
            None,
        )
        .await;
    assert_eq!(listed.status, StatusCode::OK, "{:?}", listed.body);
}

/// A service principal's access token, sender-constrained to `key` when
/// given one, and the principal's id.
async fn service_login(app: &TestApp, key: Option<&DpopKey>) -> (String, String) {
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
    let proof = key.map(|key| key.proof("POST", &url("/v1/login/secret-key"), None));
    let headers: Vec<(&str, &str)> = proof.iter().map(|proof| ("dpop", &**proof)).collect();
    let login = app
        .send(
            Method::POST,
            "/v1/login/secret-key",
            &headers,
            Some(json!({"key_id": key_id, "secret": secret})),
        )
        .await;
    assert_eq!(login.status, StatusCode::OK, "{:?}", login.body);
    let access = login.body["access_token"].as_str().unwrap().to_owned();
    (access, id.to_string())
}

/// The status of a `GET` on a listener that serves only the relying
/// surface, as the default layout's relying port does.
async fn relying_get(app: &TestApp, path: &str, headers: &[(&str, &str)]) -> StatusCode {
    use konklav_server::surface::{Surface, router};
    use tower::ServiceExt;
    let mut request = axum::http::Request::builder().method(Method::GET).uri(path);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let request = request.body(axum::body::Body::empty()).unwrap();
    router(&[Surface::Relying], app.state.clone())
        .oneshot(request)
        .await
        .unwrap()
        .status()
}

// r[verify session.dpop.surfaces]
// r[verify session.dpop.fail-closed]
// r[verify token.dpop.scheme]
#[tokio::test(flavor = "multi_thread")]
async fn the_relying_surface_alone_takes_bound_tokens_only_with_proofs() {
    let app = TestApp::new().await;
    let key = DpopKey::new(1);
    let (access, principal) = service_login(&app, Some(&key)).await;
    assert_eq!(app.verify(&access).await.cnf.unwrap().jkt, key.jkt());
    let path = format!("/v1/entitlements/{principal}");

    let bearer = format!("Bearer {access}");
    let as_bearer = relying_get(&app, &path, &[("authorization", &bearer)]).await;
    assert_eq!(as_bearer, StatusCode::UNAUTHORIZED, "no proof, no access");
    let dpop_auth = format!("DPoP {access}");
    let without = relying_get(&app, &path, &[("authorization", &dpop_auth)]).await;
    assert_eq!(without, StatusCode::UNAUTHORIZED);
    let stolen = DpopKey::new(2).proof("GET", &url(&path), Some(&access));
    let headers = [("authorization", &*dpop_auth), ("dpop", &*stolen)];
    assert_eq!(
        relying_get(&app, &path, &headers).await,
        StatusCode::UNAUTHORIZED
    );
    let proof = key.proof("GET", &url(&path), Some(&access));
    let headers = [("authorization", &*dpop_auth), ("dpop", &*proof)];
    assert_eq!(relying_get(&app, &path, &headers).await, StatusCode::OK);
    assert_eq!(
        relying_get(&app, &path, &headers).await,
        StatusCode::UNAUTHORIZED,
        "a proof works once"
    );

    // Bearer tokens of unbound sessions work as before.
    let (unbound, _) = service_login(&app, None).await;
    let bearer = format!("Bearer {unbound}");
    assert_eq!(
        relying_get(&app, &path, &[("authorization", &bearer)]).await,
        StatusCode::OK
    );
}
