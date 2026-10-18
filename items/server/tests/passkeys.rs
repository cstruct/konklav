//! Passkeys: registration, usernameless login, step-up and removal, driven
//! by a software authenticator standing in for the browser.

mod common;

use axum::http::{Method, StatusCode};
use common::{ORIGIN, Reply, TestApp};
use diesel_async::RunQueryDsl;
use serde_json::{Value, json};
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse, Url};
use webauthn_rs_proto::{AllowCredentials, UserVerificationPolicy};

const EMAIL: &str = "ada@example.com";
const PASSWORD: &str = "correct horse battery staple";

async fn app() -> TestApp {
    TestApp::with_auth(|auth| {
        auth.passkeys = Some(
            konklav_server::passkeys::Verifier::new("app.example", "Konklav", &[ORIGIN.into()])
                .unwrap(),
        );
    })
    .await
}

fn token(reply: &Reply) -> String {
    reply.body["access_token"]
        .as_str()
        .unwrap_or_else(|| panic!("no access token: {:?}", reply.body))
        .to_owned()
}

async fn post_bearer(app: &TestApp, uri: &str, token: &str, body: Value) -> Reply {
    let auth = format!("Bearer {token}");
    app.send(Method::POST, uri, &[("authorization", &auth)], Some(body))
        .await
}

/// A passkey on a software authenticator. It can't create discoverable
/// keys or verify users, so it plays a browser that does: it keeps the
/// user handle itself, offers its key when the server names none, and
/// reports user verification whenever it is asked for.
struct Device {
    authenticator: WebauthnAuthenticator<SoftPasskey>,
    origin: Url,
    user: Option<Vec<u8>>,
    credential: Option<Vec<u8>>,
}

impl Device {
    fn new() -> Self {
        Self::at(ORIGIN)
    }

    fn at(origin: &str) -> Self {
        Self {
            authenticator: WebauthnAuthenticator::new(SoftPasskey::new(true)),
            origin: Url::parse(origin).unwrap(),
            user: None,
            credential: None,
        }
    }

    fn create(&mut self, options: &Value) -> Value {
        let mut options: CreationChallengeResponse =
            serde_json::from_value(options.clone()).unwrap();
        if let Some(selection) = options.public_key.authenticator_selection.as_mut() {
            selection.require_resident_key = false;
            selection.resident_key = None;
        }
        self.user = Some(options.public_key.user.id.to_vec());
        let response = self
            .authenticator
            .do_registration(self.origin.clone(), options)
            .unwrap();
        self.credential = Some(response.raw_id.to_vec());
        serde_json::to_value(response).unwrap()
    }

    fn sign(&mut self, options: &Value) -> Value {
        self.sign_with(options, |_| {})
    }

    fn sign_with(
        &mut self,
        options: &Value,
        adjust: impl FnOnce(&mut RequestChallengeResponse),
    ) -> Value {
        let mut options: RequestChallengeResponse =
            serde_json::from_value(options.clone()).unwrap();
        if options.public_key.allow_credentials.is_empty() {
            options.public_key.allow_credentials.push(AllowCredentials {
                type_: "public-key".into(),
                id: self.credential.clone().unwrap().into(),
                transports: None,
            });
        }
        adjust(&mut options);
        let mut response = self
            .authenticator
            .do_authentication(self.origin.clone(), options)
            .unwrap();
        response.response.user_handle = self.user.clone().map(Into::into);
        serde_json::to_value(response).unwrap()
    }
}

/// A human with a password and a passkey on `device`. Returns the
/// password session's token.
async fn with_passkey(app: &TestApp, device: &mut Device) -> String {
    app.human(EMAIL, PASSWORD).await;
    let session = token(&app.login(EMAIL, PASSWORD).await);
    let started = post_bearer(
        app,
        "/v1/passkeys/registration/options",
        &session,
        json!({"label": "Laptop"}),
    )
    .await;
    assert_eq!(started.status, StatusCode::OK, "{:?}", started.body);
    let credential = device.create(&started.body["options"]);
    let registered = post_bearer(
        app,
        "/v1/passkeys/registration",
        &session,
        json!({"ceremony": started.body["ceremony"], "credential": credential}),
    )
    .await;
    assert_eq!(
        registered.status,
        StatusCode::CREATED,
        "{:?}",
        registered.body
    );
    assert_eq!(registered.body["label"], "Laptop");
    session
}

async fn login_options(app: &TestApp) -> Value {
    let reply = app.post("/v1/login/passkey/options", json!({})).await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    reply.body
}

async fn login(app: &TestApp, ceremony: &Value, credential: Value) -> Reply {
    app.post(
        "/v1/login/passkey",
        json!({"ceremony": ceremony, "credential": credential}),
    )
    .await
}

async fn log_in(app: &TestApp, device: &mut Device) -> Reply {
    let started = login_options(app).await;
    let credential = device.sign(&started["options"]);
    login(app, &started["ceremony"], credential).await
}

fn refused(reply: &Reply) {
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{:?}", reply.body);
    assert_eq!(reply.code(), "INVALID_CREDENTIALS");
}

// r[verify authn.login.methods]
// r[verify authn.passkey.registration]
// r[verify authn.passkey.discoverable]
// r[verify authn.passkey.amr]
// r[verify credential.public-key.no-mfa]
#[tokio::test(flavor = "multi_thread")]
async fn a_registered_passkey_logs_in_without_an_identifier() {
    let app = app().await;
    let mut device = Device::new();
    let session = with_passkey(&app, &mut device).await;

    let started = login_options(&app).await;
    assert_eq!(
        started["options"]["publicKey"]["allowCredentials"],
        json!([]),
        "login names no account"
    );
    let reply = login(&app, &started["ceremony"], device.sign(&started["options"])).await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    assert!(
        reply.body["refresh_token"].is_string(),
        "no MFA step follows"
    );
    let claims = app.verify(&token(&reply)).await;
    assert_eq!(claims.amr, ["swk", "mfa"]);

    let listed = app.with_bearer(Method::GET, "/v1/passkeys", &session).await;
    assert_eq!(
        listed.body.as_array().unwrap().len(),
        1,
        "{:?}",
        listed.body
    );
    assert_eq!(listed.body[0]["label"], "Laptop");
    assert!(listed.body[0]["last_used_at"].is_string());
}

// r[verify challenge.single-use]
#[tokio::test(flavor = "multi_thread")]
async fn a_login_ceremony_works_once() {
    let app = app().await;
    let mut device = Device::new();
    with_passkey(&app, &mut device).await;
    let started = login_options(&app).await;
    let credential = device.sign(&started["options"]);
    let first = login(&app, &started["ceremony"], credential.clone()).await;
    assert_eq!(first.status, StatusCode::OK, "{:?}", first.body);
    refused(&login(&app, &started["ceremony"], credential).await);
}

// r[verify authn.passkey.origin]
#[tokio::test(flavor = "multi_thread")]
async fn assertions_for_another_origin_or_relying_party_id_are_refused() {
    let app = app().await;
    let mut device = Device::new();
    with_passkey(&app, &mut device).await;

    // Browsers let a subdomain use the relying party ID, but this one is
    // not a configured origin.
    let started = login_options(&app).await;
    device.origin = Url::parse("https://other.app.example").unwrap();
    refused(&login(&app, &started["ceremony"], device.sign(&started["options"])).await);

    // Signed for another site's relying party ID.
    device.origin = Url::parse("https://evil.example").unwrap();
    let started = login_options(&app).await;
    let credential = device.sign_with(&started["options"], |options| {
        options.public_key.rp_id = "evil.example".into();
    });
    refused(&login(&app, &started["ceremony"], credential).await);
}

// r[verify authn.passkey.user-verification]
#[tokio::test(flavor = "multi_thread")]
async fn assertions_without_user_verification_are_refused() {
    let app = app().await;
    let mut device = Device::new();
    with_passkey(&app, &mut device).await;
    let started = login_options(&app).await;
    let credential = device.sign_with(&started["options"], |options| {
        options.public_key.user_verification = UserVerificationPolicy::Discouraged_DO_NOT_USE;
    });
    refused(&login(&app, &started["ceremony"], credential).await);
}

// r[verify authn.passkey.counter]
#[tokio::test(flavor = "multi_thread")]
async fn a_signature_counter_that_does_not_increase_is_refused() {
    let app = app().await;
    let mut device = Device::new();
    with_passkey(&app, &mut device).await;
    let first = log_in(&app, &mut device).await;
    assert_eq!(first.status, StatusCode::OK, "{:?}", first.body);
    let mut conn = app.db.pool().get().await.unwrap();
    let counter: Vec<Counter> = diesel::sql_query(
        "select (data #>> '{state,cred,counter}')::bigint as counter \
         from credential where kind = 'public_key'",
    )
    .load(&mut conn)
    .await
    .unwrap();
    assert!(counter[0].counter > 0, "the counter is persisted");

    diesel::sql_query(
        "update credential set data = jsonb_set(data, '{state,cred,counter}', '1000') \
         where kind = 'public_key'",
    )
    .execute(&mut conn)
    .await
    .unwrap();
    refused(&log_in(&app, &mut device).await);
}

#[derive(diesel::QueryableByName)]
struct Counter {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    counter: i64,
}

// r[verify authn.passkey.discoverable]
#[tokio::test(flavor = "multi_thread")]
async fn the_user_handle_must_name_the_keys_subject() {
    let app = app().await;
    let mut device = Device::new();
    with_passkey(&app, &mut device).await;
    device.user = Some(uuid::Uuid::now_v7().as_bytes().to_vec());
    refused(&log_in(&app, &mut device).await);
}

// r[verify authn.passkey.registration]
#[tokio::test(flavor = "multi_thread")]
async fn registering_needs_a_recent_authentication() {
    let app = app().await;
    app.human(EMAIL, PASSWORD).await;
    let session = token(&app.login(EMAIL, PASSWORD).await);
    let mut conn = app.db.pool().get().await.unwrap();
    diesel::sql_query("update session set auth_time = now() - interval '1 hour'")
        .execute(&mut conn)
        .await
        .unwrap();
    let reply = post_bearer(
        &app,
        "/v1/passkeys/registration/options",
        &session,
        json!({"label": "Laptop"}),
    )
    .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN, "{:?}", reply.body);
}

// r[verify authn.step-up.in-session]
// r[verify authn.passkey.amr]
#[tokio::test(flavor = "multi_thread")]
async fn a_passkey_steps_up_a_session() {
    let app = app().await;
    let mut device = Device::new();
    let session = with_passkey(&app, &mut device).await;
    let before = app.verify(&session).await;

    let started = post_bearer(&app, "/v1/step-up/passkey/options", &session, json!({})).await;
    assert_eq!(started.status, StatusCode::OK, "{:?}", started.body);
    let credential = device.sign(&started.body["options"]);
    let stepped = post_bearer(
        &app,
        "/v1/step-up",
        &session,
        json!({"ceremony": started.body["ceremony"], "passkey": credential}),
    )
    .await;
    assert_eq!(stepped.status, StatusCode::OK, "{:?}", stepped.body);
    let after = app.verify(&token(&stepped)).await;
    assert_eq!(after.sid, before.sid, "the same session");
    assert_eq!(after.amr, ["pwd", "swk", "mfa"]);

    // A login ceremony can't stand in for a step-up one.
    let login = login_options(&app).await;
    let credential = device.sign(&login["options"]);
    let reply = post_bearer(
        &app,
        "/v1/step-up",
        &token(&stepped),
        json!({"ceremony": login["ceremony"], "passkey": credential}),
    )
    .await;
    refused(&reply);
}

// r[verify authn.passkey.management]
// r[verify credential.revocation-ends-sessions]
#[tokio::test(flavor = "multi_thread")]
async fn removing_a_passkey_revokes_it_and_its_sessions() {
    let app = app().await;
    let mut device = Device::new();
    let session = with_passkey(&app, &mut device).await;
    let passkey_session = token(&log_in(&app, &mut device).await);
    let listed = app.with_bearer(Method::GET, "/v1/passkeys", &session).await;
    let id = listed.body[0]["id"].as_str().unwrap().to_owned();

    let auth = format!("Bearer {session}");
    let removed = app
        .send(
            Method::DELETE,
            &format!("/v1/passkeys/{id}"),
            &[("authorization", &auth)],
            None,
        )
        .await;
    assert_eq!(removed.status, StatusCode::OK, "{:?}", removed.body);

    refused(&log_in(&app, &mut device).await);
    let ended = app
        .with_bearer(Method::GET, "/v1/passkeys", &passkey_session)
        .await;
    assert_eq!(ended.status, StatusCode::UNAUTHORIZED, "{:?}", ended.body);
    let listed = app.with_bearer(Method::GET, "/v1/passkeys", &session).await;
    assert_eq!(listed.body, json!([]));
}

#[tokio::test(flavor = "multi_thread")]
async fn passkeys_are_unavailable_unless_configured() {
    let app = TestApp::new().await;
    let reply = app.post("/v1/login/passkey/options", json!({})).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND, "{:?}", reply.body);
}
