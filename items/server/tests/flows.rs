#![allow(clippy::too_many_lines)]

mod common;

use axum::http::{Method, StatusCode};
use common::TestApp;
use diesel_async::RunQueryDsl;
use konklav_authn::TotpSecret;
use serde_json::{Value, json};

const EMAIL: &str = "ada@example.com";
const PASSWORD: &str = "correct horse battery";

/// A service principal allowed to read delivery requests, like a relying
/// system's mailer.
// r[verify authz.role.builtin.set]
async fn mailer(app: &TestApp) -> String {
    let token = app.service_token().await;
    let claims = app.verify(&token).await;
    let assigned = app
        .control(
            Method::POST,
            &format!("/v1/subjects/{}/global-assignments", claims.sub),
            Some(json!({"role": "konklav.delivery"})),
        )
        .await;
    assert_eq!(assigned.status, StatusCode::CREATED, "{:?}", assigned.body);
    token
}

/// The material of the newest delivery request for `recipient`.
async fn delivered(app: &TestApp, mailer: &str, recipient: &str) -> Value {
    let batch = app
        .with_bearer(
            Method::GET,
            "/v1/events/batch?after=0&kinds=delivery.requested&limit=1000",
            mailer,
        )
        .await;
    batch.body["events"]
        .as_array()
        .unwrap()
        .iter()
        .rev()
        .find(|e| e.data_recipient() == recipient)
        .map_or_else(
            || panic!("nothing delivered to {recipient}: {:?}", batch.body),
            |e| e["payload"]["material"].clone(),
        )
}

trait Recipient {
    fn data_recipient(&self) -> &str;
}

impl Recipient for Value {
    fn data_recipient(&self) -> &str {
        self["payload"]["recipient"].as_str().unwrap_or_default()
    }
}

fn token(reply: &common::Reply) -> String {
    reply.body["access_token"].as_str().unwrap().to_owned()
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

fn totp_code(secret: &str, offset_steps: i64) -> String {
    let step = chrono::Utc::now().timestamp() / 30 + offset_steps;
    TotpSecret::from_bytes(base32_decode(secret)).code_at_step(step)
}

async fn post_bearer(app: &TestApp, uri: &str, bearer: &str, body: Value) -> common::Reply {
    let auth = format!("Bearer {bearer}");
    app.send(Method::POST, uri, &[("authorization", &auth)], Some(body))
        .await
}

// r[verify authn.mfa.factors]
// r[verify authn.mfa.secrets-encrypted]
// r[verify authn.mfa.amr]
#[tokio::test(flavor = "multi_thread")]
async fn totp_completes_mfa_for_credentials_that_require_it() {
    let app = TestApp::new().await;
    app.human(EMAIL, PASSWORD).await;
    let session = token(&app.login(EMAIL, PASSWORD).await);
    let enrolled = post_bearer(&app, "/v1/mfa/totp", &session, json!({})).await;
    assert_eq!(enrolled.status, StatusCode::OK, "{:?}", enrolled.body);
    let secret = enrolled.body["secret"].as_str().unwrap().to_owned();
    let factor = enrolled.body["factor_id"].as_str().unwrap().to_owned();
    assert!(
        enrolled.body["uri"]
            .as_str()
            .unwrap()
            .starts_with("otpauth://totp/")
    );

    {
        let mut conn = app.db.pool().get().await.unwrap();
        let stored: Vec<StoredFactor> =
            diesel::sql_query("select data::text as data from mfa_factor")
                .load(&mut conn)
                .await
                .unwrap();
        assert!(
            !stored[0].data.contains(&secret),
            "the seed is encrypted at rest"
        );
    }

    let wrong = post_bearer(
        &app,
        &format!("/v1/mfa/{factor}/activate"),
        &session,
        json!({"code": "000000"}),
    )
    .await;
    assert_eq!(wrong.code(), "INVALID_CREDENTIALS");
    let activated = post_bearer(
        &app,
        &format!("/v1/mfa/{factor}/activate"),
        &session,
        json!({"code": totp_code(&secret, 0)}),
    )
    .await;
    assert_eq!(activated.body["active"], true, "{:?}", activated.body);

    {
        let mut conn = app.db.pool().get().await.unwrap();
        diesel::sql_query("update credential set mfa_factors_required = 1")
            .execute(&mut conn)
            .await
            .unwrap();
    }
    let partial = app.login(EMAIL, PASSWORD).await;
    assert_eq!(partial.body["token_kind"], "partial");
    let partial = token(&partial);
    let replay = post_bearer(
        &app,
        "/v1/login/mfa",
        &partial,
        json!({"factor_id": factor, "code": totp_code(&secret, 0)}),
    )
    .await;
    assert_eq!(
        replay.code(),
        "INVALID_CREDENTIALS",
        "codes can't be replayed"
    );
    let done = post_bearer(
        &app,
        "/v1/login/mfa",
        &partial,
        json!({"factor_id": factor, "code": totp_code(&secret, 1)}),
    )
    .await;
    assert_eq!(done.status, StatusCode::OK, "{:?}", done.body);
    assert_eq!(done.body["token_kind"], "identity");
    assert!(done.body["refresh_token"].is_string());
    let claims = app.verify(&token(&done)).await;
    assert_eq!(claims.amr, vec!["pwd", "otp"]);
}

// r[verify authn.mfa.partial-factors]
// r[verify session.browser.mfa]
#[tokio::test(flavor = "multi_thread")]
async fn browsers_complete_mfa_with_a_listed_factor_and_get_the_cookie() {
    let app = TestApp::new().await;
    app.human(EMAIL, PASSWORD).await;
    let session = token(&app.login(EMAIL, PASSWORD).await);
    let enrolled = post_bearer(&app, "/v1/mfa/totp", &session, json!({})).await;
    let secret = enrolled.body["secret"].as_str().unwrap().to_owned();
    let factor = enrolled.body["factor_id"].as_str().unwrap().to_owned();
    post_bearer(
        &app,
        &format!("/v1/mfa/{factor}/activate"),
        &session,
        json!({"code": totp_code(&secret, 0)}),
    )
    .await;
    // An inactive factor that a partial session must not see.
    post_bearer(&app, "/v1/mfa/totp", &session, json!({})).await;
    {
        let mut conn = app.db.pool().get().await.unwrap();
        diesel::sql_query("update credential set mfa_factors_required = 1")
            .execute(&mut conn)
            .await
            .unwrap();
    }

    let browser = [("origin", common::ORIGIN), ("x-konklav-client", "web")];
    let login = app
        .send(
            Method::POST,
            "/v1/login/password",
            &browser,
            Some(json!({"identifier": EMAIL, "password": PASSWORD, "client": "browser"})),
        )
        .await;
    assert_eq!(login.body["token_kind"], "partial");
    assert!(login.set_cookies().is_empty(), "no cookie before MFA");
    let partial = token(&login);

    let listed = app.with_bearer(Method::GET, "/v1/mfa", &partial).await;
    assert_eq!(listed.status, StatusCode::OK, "{:?}", listed.body);
    let listed = listed.body.as_array().unwrap();
    assert_eq!(listed.len(), 1, "only active factors: {listed:?}");
    assert_eq!(listed[0]["id"], factor.as_str());
    let enroll = post_bearer(&app, "/v1/mfa/totp", &partial, json!({})).await;
    assert_eq!(enroll.code(), "FORBIDDEN");

    let auth = format!("Bearer {partial}");
    let body = json!({"factor_id": factor, "code": totp_code(&secret, 1)});
    let no_header = app
        .send(
            Method::POST,
            "/v1/login/mfa",
            &[("authorization", &auth), ("origin", common::ORIGIN)],
            Some(body.clone()),
        )
        .await;
    assert_eq!(no_header.code(), "FORBIDDEN", "{:?}", no_header.body);
    let done = app
        .send(
            Method::POST,
            "/v1/login/mfa",
            &[
                ("authorization", &auth),
                ("origin", common::ORIGIN),
                ("x-konklav-client", "web"),
            ],
            Some(body),
        )
        .await;
    assert_eq!(done.status, StatusCode::OK, "{:?}", done.body);
    assert_eq!(done.body["token_kind"], "identity");
    assert!(done.body.get("refresh_token").is_none());
    let cookies = done.set_cookies();
    assert_eq!(cookies.len(), 2, "{cookies:?}");
    let cookie = cookies[0].split(';').next().unwrap().to_owned();
    let refreshed = app
        .send(
            Method::POST,
            "/v1/refresh",
            &[
                ("origin", common::ORIGIN),
                ("x-konklav-client", "web"),
                ("cookie", &cookie),
            ],
            None,
        )
        .await;
    assert_eq!(refreshed.status, StatusCode::OK, "{:?}", refreshed.body);
}

#[derive(diesel::QueryableByName)]
struct StoredFactor {
    #[diesel(sql_type = diesel::sql_types::Text)]
    data: String,
}

// r[verify authn.step-up.in-session]
// r[verify challenge.delivery.event]
#[tokio::test(flavor = "multi_thread")]
async fn email_codes_activate_factors_and_step_up() {
    let app = TestApp::new().await;
    let mailer = mailer(&app).await;
    app.human(EMAIL, PASSWORD).await;
    let session = token(&app.login(EMAIL, PASSWORD).await);
    let enrolled = post_bearer(
        &app,
        "/v1/mfa/email",
        &session,
        json!({"email": "codes@example.com"}),
    )
    .await;
    assert_eq!(enrolled.status, StatusCode::CREATED, "{:?}", enrolled.body);
    let factor = enrolled.body["id"].as_str().unwrap().to_owned();
    let code = delivered(&app, &mailer, "codes@example.com").await["code"]
        .as_str()
        .unwrap()
        .to_owned();
    let activated = post_bearer(
        &app,
        &format!("/v1/mfa/{factor}/activate"),
        &session,
        json!({"code": code}),
    )
    .await;
    assert_eq!(activated.body["active"], true, "{:?}", activated.body);

    let before = app.verify(&session).await;
    assert_eq!(
        post_bearer(&app, &format!("/v1/mfa/{factor}/send"), &session, json!({}))
            .await
            .status,
        StatusCode::ACCEPTED
    );
    let code = delivered(&app, &mailer, "codes@example.com").await["code"]
        .as_str()
        .unwrap()
        .to_owned();
    let stepped = post_bearer(
        &app,
        "/v1/step-up",
        &session,
        json!({"factor_id": factor, "code": code}),
    )
    .await;
    assert_eq!(stepped.status, StatusCode::OK, "{:?}", stepped.body);
    let after = app.verify(&token(&stepped)).await;
    assert_eq!(after.sid, before.sid, "same session");
    assert!(after.sv > before.sv);
    assert_eq!(after.amr, vec!["pwd", "eml"]);

    let by_password = post_bearer(
        &app,
        "/v1/step-up",
        &token(&stepped),
        json!({"password": PASSWORD}),
    )
    .await;
    assert_eq!(by_password.status, StatusCode::OK, "{:?}", by_password.body);
    let wrong = post_bearer(
        &app,
        "/v1/step-up",
        &token(&by_password),
        json!({"password": "nope nope"}),
    )
    .await;
    assert_eq!(wrong.code(), "INVALID_CREDENTIALS");
}

async fn passwordless_subject(app: &TestApp, kind: &str, identifier: &str) {
    let id = uuid::Uuid::now_v7();
    app.control(
        Method::PUT,
        &format!("/v1/subjects/{id}"),
        Some(json!({"kind": "human"})),
    )
    .await;
    let created = app
        .control(
            Method::POST,
            &format!("/v1/subjects/{id}/credentials"),
            Some(json!({"kind": kind, "identifier": identifier})),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
}

// r[verify challenge.single-use]
#[tokio::test(flavor = "multi_thread")]
async fn magic_links_log_in_once() {
    let app = TestApp::new().await;
    let mailer = mailer(&app).await;
    passwordless_subject(&app, "email_link", "link@example.com").await;
    let unknown = app
        .post(
            "/v1/login/email-link/start",
            json!({"email": "nobody@example.com"}),
        )
        .await;
    let known = app
        .post(
            "/v1/login/email-link/start",
            json!({"email": "Link@Example.com"}),
        )
        .await;
    assert_eq!(unknown.status, StatusCode::ACCEPTED);
    assert_eq!(known.status, StatusCode::ACCEPTED, "both look the same");
    let link = delivered(&app, &mailer, "link@example.com").await["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let login = app
        .post("/v1/login/email-link/complete", json!({"token": link}))
        .await;
    assert_eq!(login.status, StatusCode::OK, "{:?}", login.body);
    assert_eq!(app.verify(&token(&login)).await.amr, vec!["eml"]);
    let again = app
        .post("/v1/login/email-link/complete", json!({"token": link}))
        .await;
    assert_eq!(again.code(), "INVALID_CREDENTIALS");
}

// r[verify challenge.attempts]
#[tokio::test(flavor = "multi_thread")]
async fn phone_codes_allow_limited_attempts() {
    let app = TestApp::new().await;
    let mailer = mailer(&app).await;
    passwordless_subject(&app, "phone_otp", "+46701234567").await;
    app.post("/v1/login/phone/start", json!({"phone": "+46701234567"}))
        .await;
    let code = delivered(&app, &mailer, "+46701234567").await["code"]
        .as_str()
        .unwrap()
        .to_owned();
    for _ in 0..2 {
        let wrong = app
            .post(
                "/v1/login/phone/complete",
                json!({"phone": "+46701234567", "code": "999999x"}),
            )
            .await;
        assert_eq!(wrong.code(), "INVALID_CREDENTIALS");
    }
    let login = app
        .post(
            "/v1/login/phone/complete",
            json!({"phone": "+46701234567", "code": code}),
        )
        .await;
    assert_eq!(login.status, StatusCode::OK, "{:?}", login.body);
    assert_eq!(app.verify(&token(&login)).await.amr, vec!["sms"]);

    app.post("/v1/login/phone/start", json!({"phone": "+46701234567"}))
        .await;
    let code = delivered(&app, &mailer, "+46701234567").await["code"]
        .as_str()
        .unwrap()
        .to_owned();
    for _ in 0..5 {
        app.post(
            "/v1/login/phone/complete",
            json!({"phone": "+46701234567", "code": "999999x"}),
        )
        .await;
    }
    let exhausted = app
        .post(
            "/v1/login/phone/complete",
            json!({"phone": "+46701234567", "code": code}),
        )
        .await;
    assert_eq!(
        exhausted.code(),
        "INVALID_CREDENTIALS",
        "the code is burnt after too many attempts"
    );
}

// r[verify authn.reset-password]
#[tokio::test(flavor = "multi_thread")]
async fn password_resets_replace_the_password_and_end_sessions() {
    let app = TestApp::new().await;
    let mailer = mailer(&app).await;
    app.human(EMAIL, PASSWORD).await;
    let session = app.login(EMAIL, PASSWORD).await;
    assert_eq!(
        app.post("/v1/password-reset/start", json!({"identifier": EMAIL}))
            .await
            .status,
        StatusCode::ACCEPTED
    );
    let link = delivered(&app, &mailer, EMAIL).await["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let reset = app
        .post(
            "/v1/password-reset/complete",
            json!({"token": link, "password": "a fresh password"}),
        )
        .await;
    assert_eq!(reset.status, StatusCode::OK, "{:?}", reset.body);
    let refresh = app
        .post(
            "/v1/refresh",
            json!({"refresh_token": session.body["refresh_token"]}),
        )
        .await;
    assert_eq!(refresh.code(), "SESSION_ENDED");
    assert_eq!(
        app.login(EMAIL, PASSWORD).await.code(),
        "INVALID_CREDENTIALS"
    );
    assert_eq!(
        app.login(EMAIL, "a fresh password").await.status,
        StatusCode::OK
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn changing_the_password_keeps_the_current_session() {
    let app = TestApp::new().await;
    app.human(EMAIL, PASSWORD).await;
    let current = app.login(EMAIL, PASSWORD).await;
    let other = app.login(EMAIL, PASSWORD).await;
    let changed = post_bearer(
        &app,
        "/v1/password/change",
        &token(&current),
        json!({"current": PASSWORD, "new": "another password"}),
    )
    .await;
    assert_eq!(changed.status, StatusCode::OK, "{:?}", changed.body);
    let kept = app
        .post(
            "/v1/refresh",
            json!({"refresh_token": current.body["refresh_token"]}),
        )
        .await;
    assert_eq!(kept.status, StatusCode::OK, "{:?}", kept.body);
    let ended = app
        .post(
            "/v1/refresh",
            json!({"refresh_token": other.body["refresh_token"]}),
        )
        .await;
    assert_eq!(ended.code(), "SESSION_ENDED");
}

// r[verify authn.invite.redeem]
#[tokio::test(flavor = "multi_thread")]
async fn invites_create_accounts_with_memberships() {
    let app = TestApp::new().await;
    let mailer = mailer(&app).await;
    app.control(
        Method::PUT,
        "/v1/catalog",
        Some(json!({"actions": [{"name": "workspace:read"}]})),
    )
    .await;
    let tenant = uuid::Uuid::now_v7();
    app.control(
        Method::PUT,
        &format!("/v1/tenants/{tenant}"),
        Some(json!({})),
    )
    .await;
    app.control(
        Method::PUT,
        &format!("/v1/tenants/{tenant}/roles/reader"),
        Some(json!({"policies": [{"action": "workspace:read", "effect": "allow"}]})),
    )
    .await;
    let invite = app
        .control(
            Method::POST,
            "/v1/invites",
            Some(json!({"email": "new@example.com", "tenant": tenant, "roles": ["reader"]})),
        )
        .await;
    assert_eq!(invite.status, StatusCode::CREATED, "{:?}", invite.body);
    assert!(
        !invite.body.to_string().contains("token"),
        "the token is only delivered"
    );
    let link = delivered(&app, &mailer, "new@example.com").await["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let redeemed = app
        .post(
            "/v1/invites/redeem",
            json!({"token": link, "password": "my new password"}),
        )
        .await;
    assert_eq!(redeemed.status, StatusCode::OK, "{:?}", redeemed.body);
    let again = app
        .post(
            "/v1/invites/redeem",
            json!({"token": link, "password": "my new password"}),
        )
        .await;
    assert_eq!(again.code(), "INVALID_CREDENTIALS");

    let selected = post_bearer(
        &app,
        "/v1/login/tenant",
        &token(&redeemed),
        json!({"tenant": tenant}),
    )
    .await;
    assert_eq!(selected.status, StatusCode::OK, "{:?}", selected.body);
    let claims = app.verify(&token(&selected)).await;
    let entitlements = app
        .control(
            Method::GET,
            &format!("/v1/subjects/{}/entitlements?tenant={tenant}", claims.sub),
            None,
        )
        .await;
    assert_eq!(entitlements.body["tenant"], json!(["workspace:read"]));
    assert_eq!(
        app.login("new@example.com", "my new password").await.status,
        StatusCode::OK
    );
}

// r[verify authn.invite.membership-id]
#[tokio::test(flavor = "multi_thread")]
async fn invites_can_name_the_membership_they_create() {
    let app = TestApp::new().await;
    let mailer = mailer(&app).await;
    let tenant = uuid::Uuid::now_v7();
    app.control(
        Method::PUT,
        &format!("/v1/tenants/{tenant}"),
        Some(json!({})),
    )
    .await;
    let membership = uuid::Uuid::now_v7();
    let invite = app
        .control(
            Method::POST,
            "/v1/invites",
            Some(json!({"email": "named@example.com", "tenant": tenant, "membership": membership})),
        )
        .await;
    assert_eq!(invite.status, StatusCode::CREATED, "{:?}", invite.body);
    let link = delivered(&app, &mailer, "named@example.com").await["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let redeemed = app
        .post(
            "/v1/invites/redeem",
            json!({"token": link, "password": "my new password"}),
        )
        .await;
    assert_eq!(redeemed.status, StatusCode::OK, "{:?}", redeemed.body);
    let created = app
        .control(Method::GET, &format!("/v1/memberships/{membership}"), None)
        .await;
    assert_eq!(created.status, StatusCode::OK, "{:?}", created.body);
    assert_eq!(created.body["tenant_id"], json!(tenant));

    // A second invite naming another membership in the same tenant conflicts.
    app.control(
        Method::POST,
        "/v1/invites",
        Some(json!({"email": "named@example.com", "tenant": tenant, "membership": uuid::Uuid::now_v7()})),
    )
    .await;
    let link = delivered(&app, &mailer, "named@example.com").await["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let conflicting = app
        .post(
            "/v1/invites/redeem",
            json!({"token": link, "password": "my new password"}),
        )
        .await;
    assert_eq!(conflicting.code(), "CONFLICT");
}

// r[verify authn.impersonation.actor-chain]
// r[verify authn.impersonation.time-bounded]
// r[verify token.access.actor-chain]
// r[verify authz.control-plane.capability]
#[tokio::test(flavor = "multi_thread")]
async fn impersonation_needs_the_capability_and_ends_with_the_impersonator() {
    let app = TestApp::new().await;
    let support = app.human("support@example.com", PASSWORD).await;
    let target = app.human(EMAIL, PASSWORD).await;
    let support_login = app.login("support@example.com", PASSWORD).await;
    let support_token = token(&support_login);
    let denied = post_bearer(
        &app,
        "/v1/impersonate",
        &support_token,
        json!({"subject": target}),
    )
    .await;
    assert_eq!(denied.code(), "FORBIDDEN");

    app.control(
        Method::PUT,
        "/v1/tenants/root/roles/SUPPORT",
        Some(json!({"policies": [{"action": "konklav:subject:impersonate", "effect": "allow"}]})),
    )
    .await;
    app.control(
        Method::POST,
        &format!("/v1/subjects/{support}/global-assignments"),
        Some(json!({"role": "SUPPORT"})),
    )
    .await;
    let impersonating = post_bearer(
        &app,
        "/v1/impersonate",
        &support_token,
        json!({"subject": target}),
    )
    .await;
    assert_eq!(
        impersonating.status,
        StatusCode::OK,
        "{:?}",
        impersonating.body
    );
    let claims = app.verify(&token(&impersonating)).await;
    assert_eq!(claims.sub.to_string(), target);
    assert_eq!(claims.act.unwrap().sub.to_string(), support);
    let session = app
        .control(Method::GET, &format!("/v1/sessions/{}", claims.sid), None)
        .await;
    let expires =
        chrono::DateTime::parse_from_rfc3339(session.body["expires_at"].as_str().unwrap()).unwrap();
    assert!(expires <= chrono::Utc::now() + chrono::Duration::minutes(61));

    app.with_bearer(Method::POST, "/v1/sign-out", &support_token)
        .await;
    let ended = app
        .with_bearer(Method::POST, "/v1/sign-out/others", &token(&impersonating))
        .await;
    assert_eq!(
        ended.code(),
        "SESSION_ENDED",
        "ending the impersonator's session ends the impersonation"
    );
}

// r[verify authn.impersonation.limits]
#[tokio::test(flavor = "multi_thread")]
async fn impersonation_cannot_reach_the_control_plane_or_change_authentication() {
    let app = TestApp::new().await;
    let support = app.human("support@example.com", PASSWORD).await;
    let admin = app.human(EMAIL, PASSWORD).await;
    app.control(
        Method::PUT,
        "/v1/tenants/root/roles/SUPPORT",
        Some(json!({"policies": [{"action": "konklav:subject:impersonate", "effect": "allow"}]})),
    )
    .await;
    for (subject, role) in [(&support, "SUPPORT"), (&admin, "konklav.admin")] {
        let assigned = app
            .control(
                Method::POST,
                &format!("/v1/subjects/{subject}/global-assignments"),
                Some(json!({"role": role})),
            )
            .await;
        assert_eq!(assigned.status, StatusCode::CREATED, "{:?}", assigned.body);
    }
    let support_token = token(&app.login("support@example.com", PASSWORD).await);
    let impersonating = post_bearer(
        &app,
        "/v1/impersonate",
        &support_token,
        json!({"subject": admin}),
    )
    .await;
    assert_eq!(
        impersonating.status,
        StatusCode::OK,
        "{:?}",
        impersonating.body
    );
    let as_admin = token(&impersonating);

    let control = app
        .with_bearer(Method::GET, "/v1/sessions", &as_admin)
        .await;
    assert_eq!(control.code(), "FORBIDDEN", "{:?}", control.body);
    let own = app
        .with_bearer(Method::GET, "/v1/capabilities", &as_admin)
        .await;
    assert_eq!(own.body["capabilities"], json!([]));
    for (uri, body) in [
        ("/v1/impersonate", json!({"subject": support})),
        ("/v1/mfa/totp", json!({})),
        ("/v1/mfa/email", json!({"email": "attacker@example.com"})),
        (
            "/v1/password/change",
            json!({"current": PASSWORD, "new": "a different password"}),
        ),
        ("/v1/sign-out/others", json!({})),
    ] {
        let refused = post_bearer(&app, uri, &as_admin, body).await;
        assert_eq!(refused.code(), "FORBIDDEN", "{uri}: {:?}", refused.body);
    }

    // The admin's own session still works.
    let admin_token = token(&app.login(EMAIL, PASSWORD).await);
    let control = app
        .with_bearer(Method::GET, "/v1/sessions", &admin_token)
        .await;
    assert_eq!(control.status, StatusCode::OK, "{:?}", control.body);
}

// r[verify challenge.delivery.no-replay]
#[tokio::test(flavor = "multi_thread")]
async fn delivery_requests_are_only_for_the_delivery_capability_and_expire() {
    let app = TestApp::new().await;
    let mailer = mailer(&app).await;
    let plain = app.service_token().await;
    passwordless_subject(&app, "email_link", "link@example.com").await;
    app.post(
        "/v1/login/email-link/start",
        json!({"email": "link@example.com"}),
    )
    .await;
    let hidden = app
        .with_bearer(
            Method::GET,
            "/v1/events/batch?after=0&kinds=delivery.requested",
            &plain,
        )
        .await;
    assert_eq!(hidden.body["events"], json!([]));
    assert!(delivered(&app, &mailer, "link@example.com").await["token"].is_string());

    {
        let mut conn = app.db.pool().get().await.unwrap();
        diesel::sql_query(
            "update event set payload = jsonb_set(payload, '{expires_at}', '0') where kind = 'delivery.requested'",
        )
        .execute(&mut conn)
        .await
        .unwrap();
    }
    assert_eq!(
        delivered(&app, &mailer, "link@example.com").await,
        Value::Null,
        "material is gone once expired"
    );
}
