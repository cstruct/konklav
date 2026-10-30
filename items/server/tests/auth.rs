mod common;

use axum::http::{Method, StatusCode};
use common::{ORIGIN, TestApp};
use konklav_token::TokenKind;
use serde_json::json;

const EMAIL: &str = "ada@example.com";
const PASSWORD: &str = "correct horse battery";

fn token(reply: &common::Reply) -> String {
    reply.body["access_token"]
        .as_str()
        .expect("access token")
        .to_owned()
}

fn refresh_token(reply: &common::Reply) -> String {
    reply.body["refresh_token"]
        .as_str()
        .expect("refresh token")
        .to_owned()
}

// r[verify authn.login.methods]
// r[verify token.access.jwt]
// r[verify token.access.standard-claims]
// r[verify token.access.session-claims]
// r[verify token.keys.jwks]
// r[verify token.access.no-grants]
#[tokio::test(flavor = "multi_thread")]
async fn password_login_issues_verifiable_tokens() {
    let app = TestApp::new().await;
    let subject = app.human(EMAIL, PASSWORD).await;

    let reply = app.login("  ADA@example.com ", PASSWORD).await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    assert_eq!(reply.body["token_type"], "Bearer");
    assert!(reply.body["cursor"].is_i64());
    let claims = app.verify(&token(&reply)).await;
    assert_eq!(claims.sub.to_string(), subject);
    assert_eq!(claims.knd, TokenKind::Identity);
    assert_eq!(claims.amr, vec!["pwd"]);
    assert_eq!(claims.sv, 1);
    assert!(claims.exp - claims.iat <= 15 * 60);
    assert_eq!(claims.sid.to_string(), reply.body["session_id"]);
    let payload = token(&reply).split('.').nth(1).unwrap().to_owned();
    let payload =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload).unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    assert!(payload.get("az").is_none(), "tokens carry no grants");
}

// r[verify platform.error.no-enumeration]
// r[verify authn.login.timing]
#[tokio::test(flavor = "multi_thread")]
async fn failed_logins_do_not_reveal_what_was_wrong() {
    let app = TestApp::new().await;
    app.human(EMAIL, PASSWORD).await;
    let wrong_password = app.login(EMAIL, "not the password").await;
    let unknown = app.login("nobody@example.com", PASSWORD).await;
    assert_eq!(wrong_password.status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong_password.body, unknown.body);
    assert_eq!(wrong_password.code(), "INVALID_CREDENTIALS");
}

// r[verify authn.login.rate-limit]
// r[verify platform.error.retry-after]
#[tokio::test(flavor = "multi_thread")]
async fn repeated_failures_are_rate_limited_per_identifier() {
    let app = TestApp::new().await;
    app.human(EMAIL, PASSWORD).await;
    for _ in 0..30 {
        assert_eq!(
            app.login(EMAIL, "wrong password").await.code(),
            "INVALID_CREDENTIALS"
        );
    }
    let limited = app.login(EMAIL, PASSWORD).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.code(), "RATE_LIMITED");
    let wait: u32 = limited.headers["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((60..=90).contains(&wait), "{wait}");
    // Other identifiers are unaffected, including unknown ones.
    assert_eq!(
        app.login("other@example.com", "x").await.code(),
        "INVALID_CREDENTIALS"
    );
}

// r[verify authn.login.rate-limit]
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_failures_cannot_exceed_the_limit() {
    let app = TestApp::new().await;
    app.human(EMAIL, PASSWORD).await;
    let burst = (0..45).map(|_| app.login(EMAIL, "wrong password"));
    let replies = futures_util::future::join_all(burst).await;
    let checked = replies
        .iter()
        .filter(|reply| reply.code() == "INVALID_CREDENTIALS")
        .count();
    assert!(checked <= 30, "{checked} attempts were checked");
    assert_eq!(app.login(EMAIL, PASSWORD).await.code(), "RATE_LIMITED");
}

// r[verify authn.login.rate-limit]
#[tokio::test(flavor = "multi_thread")]
async fn password_checks_in_step_up_count_toward_the_limit() {
    let app = TestApp::new().await;
    app.human(EMAIL, PASSWORD).await;
    let session = token(&app.login(EMAIL, PASSWORD).await);
    let auth = format!("Bearer {session}");
    for _ in 0..30 {
        let step_up = app
            .send(
                Method::POST,
                "/v1/step-up",
                &[("authorization", &auth)],
                Some(json!({"password": "wrong password"})),
            )
            .await;
        assert_eq!(step_up.code(), "INVALID_CREDENTIALS");
    }
    assert_eq!(app.login(EMAIL, PASSWORD).await.code(), "RATE_LIMITED");
}

// r[verify authn.login.rate-limit]
#[tokio::test(flavor = "multi_thread")]
async fn one_address_cannot_try_many_identifiers() {
    let app = TestApp::new().await;
    let login = |peer: &str, n: usize| {
        let peer = peer.parse().unwrap();
        let app = &app;
        async move {
            app.send_from(
                Some(peer),
                Method::POST,
                "/v1/login/password",
                &[],
                Some(json!({"identifier": format!("user{n}@example.com"), "password": "x"})),
            )
            .await
        }
    };
    for n in 0..100 {
        assert_eq!(
            login("203.0.113.9:1000", n).await.code(),
            "INVALID_CREDENTIALS"
        );
    }
    assert_eq!(login("203.0.113.9:1001", 100).await.code(), "RATE_LIMITED");
    assert_eq!(
        login("198.51.100.1:1000", 100).await.code(),
        "INVALID_CREDENTIALS",
        "other addresses are unaffected"
    );
}

// r[verify platform.server.client-address]
#[tokio::test(flavor = "multi_thread")]
async fn trusted_proxies_report_the_client_address() {
    let app = TestApp::with_auth(|auth| {
        auth.trusted_proxies = vec!["10.0.0.1".parse().unwrap()];
    })
    .await;
    let login = |forwarded: &'static str, n: usize| {
        let app = &app;
        async move {
            app.send_from(
                Some("10.0.0.1:443".parse().unwrap()),
                Method::POST,
                "/v1/login/password",
                &[("x-forwarded-for", forwarded)],
                Some(json!({"identifier": format!("user{n}@example.com"), "password": "x"})),
            )
            .await
        }
    };
    for n in 0..100 {
        // The client varies what it claims; the proxy's hop doesn't.
        let claim = if n % 2 == 0 {
            "1.1.1.1, 203.0.113.9"
        } else {
            "2.2.2.2, 203.0.113.9"
        };
        assert_eq!(login(claim, n).await.code(), "INVALID_CREDENTIALS");
    }
    assert_eq!(login("203.0.113.9", 100).await.code(), "RATE_LIMITED");
    assert_eq!(
        login("198.51.100.1", 100).await.code(),
        "INVALID_CREDENTIALS"
    );
}

// r[verify session.version]
// r[verify session.refresh.rotation]
#[tokio::test(flavor = "multi_thread")]
async fn refresh_rotates_supersedes_old_tokens_and_detects_reuse() {
    let app = TestApp::new().await;
    app.human(EMAIL, PASSWORD).await;
    let login = app.login(EMAIL, PASSWORD).await;
    let first_access = token(&login);
    let first_refresh = refresh_token(&login);

    let refreshed = app
        .post("/v1/refresh", json!({"refresh_token": first_refresh}))
        .await;
    assert_eq!(refreshed.status, StatusCode::OK, "{:?}", refreshed.body);
    let second_refresh = refresh_token(&refreshed);
    assert_ne!(second_refresh, first_refresh);
    assert_eq!(app.verify(&token(&refreshed)).await.sv, 2);

    // The pre-refresh access token is superseded.
    let stale = app
        .with_bearer(Method::POST, "/v1/sign-out/others", &first_access)
        .await;
    assert_eq!(stale.code(), "SESSION_ENDED");

    // Replaying the rotated-away refresh token ends the session for good.
    let replay = app
        .post("/v1/refresh", json!({"refresh_token": first_refresh}))
        .await;
    assert_eq!(replay.code(), "SESSION_ENDED");
    let after = app
        .post("/v1/refresh", json!({"refresh_token": second_refresh}))
        .await;
    assert_eq!(after.code(), "SESSION_ENDED");
    let current = app
        .with_bearer(Method::POST, "/v1/sign-out/others", &token(&refreshed))
        .await;
    assert_eq!(current.code(), "SESSION_ENDED");
}

// r[verify session.server-side]
// r[verify platform.idempotency.write-cursor]
#[tokio::test(flavor = "multi_thread")]
async fn sign_out_ends_only_the_chosen_sessions() {
    let app = TestApp::new().await;
    app.human(EMAIL, PASSWORD).await;
    let a = app.login(EMAIL, PASSWORD).await;
    let b = app.login(EMAIL, PASSWORD).await;
    let c = app.login(EMAIL, PASSWORD).await;

    let others = app
        .with_bearer(Method::POST, "/v1/sign-out/others", &token(&a))
        .await;
    assert_eq!(others.status, StatusCode::OK, "{:?}", others.body);
    assert!(others.body["cursor"].is_i64());
    for ended in [&b, &c] {
        let refresh = app
            .post(
                "/v1/refresh",
                json!({"refresh_token": refresh_token(ended)}),
            )
            .await;
        assert_eq!(refresh.code(), "SESSION_ENDED");
    }

    let out = app
        .with_bearer(Method::POST, "/v1/sign-out", &token(&a))
        .await;
    assert_eq!(out.status, StatusCode::OK);
    let refresh = app
        .post("/v1/refresh", json!({"refresh_token": refresh_token(&a)}))
        .await;
    assert_eq!(refresh.code(), "SESSION_ENDED");
}

// r[verify session.browser.cookie]
// r[verify session.browser.csrf]
// r[verify session.client-kind]
#[tokio::test(flavor = "multi_thread")]
async fn browsers_get_http_only_cookies_and_must_pass_csrf_checks() {
    let app = TestApp::new().await;
    app.human(EMAIL, PASSWORD).await;
    let body = json!({"identifier": EMAIL, "password": PASSWORD, "client": "browser"});

    let no_origin = app
        .send(Method::POST, "/v1/login/password", &[], Some(body.clone()))
        .await;
    assert_eq!(no_origin.code(), "FORBIDDEN");
    let evil = [
        ("origin", "https://evil.example"),
        ("x-konklav-client", "web"),
    ];
    assert_eq!(
        app.send(
            Method::POST,
            "/v1/login/password",
            &evil,
            Some(body.clone())
        )
        .await
        .code(),
        "FORBIDDEN"
    );
    let no_header = [("origin", ORIGIN)];
    assert_eq!(
        app.send(
            Method::POST,
            "/v1/login/password",
            &no_header,
            Some(body.clone())
        )
        .await
        .code(),
        "FORBIDDEN"
    );

    let browser = [("origin", ORIGIN), ("x-konklav-client", "web")];
    let login = app
        .send(Method::POST, "/v1/login/password", &browser, Some(body))
        .await;
    assert_eq!(login.status, StatusCode::OK, "{:?}", login.body);
    assert!(
        login.body.get("refresh_token").is_none(),
        "browsers never see the refresh token"
    );
    let cookies = login.set_cookies();
    assert_eq!(cookies.len(), 1);
    // The `__Host-` prefix needs `Path=/` and no `Domain`.
    let cookie = &cookies[0];
    assert!(cookie.starts_with("__Host-konklav_refresh="), "{cookie}");
    for attribute in ["HttpOnly", "SameSite=Strict", "Secure", "Path=/;"] {
        assert!(cookie.contains(attribute), "{cookie} lacks {attribute}");
    }
    assert!(!cookie.contains("Domain"), "{cookie}");
    let value = cookies[0].split(';').next().unwrap().to_owned();

    // Refreshing with the cookie needs the same CSRF checks.
    let cookie_only = [("cookie", value.as_str())];
    assert_eq!(
        app.send(Method::POST, "/v1/refresh", &cookie_only, None)
            .await
            .code(),
        "FORBIDDEN"
    );
    let with_cookie = [
        ("origin", ORIGIN),
        ("x-konklav-client", "web"),
        ("cookie", value.as_str()),
    ];
    let refreshed = app
        .send(Method::POST, "/v1/refresh", &with_cookie, None)
        .await;
    assert_eq!(refreshed.status, StatusCode::OK, "{:?}", refreshed.body);
    let rotated = refreshed.set_cookies()[0]
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    assert_ne!(rotated, value);

    let sign_out = [
        ("origin", ORIGIN),
        ("x-konklav-client", "web"),
        ("cookie", rotated.as_str()),
    ];
    let out = app
        .send(Method::POST, "/v1/sign-out", &sign_out, None)
        .await;
    assert_eq!(out.status, StatusCode::OK);
    assert!(out.set_cookies().iter().all(|c| c.contains("Max-Age=0")));
    let again = [
        ("origin", ORIGIN),
        ("x-konklav-client", "web"),
        ("cookie", rotated.as_str()),
    ];
    assert_eq!(
        app.send(Method::POST, "/v1/refresh", &again, None)
            .await
            .code(),
        "SESSION_ENDED"
    );
}

// r[verify subject.kind]
// r[verify credential.secret-key.dual]
// r[verify credential.secret-key.hashed]
#[tokio::test(flavor = "multi_thread")]
async fn service_principals_log_in_with_either_secret_key_slot() {
    let app = TestApp::new().await;
    let id = uuid::Uuid::now_v7();
    app.control(
        Method::PUT,
        &format!("/v1/subjects/{id}"),
        Some(json!({"kind": "service"})),
    )
    .await;
    let password = app
        .control(
            Method::POST,
            &format!("/v1/subjects/{id}/credentials"),
            Some(json!({"kind": "password", "identifier": "svc", "password": "long enough"})),
        )
        .await;
    assert_eq!(
        password.code(),
        "INVALID_REQUEST",
        "no passwords for services"
    );

    let created = app
        .control(
            Method::POST,
            &format!("/v1/subjects/{id}/credentials"),
            Some(json!({"kind": "secret_key"})),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    let key_id = created.body["credential"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        !created.body.to_string().contains("$argon2"),
        "hashes never leave"
    );
    let secret = |presented: &serde_json::Value| {
        let presented = presented.as_str().unwrap();
        presented.split_once('.').unwrap().1.to_owned()
    };
    let old_a = secret(&created.body["secret_keys"]["a"]);
    let b = secret(&created.body["secret_keys"]["b"]);
    assert_ne!(old_a, b);
    let login = |secret: String| {
        let key_id = key_id.clone();
        let app = &app;
        async move {
            app.post(
                "/v1/login/secret-key",
                json!({"key_id": key_id, "secret": secret}),
            )
            .await
        }
    };

    let with_a = login(old_a.clone()).await;
    assert_eq!(with_a.status, StatusCode::OK, "{:?}", with_a.body);
    assert_eq!(app.verify(&token(&with_a)).await.amr, vec!["sk"]);
    assert_eq!(login(b.clone()).await.status, StatusCode::OK);

    // Rotating a replaces only a: b keeps working throughout.
    let rotated = app
        .control(
            Method::POST,
            &format!("/v1/credentials/{key_id}/slots/a/rotate"),
            None,
        )
        .await;
    assert_eq!(rotated.status, StatusCode::OK, "{:?}", rotated.body);
    assert_eq!(rotated.body["slot"], "a");
    let new_a = secret(&rotated.body["secret_key"]);
    assert_eq!(login(new_a).await.status, StatusCode::OK);
    assert_eq!(login(b).await.status, StatusCode::OK);
    assert_eq!(login(old_a).await.code(), "INVALID_CREDENTIALS");
    let wrong = app
        .post(
            "/v1/login/secret-key",
            json!({"key_id": key_id, "secret": "nope"}),
        )
        .await;
    assert_eq!(wrong.code(), "INVALID_CREDENTIALS");
}

// r[verify credential.revocation-ends-sessions]
// r[verify credential.linked]
#[tokio::test(flavor = "multi_thread")]
async fn replacing_a_password_ends_its_sessions() {
    let app = TestApp::new().await;
    let subject = app.human(EMAIL, PASSWORD).await;
    let session = app.login(EMAIL, PASSWORD).await;
    let detail = app
        .control(Method::GET, &format!("/v1/subjects/{subject}"), None)
        .await;
    let credential = detail.body["credentials"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let replaced = app
        .control(
            Method::POST,
            &format!("/v1/credentials/{credential}/replace"),
            Some(json!({"password": "a brand new password"})),
        )
        .await;
    assert_eq!(replaced.status, StatusCode::CREATED, "{:?}", replaced.body);
    assert_eq!(replaced.body["replaces"], credential.as_str());
    assert!(replaced.body["cursor"].is_i64());

    assert_eq!(
        app.login(EMAIL, PASSWORD).await.code(),
        "INVALID_CREDENTIALS"
    );
    assert_eq!(
        app.login(EMAIL, "a brand new password").await.status,
        StatusCode::OK
    );
    let refresh = app
        .post(
            "/v1/refresh",
            json!({"refresh_token": refresh_token(&session)}),
        )
        .await;
    assert_eq!(refresh.code(), "SESSION_ENDED");

    let detail = app
        .control(Method::GET, &format!("/v1/subjects/{subject}"), None)
        .await;
    assert_eq!(
        detail.body["credentials"].as_array().unwrap().len(),
        2,
        "history is kept"
    );
}

// r[verify subject.state]
// r[verify session.refresh.recompute]
#[tokio::test(flavor = "multi_thread")]
async fn disabling_a_subject_ends_its_sessions_and_blocks_login() {
    let app = TestApp::new().await;
    let subject = app.human(EMAIL, PASSWORD).await;
    let session = app.login(EMAIL, PASSWORD).await;
    let disabled = app
        .control(
            Method::POST,
            &format!("/v1/subjects/{subject}/disable"),
            None,
        )
        .await;
    assert_eq!(disabled.body["state"], "disabled");
    assert!(disabled.body["cursor"].is_i64());
    assert_eq!(
        app.login(EMAIL, PASSWORD).await.code(),
        "INVALID_CREDENTIALS"
    );
    let refresh = app
        .post(
            "/v1/refresh",
            json!({"refresh_token": refresh_token(&session)}),
        )
        .await;
    assert_eq!(refresh.code(), "SESSION_ENDED");

    app.control(
        Method::POST,
        &format!("/v1/subjects/{subject}/enable"),
        None,
    )
    .await;
    assert_eq!(app.login(EMAIL, PASSWORD).await.status, StatusCode::OK);
}

// r[verify credential.mfa-requirement]
// r[verify token.access.kind]
#[tokio::test(flavor = "multi_thread")]
async fn credentials_requiring_mfa_only_get_a_partial_token() {
    let app = TestApp::new().await;
    let id = uuid::Uuid::now_v7();
    app.control(
        Method::PUT,
        &format!("/v1/subjects/{id}"),
        Some(json!({"kind": "human"})),
    )
    .await;
    app.control(
        Method::POST,
        &format!("/v1/subjects/{id}/credentials"),
        Some(json!({"kind": "password", "identifier": EMAIL, "password": PASSWORD, "mfa_factors_required": 1})),
    )
    .await;
    let login = app.login(EMAIL, PASSWORD).await;
    assert_eq!(login.body["token_kind"], "partial");
    assert!(login.body.get("refresh_token").is_none());
    assert_eq!(app.verify(&token(&login)).await.knd, TokenKind::Partial);
}

// r[verify session.admin]
#[tokio::test(flavor = "multi_thread")]
async fn operators_list_and_revoke_sessions() {
    let app = TestApp::new().await;
    let subject = app.human(EMAIL, PASSWORD).await;
    let a = app.login(EMAIL, PASSWORD).await;
    app.login(EMAIL, PASSWORD).await;

    let listed = app
        .control(
            Method::GET,
            &format!("/v1/sessions?subject={subject}&active=true"),
            None,
        )
        .await;
    assert_eq!(listed.body["sessions"].as_array().unwrap().len(), 2);
    let empty = app
        .control(Method::POST, "/v1/sessions/revoke", Some(json!({})))
        .await;
    assert_eq!(
        empty.code(),
        "INVALID_REQUEST",
        "an empty filter never means everything"
    );

    let keep = a.body["session_id"].as_str().unwrap();
    let revoked = app
        .control(
            Method::POST,
            "/v1/sessions/revoke",
            Some(json!({"subject": subject, "keep": keep})),
        )
        .await;
    assert_eq!(revoked.body["revoked"].as_array().unwrap().len(), 1);
    let listed = app
        .control(
            Method::GET,
            &format!("/v1/sessions?subject={subject}&active=true"),
            None,
        )
        .await;
    assert_eq!(listed.body["sessions"][0]["id"], keep);
    let one = app
        .control(Method::GET, &format!("/v1/sessions/{keep}"), None)
        .await;
    assert_eq!(one.body["subject_id"], subject.as_str());
}

// r[verify token.keys.break-glass]
#[tokio::test(flavor = "multi_thread")]
async fn revoking_the_signing_key_stops_issuance_and_unpublishes_it() {
    let app = TestApp::new().await;
    app.human(EMAIL, PASSWORD).await;
    let kid = app.state.auth.signer.kid().to_owned();
    let revoked = app
        .control(
            Method::POST,
            &format!("/v1/signing-keys/{kid}/revoke"),
            None,
        )
        .await;
    assert_eq!(revoked.body["revoked"], true);

    let login = app.login(EMAIL, PASSWORD).await;
    assert_eq!(login.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(login.code(), "SIGNING_KEY_UNAVAILABLE");
    let jwks = app
        .send(Method::GET, "/.well-known/jwks.json", &[], None)
        .await;
    assert_eq!(jwks.body["keys"], json!([]));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_control_plane_requires_its_token() {
    let app = TestApp::new().await;
    let id = uuid::Uuid::now_v7();
    let anonymous = app
        .send(
            Method::PUT,
            &format!("/v1/subjects/{id}"),
            &[],
            Some(json!({"kind": "human"})),
        )
        .await;
    assert_eq!(anonymous.code(), "UNAUTHENTICATED");
    let wrong = app
        .send(
            Method::PUT,
            &format!("/v1/subjects/{id}"),
            &[("authorization", "Bearer nope")],
            Some(json!({"kind": "human"})),
        )
        .await;
    assert_eq!(wrong.code(), "UNAUTHENTICATED");
}

// r[verify platform.idempotency.client-ids]
#[tokio::test(flavor = "multi_thread")]
async fn creating_subjects_is_idempotent() {
    let app = TestApp::new().await;
    let id = uuid::Uuid::now_v7();
    let uri = format!("/v1/subjects/{id}");
    assert_eq!(
        app.control(Method::PUT, &uri, Some(json!({"kind": "human"})))
            .await
            .status,
        StatusCode::CREATED
    );
    assert_eq!(
        app.control(Method::PUT, &uri, Some(json!({"kind": "human"})))
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        app.control(Method::PUT, &uri, Some(json!({"kind": "service"})))
            .await
            .code(),
        "CONFLICT"
    );
    let bad = app
        .control(Method::PUT, &uri, Some(json!({"kind": "robot"})))
        .await;
    assert_eq!(bad.code(), "INVALID_REQUEST");
}

// r[verify credential.password.hash-input]
#[tokio::test(flavor = "multi_thread")]
async fn password_credentials_can_be_created_from_an_argon2id_hash() {
    let app = TestApp::new().await;
    let subject = uuid::Uuid::now_v7();
    app.control(
        Method::PUT,
        &format!("/v1/subjects/{subject}"),
        Some(json!({"kind": "human"})),
    )
    .await;
    let create = |body: serde_json::Value| {
        let app = &app;
        async move {
            app.control(
                Method::POST,
                &format!("/v1/subjects/{subject}/credentials"),
                Some(body),
            )
            .await
        }
    };

    let argon2i = "$argon2i$v=19$m=16,t=2,p=1$c29tZXNhbHQ$Iv7FuOybn2c7RtUrVZWQjQ";
    let bcrypt = "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW";
    for invalid in [
        json!({"kind": "password", "identifier": EMAIL, "password_hash": bcrypt}),
        json!({"kind": "password", "identifier": EMAIL, "password_hash": argon2i}),
        json!({"kind": "password", "identifier": EMAIL, "password_hash": "$argon2id$v=19$m=bad"}),
        json!({"kind": "password", "identifier": EMAIL, "password": PASSWORD, "password_hash": "x"}),
        json!({"kind": "password", "identifier": EMAIL}),
    ] {
        let reply = create(invalid.clone()).await;
        assert_eq!(reply.code(), "INVALID_REQUEST", "{invalid}");
    }

    // Cheap parameters, so the login below verifies and then rehashes.
    let hashed = konklav_authn::PasswordHasher::new(8, 1, 1)
        .unwrap()
        .hash(PASSWORD);
    let created =
        create(json!({"kind": "password", "identifier": EMAIL, "password_hash": hashed})).await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    let login = app.login(EMAIL, PASSWORD).await;
    assert_eq!(login.status, StatusCode::OK, "{:?}", login.body);
    assert_eq!(
        app.login(EMAIL, "wrong password").await.code(),
        "INVALID_CREDENTIALS"
    );
}
