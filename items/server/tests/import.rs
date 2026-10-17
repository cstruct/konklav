#![allow(clippy::too_many_lines)]

mod common;

use axum::http::{Method, StatusCode};
use common::TestApp;
use conclave_authn::TotpSecret;
use serde_json::json;
use sha2::{Digest, Sha256};

/// Produced by Python's argon2-cffi (t=3, m=64 MiB, p=4) for "hunter2".
const HUNTER2: &str = "$argon2id$v=19$m=65536,t=3,p=4$MVCOUWPIMIJHbBE8MJIPLg$dPyh03xOkyCVNP5STWcNJy8ENnhtBiv84a3FtUXX7Os";

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

// r[verify import.idempotent]
// r[verify import.credentials]
#[tokio::test(flavor = "multi_thread")]
async fn imported_password_hashes_keep_working_and_imports_rerun() {
    let app = TestApp::new().await;
    let subject = uuid::Uuid::now_v7();
    let credential = uuid::Uuid::now_v7();
    let subjects = json!({"subjects": [{"id": subject, "kind": "human"}]});
    let credentials = json!({"credentials": [{
        "id": credential, "subject": subject, "identifier": "Legacy@Example.com",
        "kind": "password", "password_hash": HUNTER2
    }]});
    for expected in [1, 0] {
        let reply = app
            .control(Method::POST, "/v1/import/subjects", Some(subjects.clone()))
            .await;
        assert_eq!(reply.body["imported"], expected, "{:?}", reply.body);
        let reply = app
            .control(
                Method::POST,
                "/v1/import/credentials",
                Some(credentials.clone()),
            )
            .await;
        assert_eq!(reply.body["imported"], expected, "{:?}", reply.body);
    }
    let login = app.login("legacy@example.com", "hunter2").await;
    assert_eq!(login.status, StatusCode::OK, "{:?}", login.body);
    assert_eq!(
        app.verify(login.body["access_token"].as_str().unwrap())
            .await
            .sub
            .to_string(),
        subject.to_string()
    );

    let bad = app
        .control(
            Method::POST,
            "/v1/import/credentials",
            Some(json!({"credentials": [{"id": uuid::Uuid::now_v7(), "subject": subject, "identifier": "x@y", "kind": "password", "password_hash": "plaintext"}]})),
        )
        .await;
    assert_eq!(
        bad.code(),
        "CONFLICT",
        "the database refuses non-Argon2 hashes"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn imported_secret_keys_keep_working() {
    let app = TestApp::new().await;
    let subject = uuid::Uuid::now_v7();
    let credential = uuid::Uuid::now_v7();
    app.control(
        Method::POST,
        "/v1/import/subjects",
        Some(json!({"subjects": [{"id": subject, "kind": "service"}]})),
    )
    .await;
    let slot = json!({"hash": HUNTER2, "created_at": "2026-01-01T00:00:00Z"});
    let reply = app
        .control(
            Method::POST,
            "/v1/import/credentials",
            Some(json!({"credentials": [{"id": credential, "subject": subject, "identifier": credential, "kind": "secret_key", "a": slot, "b": slot}]})),
        )
        .await;
    assert_eq!(reply.body["imported"], 1, "{:?}", reply.body);
    let login = app
        .post(
            "/v1/login/secret-key",
            json!({"key_id": credential, "secret": "hunter2"}),
        )
        .await;
    assert_eq!(login.status, StatusCode::OK, "{:?}", login.body);
}

// r[verify import.mfa]
#[tokio::test(flavor = "multi_thread")]
async fn imported_totp_seeds_are_encrypted_and_verify() {
    let app = TestApp::new().await;
    let subject = app.human("ada@example.com", "correct horse battery").await;
    let factor = uuid::Uuid::now_v7();
    let seed = TotpSecret::generate();
    let reply = app
        .control(
            Method::POST,
            "/v1/import/mfa-factors",
            Some(json!({"factors": [{"id": factor, "subject": subject, "kind": "totp", "seed_base32": seed.to_base32()}]})),
        )
        .await;
    assert_eq!(reply.body["imported"], 1, "{:?}", reply.body);
    let login = app.login("ada@example.com", "correct horse battery").await;
    let auth = format!("Bearer {}", login.body["access_token"].as_str().unwrap());
    let code = seed.code_at_step(chrono::Utc::now().timestamp() / 30);
    let stepped = app
        .send(
            Method::POST,
            "/v1/step-up",
            &[("authorization", &auth)],
            Some(json!({"factor_id": factor, "code": code})),
        )
        .await;
    assert_eq!(stepped.status, StatusCode::OK, "{:?}", stepped.body);
}

// r[verify import.sessions]
#[tokio::test(flavor = "multi_thread")]
async fn imported_sessions_refresh_with_the_carried_over_secret() {
    let app = TestApp::new().await;
    let subject = app.human("ada@example.com", "correct horse battery").await;
    let detail = app
        .control(Method::GET, &format!("/v1/subjects/{subject}"), None)
        .await;
    let credential = detail.body["credentials"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let session = uuid::Uuid::now_v7();
    let carried = uuid::Uuid::new_v4().to_string();
    let refresh_token = format!("{session}.{carried}");
    let reply = app
        .control(
            Method::POST,
            "/v1/import/sessions",
            Some(json!({"sessions": [{
                "id": session, "subject": subject, "credential": credential, "stage": "identity",
                "amr": ["pwd"], "auth_time": "2026-10-01T00:00:00Z", "version": 7,
                "refresh_hash": hex(&Sha256::digest(refresh_token.as_bytes())),
                "expires_at": (chrono::Utc::now() + chrono::Duration::days(5)).to_rfc3339(),
            }]})),
        )
        .await;
    assert_eq!(reply.body["imported"], 1, "{:?}", reply.body);
    let refreshed = app
        .post("/v1/refresh", json!({"refresh_token": refresh_token}))
        .await;
    assert_eq!(refreshed.status, StatusCode::OK, "{:?}", refreshed.body);
    let claims = app
        .verify(refreshed.body["access_token"].as_str().unwrap())
        .await;
    assert_eq!(claims.sid.to_string(), session.to_string());
    assert_eq!(claims.sv, 8, "the imported version carries on");
}

#[tokio::test(flavor = "multi_thread")]
async fn importing_needs_the_capability() {
    let app = TestApp::new().await;
    app.human("ops@example.com", "correct horse battery").await;
    let token = app
        .login("ops@example.com", "correct horse battery")
        .await
        .body["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let auth = format!("Bearer {token}");
    let reply = app
        .send(
            Method::POST,
            "/v1/import/subjects",
            &[("authorization", &auth)],
            Some(json!({"subjects": []})),
        )
        .await;
    assert_eq!(reply.code(), "FORBIDDEN");
}
