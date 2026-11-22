#![allow(clippy::too_many_lines)]

mod common;

use axum::http::{Method, StatusCode};
use common::TestApp;
use konklav_authn::TotpSecret;
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
    assert_eq!(bad.code(), "INVALID_REQUEST", "{:?}", bad.body);
}

// r[verify import.credentials.cost-limit]
#[tokio::test(flavor = "multi_thread")]
async fn hashes_that_cost_too_much_are_not_imported() {
    let app = TestApp::new().await;
    let (human, service) = (uuid::Uuid::now_v7(), uuid::Uuid::now_v7());
    app.control(
        Method::POST,
        "/v1/import/subjects",
        Some(json!({"subjects": [
            {"id": human, "kind": "human"}, {"id": service, "kind": "service"},
        ]})),
    )
    .await;
    // 4 GiB of memory for every login attempt.
    let costly = HUNTER2.replace("m=65536", "m=4194304");
    let slot = |hash: &str| json!({"hash": hash, "created_at": "2026-01-01T00:00:00Z"});
    let key = uuid::Uuid::now_v7();
    for credential in [
        json!({"id": uuid::Uuid::now_v7(), "subject": human, "identifier": "costly@example.com",
            "kind": "password", "password_hash": costly}),
        json!({"id": key, "subject": service, "identifier": key,
            "kind": "secret_key", "a": slot(HUNTER2), "b": slot(&costly)}),
    ] {
        let reply = app
            .control(
                Method::POST,
                "/v1/import/credentials",
                Some(json!({"credentials": [credential]})),
            )
            .await;
        assert_eq!(reply.code(), "INVALID_REQUEST", "{:?}", reply.body);
    }
    let login = app.login("costly@example.com", "hunter2").await;
    assert_eq!(login.code(), "INVALID_CREDENTIALS", "{:?}", login.body);
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

/// Produced by Python's argon2-cffi for "swordfish".
const SWORDFISH: &str = "$argon2id$v=19$m=65536,t=3,p=4$AIuJ/bg0xA1dNFOl/Y8xkw$gKt+ObjIzIEnOSKX6cVpsSdoPA5zgkfSkXwBXGlf/88";

// r[verify import.credentials.secret-key-rotation]
#[tokio::test(flavor = "multi_thread")]
async fn reimported_secret_keys_take_rotated_slots_but_passwords_do_not() {
    let app = TestApp::new().await;
    let (service, human) = (uuid::Uuid::now_v7(), uuid::Uuid::now_v7());
    let (key, password) = (uuid::Uuid::now_v7(), uuid::Uuid::now_v7());
    app.control(
        Method::POST,
        "/v1/import/subjects",
        Some(json!({"subjects": [{"id": service, "kind": "service"}, {"id": human, "kind": "human"}]})),
    )
    .await;
    let import = |hash: &str| {
        let slot = json!({"hash": hash, "created_at": "2026-01-01T00:00:00Z"});
        json!({"credentials": [
            {"id": key, "subject": service, "identifier": key, "kind": "secret_key", "a": slot, "b": slot},
            {"id": password, "subject": human, "identifier": "rotating@example.com", "kind": "password", "password_hash": hash},
        ]})
    };
    let first = app
        .control(
            Method::POST,
            "/v1/import/credentials",
            Some(import(HUNTER2)),
        )
        .await;
    assert_eq!(first.body["imported"], 2, "{:?}", first.body);
    let rotated = app
        .control(
            Method::POST,
            "/v1/import/credentials",
            Some(import(SWORDFISH)),
        )
        .await;
    assert_eq!(rotated.body["updated"], 1, "{:?}", rotated.body);
    assert_eq!(rotated.body["skipped"], 1, "{:?}", rotated.body);

    let with = |secret: &str| json!({"key_id": key, "secret": secret});
    assert_eq!(
        app.post("/v1/login/secret-key", with("swordfish"))
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        app.post("/v1/login/secret-key", with("hunter2"))
            .await
            .code(),
        "INVALID_CREDENTIALS"
    );
    assert_eq!(
        app.login("rotating@example.com", "hunter2").await.status,
        StatusCode::OK,
        "passwords keep the hash Konklav has"
    );
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

// r[verify authn.mfa.factor-listing]
#[tokio::test(flavor = "multi_thread")]
async fn subject_reads_show_mfa_factors_without_seeds() {
    let app = TestApp::new().await;
    let subject = app.human("ada@example.com", "correct horse battery").await;
    let (totp, email) = (uuid::Uuid::now_v7(), uuid::Uuid::now_v7());
    let seed = TotpSecret::generate().to_base32();
    let reply = app
        .control(
            Method::POST,
            "/v1/import/mfa-factors",
            Some(json!({"factors": [
                {"id": totp, "subject": subject, "kind": "totp", "seed_base32": seed},
                {"id": email, "subject": subject, "kind": "email_code", "email": "ada@example.com", "active": false},
            ]})),
        )
        .await;
    assert_eq!(reply.body["imported"], 2, "{:?}", reply.body);
    let detail = app
        .control(Method::GET, &format!("/v1/subjects/{subject}"), None)
        .await;
    let mut factors = detail.body["mfa_factors"].as_array().unwrap().clone();
    factors.sort_by_key(|f| f["kind"].as_str().unwrap().to_owned());
    let shown: Vec<_> = factors
        .iter()
        .map(|f| {
            (
                f["id"].clone(),
                f["kind"].clone(),
                f["active"].clone(),
                f.get("email").cloned(),
            )
        })
        .collect();
    assert_eq!(
        shown,
        vec![
            (
                json!(email),
                json!("email_code"),
                json!(false),
                Some(json!("ada@example.com"))
            ),
            (json!(totp), json!("totp"), json!(true), None),
        ]
    );
    let body = detail.body.to_string();
    assert!(
        !body.contains(&seed) && !body.contains("ciphertext"),
        "{body}"
    );
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

/// A human with a password credential, as `(subject, credential)`.
async fn person(app: &TestApp, email: &str) -> (String, String) {
    let subject = app.human(email, "correct horse battery").await;
    let detail = app
        .control(Method::GET, &format!("/v1/subjects/{subject}"), None)
        .await;
    let credential = detail.body["credentials"][0]["id"].as_str().unwrap();
    (subject, credential.to_owned())
}

/// A new tenant with `subject` as a member, as `(tenant, membership)`.
async fn member(app: &TestApp, subject: &str) -> (String, String) {
    let (tenant, membership) = (uuid::Uuid::now_v7(), uuid::Uuid::now_v7());
    let reply = app
        .control(
            Method::PUT,
            &format!("/v1/tenants/{tenant}"),
            Some(json!({})),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.body);
    let reply = app
        .control(
            Method::PUT,
            &format!("/v1/memberships/{membership}"),
            Some(json!({"subject": subject, "tenant": tenant})),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.body);
    (tenant.to_string(), membership.to_string())
}

// r[verify import.sessions.consistent]
#[tokio::test(flavor = "multi_thread")]
async fn imported_sessions_must_fit_their_subject() {
    let app = TestApp::new().await;
    let reply = app
        .control(
            Method::PUT,
            "/v1/catalog",
            Some(json!({"session_flags": [{"name": "device_bound", "kind": "assertive"}]})),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    let (ada, ada_credential) = person(&app, "ada@example.com").await;
    let (eve, eve_credential) = person(&app, "eve@example.com").await;
    let (_, bob_credential) = person(&app, "bob@example.com").await;
    let (ada_tenant, ada_membership) = member(&app, &ada).await;
    let (eve_tenant, eve_membership) = member(&app, &eve).await;

    let import = async |fields: serde_json::Value| {
        let id = uuid::Uuid::now_v7();
        let mut session = json!({
            "id": id, "subject": eve, "credential": eve_credential, "stage": "identity",
            "amr": ["pwd"], "auth_time": "2026-10-01T00:00:00Z", "version": 1,
            "refresh_hash": hex(&Sha256::digest(b"refresh")),
            "expires_at": (chrono::Utc::now() + chrono::Duration::days(5)).to_rfc3339(),
        });
        for (key, value) in fields.as_object().unwrap() {
            session[key] = value.clone();
        }
        let reply = app
            .control(
                Method::POST,
                "/v1/import/sessions",
                Some(json!({"sessions": [session]})),
            )
            .await;
        (id.to_string(), reply)
    };
    let in_tenant = |tenant: &str, membership: &str| json!({"stage": "tenant", "tenant": tenant, "membership": membership});
    for (fields, problem) in [
        (
            json!({"subject": ada}),
            "credential belongs to another subject",
        ),
        (
            json!({"credential": uuid::Uuid::now_v7()}),
            "credential does not exist",
        ),
        (
            json!({"impersonator": ada, "credential": bob_credential}),
            "credential belongs to another subject",
        ),
        (
            in_tenant(&ada_tenant, &ada_membership),
            "membership belongs to another subject",
        ),
        (
            in_tenant(&ada_tenant, &eve_membership),
            "membership is in another tenant",
        ),
        (
            in_tenant(&eve_tenant, &uuid::Uuid::now_v7().to_string()),
            "membership does not exist",
        ),
        (
            json!({"tenant": ada_tenant}),
            "needs a tenant and a membership",
        ),
        (
            json!({"stage": "tenant"}),
            "needs a tenant and a membership",
        ),
        (
            json!({"flags": ["device_bound", "undeclared"]}),
            "`undeclared` is not in the catalog",
        ),
    ] {
        let (id, reply) = import(fields.clone()).await;
        assert_eq!(
            reply.code(),
            "INVALID_REQUEST",
            "{fields}: {:?}",
            reply.body
        );
        let message = reply.body["error"]["message"].as_str().unwrap();
        assert!(
            message.contains(&id) && message.contains(problem),
            "{fields}: {message}"
        );
    }

    for fields in [
        json!({"flags": ["device_bound"]}),
        in_tenant(&eve_tenant, &eve_membership),
        // Ada impersonating Eve, with Ada's credential.
        json!({"impersonator": ada, "credential": ada_credential}),
    ] {
        let (_, reply) = import(fields.clone()).await;
        assert_eq!(reply.body["imported"], 1, "{fields}: {:?}", reply.body);
    }
}

// r[verify import.subjects.disabled]
// r[verify subject.state]
#[tokio::test(flavor = "multi_thread")]
async fn importing_a_subject_as_disabled_ends_its_sessions() {
    let app = TestApp::new().await;
    let (ada, credential) = person(&app, "ada@example.com").await;
    let login = app.login("ada@example.com", "correct horse battery").await;
    let refresh = login.body["refresh_token"].as_str().unwrap().to_owned();
    let session = app
        .verify(login.body["access_token"].as_str().unwrap())
        .await
        .sid;
    let revoked = async |session: &str| {
        let reply = app
            .control(Method::GET, &format!("/v1/sessions/{session}"), None)
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
        !reply.body["revoked_at"].is_null()
    };
    assert!(!revoked(&session.to_string()).await);

    let reply = app
        .control(
            Method::POST,
            "/v1/import/subjects",
            Some(json!({"subjects": [{"id": ada, "kind": "human", "state": "disabled"}]})),
        )
        .await;
    assert_eq!(reply.body["skipped"], 1, "{:?}", reply.body);
    assert!(revoked(&session.to_string()).await);
    let refreshed = app
        .post("/v1/refresh", json!({"refresh_token": refresh}))
        .await;
    assert_ne!(refreshed.status, StatusCode::OK, "{:?}", refreshed.body);

    // A session carried over for the disabled subject arrives revoked.
    let carried = uuid::Uuid::now_v7();
    let reply = app
        .control(
            Method::POST,
            "/v1/import/sessions",
            Some(json!({"sessions": [{
                "id": carried, "subject": ada, "credential": credential, "stage": "identity",
                "amr": ["pwd"], "auth_time": "2026-10-01T00:00:00Z", "version": 1,
                "refresh_hash": hex(&Sha256::digest(b"refresh")),
                "expires_at": (chrono::Utc::now() + chrono::Duration::days(5)).to_rfc3339(),
            }]})),
        )
        .await;
    assert_eq!(reply.body["imported"], 1, "{:?}", reply.body);
    assert!(revoked(&carried.to_string()).await);
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
