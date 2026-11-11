//! Link-only invites, which whoever holds the link redeems, and the preview
//! that shows anyone holding a token what an invite is for. Emailed invites'
//! own tests are in `flows.rs`; the ones here check they are unchanged where
//! link-only invites differ.

#![allow(clippy::too_many_lines)]

mod common;

use axum::http::{Method, StatusCode};
use common::{Reply, TestApp};
use diesel_async::RunQueryDsl;
use serde_json::{Value, json};

const PASSWORD: &str = "correct horse battery";

#[derive(diesel::QueryableByName)]
struct Count {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    count: i64,
}

/// A service principal allowed to read the change feed's delivery requests
/// and invite events, like a relying system's worker.
async fn worker(app: &TestApp) -> String {
    let token = app.service_token().await;
    let claims = app.verify(&token).await;
    for role in ["konklav.delivery", "konklav.admin"] {
        let assigned = app
            .control(
                Method::POST,
                &format!("/v1/subjects/{}/global-assignments", claims.sub),
                Some(json!({"role": role})),
            )
            .await;
        assert_eq!(assigned.status, StatusCode::CREATED, "{:?}", assigned.body);
    }
    token
}

async fn events(app: &TestApp, worker: &str, kind: &str) -> Vec<Value> {
    let batch = app
        .with_bearer(
            Method::GET,
            &format!("/v1/events/batch?after=0&kinds={kind}&limit=1000"),
            worker,
        )
        .await;
    assert_eq!(batch.status, StatusCode::OK, "{:?}", batch.body);
    batch.body["events"].as_array().unwrap().clone()
}

async fn tenant_with_reader(app: &TestApp) -> String {
    app.control(
        Method::PUT,
        "/v1/catalog",
        Some(json!({"actions": [{"name": "record:read"}]})),
    )
    .await;
    let tenant = uuid::Uuid::now_v7().to_string();
    let created = app
        .control(
            Method::PUT,
            &format!("/v1/tenants/{tenant}"),
            Some(json!({})),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    app.control(
        Method::PUT,
        &format!("/v1/tenants/{tenant}/roles/viewer"),
        Some(json!({"policies": [{"action": "record:read", "effect": "allow"}]})),
    )
    .await;
    tenant
}

async fn invite(app: &TestApp, body: Value) -> Reply {
    app.control(Method::POST, "/v1/invites", Some(body)).await
}

async fn preview(app: &TestApp, token: &str) -> Reply {
    app.post("/v1/invites/preview", json!({"token": token}))
        .await
}

async fn redeem_signed_in(app: &TestApp, access: &str, body: Value) -> Reply {
    let auth = format!("Bearer {access}");
    app.send(
        Method::POST,
        "/v1/invites/redeem",
        &[("authorization", &auth)],
        Some(body),
    )
    .await
}

fn access(reply: &Reply) -> String {
    reply.body["access_token"].as_str().unwrap().to_owned()
}

fn token(reply: &Reply) -> String {
    reply.body["token"].as_str().unwrap().to_owned()
}

// r[verify authn.invite.link-only]
// r[verify authn.invite.emailed]
// r[verify metadata.public]
// r[verify platform.idempotency.client-ids]
#[tokio::test(flavor = "multi_thread")]
async fn link_only_invites_show_their_token_once_and_deliver_nothing() {
    let app = TestApp::new().await;
    let worker = worker(&app).await;
    let tenant = tenant_with_reader(&app).await;
    let id = uuid::Uuid::now_v7();
    let body = json!({
        "id": id,
        "tenant": tenant,
        "roles": ["viewer"],
        "metadata": {"patient": "p-1"},
        "public_metadata": {"inviter": "Ada", "access": "family"},
    });
    let created = invite(&app, body.clone()).await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    let first = token(&created);
    assert!(first.starts_with(&format!("{id}.")), "{first}");
    assert!(
        events(&app, &worker, "delivery.requested").await.is_empty(),
        "nothing is delivered"
    );

    let read = app
        .control(Method::GET, &format!("/v1/invites/{id}"), None)
        .await;
    assert_eq!(read.status, StatusCode::OK, "{:?}", read.body);
    assert_eq!(read.body["email"], Value::Null);
    assert_eq!(read.body["state"], "pending");
    assert_eq!(
        read.body["public_metadata"],
        json!({"inviter": "Ada", "access": "family"})
    );
    assert!(!read.body.to_string().contains(&first), "never shown again");
    for query in [
        format!("tenant={tenant}"),
        "metadata=%7B%22patient%22%3A%22p-1%22%7D".to_owned(),
    ] {
        let listed = app
            .control(Method::GET, &format!("/v1/invites?{query}"), None)
            .await;
        assert_eq!(listed.status, StatusCode::OK, "{:?}", listed.body);
        assert_eq!(listed.body["invites"], json!([read.body]), "{query}");
    }

    // A repeat shows a new token and stops accepting the first.
    let again = invite(&app, body.clone()).await;
    assert_eq!(again.status, StatusCode::OK, "{:?}", again.body);
    let second = token(&again);
    assert_ne!(first, second);
    assert_eq!(preview(&app, &first).await.code(), "INVALID_CREDENTIALS");
    assert_eq!(preview(&app, &second).await.status, StatusCode::OK);
    let mut other = body.clone();
    other["public_metadata"] = json!({"inviter": "Eve"});
    assert_eq!(invite(&app, other).await.code(), "CONFLICT");
    let mut emailed = body.clone();
    emailed["email"] = json!("ada@example.com");
    assert_eq!(
        invite(&app, emailed).await.code(),
        "CONFLICT",
        "an address is part of the content"
    );

    // Once it isn't pending, a repeat has no token to show.
    app.control(Method::POST, &format!("/v1/invites/{id}/revoke"), None)
        .await;
    let revoked = invite(&app, body).await;
    assert_eq!(revoked.status, StatusCode::OK, "{:?}", revoked.body);
    assert_eq!(revoked.body.get("token"), None);

    // An emailed invite's token is delivered, never shown, not even on a
    // repeat.
    let emailed = json!({"id": uuid::Uuid::now_v7(), "email": "ada@example.com"});
    for _ in 0..2 {
        let created = invite(&app, emailed.clone()).await;
        assert!(created.status.is_success(), "{:?}", created.body);
        assert_eq!(created.body.get("token"), None);
    }
    assert_eq!(events(&app, &worker, "delivery.requested").await.len(), 1);

    // Public metadata is a small object.
    let large = json!({"public_metadata": {"inviter": "x".repeat(1100)}});
    assert_eq!(invite(&app, large).await.code(), "METADATA_TOO_LARGE");
    let list = json!({"public_metadata": ["Ada"]});
    assert_eq!(invite(&app, list).await.code(), "INVALID_REQUEST");
}

// r[verify authn.invite.bearer]
// r[verify authn.invite.redeemed-event]
// r[verify metadata.invites]
#[tokio::test(flavor = "multi_thread")]
async fn signed_in_subjects_redeem_link_only_invites_whatever_they_signed_in_with() {
    let app = TestApp::new().await;
    let worker = worker(&app).await;
    let tenant = tenant_with_reader(&app).await;
    let membership = uuid::Uuid::now_v7();
    let created = invite(
        &app,
        json!({
            "tenant": tenant,
            "roles": ["viewer"],
            "membership": membership,
            "metadata": {"patient": "p-1"},
        }),
    )
    .await;
    let link = token(&created);
    let id = created.body["invite_id"].as_str().unwrap().to_owned();

    // Someone who signed up through the relying system, with a phone.
    let subject = uuid::Uuid::now_v7().to_string();
    app.control(
        Method::PUT,
        &format!("/v1/subjects/{subject}"),
        Some(json!({"kind": "human"})),
    )
    .await;
    app.control(
        Method::POST,
        &format!("/v1/subjects/{subject}/credentials"),
        Some(json!({"kind": "phone_otp", "identifier": "+46701234567"})),
    )
    .await;
    app.post("/v1/login/phone/start", json!({"phone": "+46701234567"}))
        .await;
    let code =
        events(&app, &worker, "delivery.requested").await[0]["payload"]["material"]["code"].clone();
    let signed_in = app
        .post(
            "/v1/login/phone/complete",
            json!({"phone": "+46701234567", "code": code}),
        )
        .await;
    assert_eq!(signed_in.status, StatusCode::OK, "{:?}", signed_in.body);
    let session = access(&signed_in);

    // A signed-in redemption takes only the token.
    for extra in [
        json!({"password": PASSWORD}),
        json!({"identifier": "ada@example.com"}),
        json!({"flags": ["personal_only"]}),
        json!({"client": "browser"}),
    ] {
        let mut body = json!({"token": link});
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let refused = redeem_signed_in(&app, &session, body).await;
        assert_eq!(refused.code(), "INVALID_REQUEST", "{extra}");
    }

    let redeemed = redeem_signed_in(&app, &session, json!({"token": link})).await;
    assert_eq!(redeemed.status, StatusCode::OK, "{:?}", redeemed.body);
    assert_eq!(redeemed.body["invite"], json!(id));
    assert_eq!(redeemed.body["subject"], json!(subject));
    assert_eq!(redeemed.body["tenant"], json!(tenant));
    assert_eq!(redeemed.body["membership"], json!(membership));
    assert!(redeemed.body["cursor"].is_u64(), "{:?}", redeemed.body);
    assert_eq!(redeemed.body.get("access_token"), None, "no new session");
    let again = redeem_signed_in(&app, &session, json!({"token": link})).await;
    assert_eq!(again.code(), "INVALID_CREDENTIALS");

    // The session it has moves into the tenant, with the invited role.
    let selected = app
        .send(
            Method::POST,
            "/v1/login/tenant",
            &[("authorization", &format!("Bearer {session}"))],
            Some(json!({"tenant": tenant})),
        )
        .await;
    assert_eq!(selected.status, StatusCode::OK, "{:?}", selected.body);
    let session = access(&selected);
    let entitlements = app
        .control(
            Method::GET,
            &format!("/v1/subjects/{subject}/entitlements?tenant={tenant}"),
            None,
        )
        .await;
    assert_eq!(entitlements.body["tenant"], json!(["record:read"]));

    let redeemed_events = events(&app, &worker, "invite.redeemed").await;
    assert_eq!(redeemed_events.len(), 1);
    assert_eq!(
        redeemed_events[0]["payload"],
        json!({
            "invite": id,
            "subject": subject,
            "tenant": tenant,
            "membership": membership,
            "metadata": {"patient": "p-1"},
        })
    );
    let read = app
        .control(Method::GET, &format!("/v1/invites/{id}"), None)
        .await;
    assert_eq!(read.body["state"], "redeemed");
    let revoke = app
        .control(Method::POST, &format!("/v1/invites/{id}/revoke"), None)
        .await;
    assert_eq!(
        revoke.code(),
        "CONFLICT",
        "a redeemed invite stays redeemed"
    );

    // An emailed invite isn't redeemed signed in, and nothing is used up.
    app.human("ada@example.com", PASSWORD).await;
    invite(&app, json!({"email": "ada@example.com", "tenant": tenant})).await;
    let emailed = events(&app, &worker, "delivery.requested")
        .await
        .into_iter()
        .rev()
        .find(|event| event["payload"]["purpose"] == "invite")
        .unwrap()["payload"]["material"]["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let refused = redeem_signed_in(&app, &session, json!({"token": emailed})).await;
    assert_eq!(refused.code(), "INVALID_REQUEST");
    let by_password = app
        .post(
            "/v1/invites/redeem",
            json!({"token": emailed, "password": PASSWORD}),
        )
        .await;
    assert_eq!(by_password.status, StatusCode::OK, "{:?}", by_password.body);

    // Nor by a partial session.
    let mfa = uuid::Uuid::now_v7().to_string();
    app.control(
        Method::PUT,
        &format!("/v1/subjects/{mfa}"),
        Some(json!({"kind": "human"})),
    )
    .await;
    app.control(
        Method::POST,
        &format!("/v1/subjects/{mfa}/credentials"),
        Some(json!({"kind": "password", "identifier": "mfa@example.com",
                    "password": PASSWORD, "mfa_factors_required": 1})),
    )
    .await;
    let partial = app.login("mfa@example.com", PASSWORD).await;
    assert_eq!(partial.status, StatusCode::OK, "{:?}", partial.body);
    let link = token(&invite(&app, json!({"tenant": tenant})).await);
    let refused = redeem_signed_in(&app, &access(&partial), json!({"token": link})).await;
    assert_eq!(refused.code(), "FORBIDDEN");
    assert_eq!(preview(&app, &link).await.body["state"], "pending");
}

// r[verify authn.invite.bearer]
// r[verify platform.error.no-enumeration]
#[tokio::test(flavor = "multi_thread")]
async fn link_only_invites_redeem_with_an_existing_accounts_password_only() {
    let app = TestApp::new().await;
    let tenant = tenant_with_reader(&app).await;
    let subject = app.human("ada@example.com", PASSWORD).await;
    let link = token(&invite(&app, json!({"tenant": tenant, "roles": ["viewer"]})).await);
    let redeem = |body: Value| {
        let app = &app;
        async move { app.post("/v1/invites/redeem", body).await }
    };

    let without = redeem(json!({"token": link, "password": PASSWORD})).await;
    assert_eq!(without.code(), "INVALID_REQUEST", "{:?}", without.body);
    let unknown = redeem(json!({
        "token": link, "identifier": "nobody@example.com", "password": PASSWORD,
    }))
    .await;
    let wrong = redeem(json!({
        "token": link, "identifier": "ada@example.com", "password": "not the password",
    }))
    .await;
    assert_eq!(unknown.code(), "INVALID_CREDENTIALS");
    assert_eq!(unknown.body, wrong.body, "says nothing about which exists");
    let mut conn = app.db.pool().get().await.unwrap();
    let credentials: Count = diesel::sql_query(
        "select count(*) as count from credential where identifier = 'nobody@example.com'",
    )
    .get_result(&mut conn)
    .await
    .unwrap();
    assert_eq!(credentials.count, 0, "no account is created for anyone");

    let redeemed = redeem(json!({
        "token": link, "identifier": "ada@example.com", "password": PASSWORD,
        "client": "native",
    }))
    .await;
    assert_eq!(redeemed.status, StatusCode::OK, "{:?}", redeemed.body);
    let claims = app.verify(&access(&redeemed)).await;
    assert_eq!(claims.sub.to_string(), subject);
    assert!(redeemed.body["refresh_token"].is_string());
    let entitlements = app
        .control(
            Method::GET,
            &format!("/v1/subjects/{subject}/entitlements?tenant={tenant}"),
            None,
        )
        .await;
    assert_eq!(entitlements.body["tenant"], json!(["record:read"]));

    // An emailed invite takes no identifier.
    let worker = worker(&app).await;
    invite(&app, json!({"email": "new@example.com"})).await;
    let emailed =
        events(&app, &worker, "delivery.requested").await[0]["payload"]["material"]["token"]
            .clone();
    let refused = redeem(json!({
        "token": emailed, "identifier": "ada@example.com", "password": PASSWORD,
    }))
    .await;
    assert_eq!(refused.code(), "INVALID_REQUEST");
}

// r[verify authn.invite.preview]
// r[verify authn.invite.revoke]
// r[verify metadata.public]
// r[verify metadata.control-plane-only]
#[tokio::test(flavor = "multi_thread")]
async fn previews_show_public_metadata_and_tell_revoked_from_nothing() {
    let app = TestApp::new().await;
    let worker = worker(&app).await;
    let tenant = tenant_with_reader(&app).await;
    let created = invite(
        &app,
        json!({
            "tenant": tenant,
            "roles": ["viewer"],
            "metadata": {"secret_note": "operator only"},
            "public_metadata": {"inviter": "Ada", "access": "family"},
        }),
    )
    .await;
    let link = token(&created);
    let shown = preview(&app, &link).await;
    assert_eq!(shown.status, StatusCode::OK, "{:?}", shown.body);
    assert_eq!(
        shown.body,
        json!({
            "state": "pending",
            "expires_at": created.body["expires_at"],
            "link_only": true,
            "public_metadata": {"inviter": "Ada", "access": "family"},
        }),
        "nothing else: no tenant, roles or metadata"
    );
    assert_eq!(
        preview(&app, &link).await.body,
        shown.body,
        "changes nothing"
    );

    // An emailed invite's preview doesn't show the address.
    invite(&app, json!({"email": "new@example.com"})).await;
    let emailed =
        events(&app, &worker, "delivery.requested").await[0]["payload"]["material"]["token"]
            .as_str()
            .unwrap()
            .to_owned();
    let shown = preview(&app, &emailed).await;
    assert_eq!(shown.body["link_only"], false);
    assert_eq!(shown.body["public_metadata"], json!({}));
    assert!(!shown.body.to_string().contains("new@example.com"));

    // Redeemed: still shown, as redeemed.
    app.post(
        "/v1/invites/redeem",
        json!({"token": emailed, "password": PASSWORD}),
    )
    .await;
    assert_eq!(preview(&app, &emailed).await.body["state"], "redeemed");

    // Revoked, expired, unknown or malformed: all alike, as redeeming
    // them is.
    let revoked = token(&invite(&app, json!({"public_metadata": {"inviter": "Ada"}})).await);
    let id = revoked.split_once('.').unwrap().0.to_owned();
    app.control(Method::POST, &format!("/v1/invites/{id}/revoke"), None)
        .await;
    let expired = token(&invite(&app, json!({})).await);
    let mut conn = app.db.pool().get().await.unwrap();
    diesel::sql_query(format!(
        "update challenge set expires_at = now() - interval '1 minute' where id = '{}'",
        expired.split_once('.').unwrap().0
    ))
    .execute(&mut conn)
    .await
    .unwrap();
    let unknown = preview(&app, &format!("{}.not-a-secret", uuid::Uuid::now_v7())).await;
    assert_eq!(unknown.code(), "INVALID_CREDENTIALS");
    for other in [
        revoked.clone(),
        expired,
        format!("{id}.wrong-secret"),
        "malformed".to_owned(),
    ] {
        assert_eq!(preview(&app, &other).await.body, unknown.body, "{other}");
    }
    let redeemed = app
        .post(
            "/v1/invites/redeem",
            json!({"token": revoked, "password": PASSWORD}),
        )
        .await;
    assert_eq!(
        redeemed.body, unknown.body,
        "previews fail as redeeming does"
    );
}

// r[verify authn.invite.token-limits]
#[tokio::test(flavor = "multi_thread")]
async fn one_address_cannot_try_many_invite_tokens() {
    let app = TestApp::new().await;
    let link = token(&invite(&app, json!({"public_metadata": {"inviter": "Ada"}})).await);
    let check = |peer: &str, uri: &'static str, token: String| {
        let peer = peer.parse().unwrap();
        let app = &app;
        async move {
            app.send_from(
                Some(peer),
                Method::POST,
                uri,
                &[],
                Some(json!({"token": token, "password": PASSWORD})),
            )
            .await
        }
    };
    for n in 0..100 {
        let uri = if n % 2 == 0 {
            "/v1/invites/preview"
        } else {
            "/v1/invites/redeem"
        };
        let guess = format!("{}.guess-{n}", uuid::Uuid::now_v7());
        assert_eq!(
            check("203.0.113.9:1000", uri, guess).await.code(),
            "INVALID_CREDENTIALS"
        );
    }
    let limited = check("203.0.113.9:1001", "/v1/invites/preview", link.clone()).await;
    assert_eq!(limited.code(), "RATE_LIMITED", "even with a real token");
    assert!(limited.headers.contains_key("retry-after"));
    let elsewhere = check("198.51.100.1:1000", "/v1/invites/preview", link).await;
    assert_eq!(
        elsewhere.status,
        StatusCode::OK,
        "other addresses are unaffected, and the invite isn't locked out"
    );
}
