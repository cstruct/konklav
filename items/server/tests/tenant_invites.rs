//! Invites a tenant's members make into it on the subject-facing surface,
//! with the tenant capability `konklav:tenant:invite`, giving only roles
//! they hold; the inviter recorded on every invite; and signing up with an
//! invite that lets a newcomer do so.

#![allow(clippy::too_many_lines)]

mod common;

use axum::http::{Method, StatusCode};
use common::{Reply, TestApp};
use serde_json::{Value, json};

const PASSWORD: &str = "correct horse battery";

/// A tenant with the roles `viewer` and `editor`, ordinary ones, and
/// `inviter`, which names the tenant capability.
async fn tenant(app: &TestApp) -> String {
    app.control(
        Method::PUT,
        "/v1/catalog",
        Some(json!({"actions": [{"name": "record:read"}, {"name": "record:write"}]})),
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
    for (role, action) in [
        ("viewer", "record:read"),
        ("editor", "record:write"),
        ("inviter", "konklav:tenant:invite"),
    ] {
        let written = app
            .control(
                Method::PUT,
                &format!("/v1/tenants/{tenant}/roles/{role}"),
                Some(json!({"policies": [{"action": action, "effect": "allow"}]})),
            )
            .await;
        assert!(written.status.is_success(), "{:?}", written.body);
    }
    tenant
}

/// A person who is a member of `tenant` with `roles`, signed in: their
/// subject and access token.
async fn member(app: &TestApp, tenant: &str, email: &str, roles: &[&str]) -> (String, String) {
    let subject = app.human(email, PASSWORD).await;
    let membership = uuid::Uuid::now_v7();
    let joined = app
        .control(
            Method::PUT,
            &format!("/v1/memberships/{membership}"),
            Some(json!({"subject": subject, "tenant": tenant})),
        )
        .await;
    assert!(joined.status.is_success(), "{:?}", joined.body);
    for role in roles {
        let assigned = app
            .control(
                Method::POST,
                &format!("/v1/memberships/{membership}/assignments"),
                Some(json!({"role": role})),
            )
            .await;
        assert!(assigned.status.is_success(), "{:?}", assigned.body);
    }
    let login = app.login(email, PASSWORD).await;
    assert_eq!(login.status, StatusCode::OK, "{:?}", login.body);
    (
        subject,
        login.body["access_token"].as_str().unwrap().to_owned(),
    )
}

async fn call(app: &TestApp, method: Method, uri: &str, token: &str, body: Option<Value>) -> Reply {
    let auth = format!("Bearer {token}");
    app.send(method, uri, &[("authorization", &auth)], body)
        .await
}

// r[verify authn.invite.tenant]
// r[verify authn.invite.inviter]
// r[verify authz.tenant-capability]
#[tokio::test(flavor = "multi_thread")]
async fn a_member_invites_into_their_own_tenant_only() {
    let app = TestApp::new().await;
    let mine = tenant(&app).await;
    let other = tenant(&app).await;
    let (ada, inviter) = member(&app, &mine, "ada@example.com", &["inviter", "viewer"]).await;
    let (_, viewer) = member(&app, &mine, "bea@example.com", &["viewer"]).await;

    // Made with its token shown once, link-only, into the tenant.
    let made = call(
        &app,
        Method::POST,
        &format!("/v1/tenants/{mine}/invites"),
        &inviter,
        Some(json!({"roles": ["viewer"], "public_metadata": {"inviter": "Ada"}})),
    )
    .await;
    assert_eq!(made.status, StatusCode::CREATED, "{:?}", made.body);
    let link = made.body["token"].as_str().unwrap().to_owned();
    let id = made.body["invite_id"].as_str().unwrap().to_owned();

    // Not into another tenant, not without the capability, and not without
    // a session.
    for (tenant, token) in [(&other, &inviter), (&mine, &viewer)] {
        let refused = call(
            &app,
            Method::POST,
            &format!("/v1/tenants/{tenant}/invites"),
            token,
            Some(json!({})),
        )
        .await;
        assert_eq!(refused.code(), "FORBIDDEN", "{:?}", refused.body);
    }
    let anonymous = app
        .post(&format!("/v1/tenants/{mine}/invites"), json!({}))
        .await;
    assert_eq!(
        anonymous.status,
        StatusCode::UNAUTHORIZED,
        "{:?}",
        anonymous.body
    );

    // Listed: only the tenant's link-only invites, never an emailed one,
    // each with who made it.
    let emailed = app
        .control(
            Method::POST,
            "/v1/invites",
            Some(json!({"email": "bob@example.com", "tenant": mine})),
        )
        .await;
    assert_eq!(emailed.status, StatusCode::CREATED, "{:?}", emailed.body);
    let listed = call(
        &app,
        Method::GET,
        &format!("/v1/tenants/{mine}/invites"),
        &inviter,
        None,
    )
    .await;
    assert_eq!(listed.status, StatusCode::OK, "{:?}", listed.body);
    let invites = listed.body["invites"].as_array().unwrap();
    assert_eq!(invites.len(), 1, "{invites:?}");
    assert_eq!(invites[0]["id"], json!(id));
    assert_eq!(invites[0]["roles"], json!(["viewer"]));
    assert_eq!(invites[0]["state"], json!("pending"));
    assert_eq!(invites[0]["invited_by"], json!(ada));
    let elsewhere = call(
        &app,
        Method::GET,
        &format!("/v1/tenants/{other}/invites"),
        &inviter,
        None,
    )
    .await;
    assert_eq!(elsewhere.code(), "FORBIDDEN");

    // The control plane shows the inviter too: the member, and none for the
    // bootstrap token.
    let got = app
        .control(Method::GET, &format!("/v1/invites/{id}"), None)
        .await;
    assert_eq!(got.body["invited_by"], json!(ada));
    let emailed_id = emailed.body["invite_id"].as_str().unwrap();
    let got = app
        .control(Method::GET, &format!("/v1/invites/{emailed_id}"), None)
        .await;
    assert_eq!(got.body["invited_by"], Value::Null, "{:?}", got.body);

    // Revoked from its own tenant only; the emailed one isn't the member's
    // to revoke.
    let not_theirs = call(
        &app,
        Method::POST,
        &format!("/v1/tenants/{mine}/invites/{emailed_id}/revoke"),
        &inviter,
        None,
    )
    .await;
    assert_eq!(
        not_theirs.status,
        StatusCode::NOT_FOUND,
        "{:?}",
        not_theirs.body
    );
    let revoked = call(
        &app,
        Method::POST,
        &format!("/v1/tenants/{mine}/invites/{id}/revoke"),
        &inviter,
        None,
    )
    .await;
    assert_eq!(revoked.status, StatusCode::OK, "{:?}", revoked.body);
    assert_eq!(revoked.body["state"], json!("revoked"));
    let preview = app
        .post("/v1/invites/preview", json!({"token": link}))
        .await;
    assert_eq!(preview.code(), "INVALID_CREDENTIALS");
}

// r[verify authn.invite.tenant-roles]
// r[verify authn.invite.tenant]
#[tokio::test(flavor = "multi_thread")]
async fn a_member_invites_only_into_plain_roles_they_hold() {
    let app = TestApp::new().await;
    let mine = tenant(&app).await;
    let (_, inviter) = member(&app, &mine, "ada@example.com", &["inviter", "viewer"]).await;
    let make = |body: Value| {
        let (app, mine, inviter) = (&app, &mine, &inviter);
        async move {
            call(
                app,
                Method::POST,
                &format!("/v1/tenants/{mine}/invites"),
                inviter,
                Some(body),
            )
            .await
        }
    };
    // A role they hold.
    let held = make(json!({"roles": ["viewer"]})).await;
    assert_eq!(held.status, StatusCode::CREATED, "{:?}", held.body);
    // Not one of the tenant's they don't hold.
    let more = make(json!({"roles": ["viewer", "editor"]})).await;
    assert_eq!(more.code(), "FORBIDDEN", "{:?}", more.body);
    // Not the power to invite, though they hold it, nor any role naming a
    // konklav: action.
    let handing_on = make(json!({"roles": ["inviter"]})).await;
    assert_eq!(
        handing_on.code(),
        "INVALID_REQUEST",
        "{:?}",
        handing_on.body
    );
    // Not a role the tenant doesn't have.
    let unknown = make(json!({"roles": ["admin"]})).await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND, "{:?}", unknown.body);
    // Never an address: such an invite is link-only.
    let emailed = make(json!({"email": "bob@example.com"})).await;
    assert_eq!(emailed.code(), "INVALID_REQUEST", "{:?}", emailed.body);
}

// r[verify authn.invite.inviter]
#[tokio::test(flavor = "multi_thread")]
async fn an_operators_invite_records_the_operator_and_keeps_its_first_inviter() {
    let app = TestApp::new().await;
    let ada = app.human("ada@example.com", PASSWORD).await;
    let granted = app
        .control(
            Method::POST,
            &format!("/v1/subjects/{ada}/global-assignments"),
            Some(json!({"role": "konklav.admin"})),
        )
        .await;
    assert!(granted.status.is_success(), "{:?}", granted.body);
    let operator = app.login("ada@example.com", PASSWORD).await.body["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let id = uuid::Uuid::now_v7();
    let body = json!({"id": id, "public_metadata": {"inviter": "Ada"}});
    let made = call(
        &app,
        Method::POST,
        "/v1/invites",
        &operator,
        Some(body.clone()),
    )
    .await;
    assert_eq!(made.status, StatusCode::CREATED, "{:?}", made.body);
    // A repeat by someone else is the same invite, still Ada's.
    let repeated = app.control(Method::POST, "/v1/invites", Some(body)).await;
    assert_eq!(repeated.status, StatusCode::OK, "{:?}", repeated.body);
    let got = app
        .control(Method::GET, &format!("/v1/invites/{id}"), None)
        .await;
    assert_eq!(got.body["invited_by"], json!(ada), "{:?}", got.body);
}

/// A sign-up invite into a fresh tenant, made by a member, and its token.
async fn sign_up_invite(app: &TestApp) -> (String, String) {
    let mine = tenant(app).await;
    let email = format!("{}@example.com", uuid::Uuid::now_v7());
    let (_, inviter) = member(app, &mine, &email, &["inviter", "viewer"]).await;
    let made = call(
        app,
        Method::POST,
        &format!("/v1/tenants/{mine}/invites"),
        &inviter,
        Some(json!({"roles": ["viewer"], "sign_up": true})),
    )
    .await;
    assert_eq!(made.status, StatusCode::CREATED, "{:?}", made.body);
    (mine, made.body["token"].as_str().unwrap().to_owned())
}

// r[verify authn.invite.sign-up]
// r[verify authn.invite.preview]
#[tokio::test(flavor = "multi_thread")]
async fn a_newcomer_signs_up_with_an_invite_that_lets_them() {
    let app = TestApp::new().await;
    let (mine, link) = sign_up_invite(&app).await;

    let preview = app
        .post("/v1/invites/preview", json!({"token": link}))
        .await;
    assert_eq!(preview.status, StatusCode::OK, "{:?}", preview.body);
    assert_eq!(preview.body["sign_up"], json!(true));
    assert_eq!(preview.body["link_only"], json!(true));

    let short = app
        .post(
            "/v1/invites/redeem",
            json!({"token": link, "identifier": "new@example.com", "password": "short", "sign_up": true}),
        )
        .await;
    assert_eq!(short.code(), "INVALID_REQUEST", "{:?}", short.body);

    let joined = app
        .post(
            "/v1/invites/redeem",
            json!({
                "token": link, "identifier": "New@Example.com", "password": PASSWORD,
                "sign_up": true, "client": "native",
            }),
        )
        .await;
    assert_eq!(joined.status, StatusCode::OK, "{:?}", joined.body);
    let subject = app
        .verify(joined.body["access_token"].as_str().unwrap())
        .await
        .sub;
    let entitlements = app
        .control(
            Method::GET,
            &format!("/v1/subjects/{subject}/entitlements?tenant={mine}"),
            None,
        )
        .await;
    assert_eq!(entitlements.body["tenant"], json!(["record:read"]));

    // The new account signs in with its normalized email.
    let login = app.login("new@example.com", PASSWORD).await;
    assert_eq!(login.status, StatusCode::OK, "{:?}", login.body);

    // Used up.
    let again = app
        .post("/v1/invites/preview", json!({"token": link}))
        .await;
    assert_eq!(again.body["state"], json!("redeemed"));
}

// r[verify authn.invite.sign-up]
#[tokio::test(flavor = "multi_thread")]
async fn signing_up_with_a_taken_email_conflicts_and_leaves_the_invite_pending() {
    let app = TestApp::new().await;
    let (_, link) = sign_up_invite(&app).await;
    app.human("ada@example.com", PASSWORD).await;
    let taken = app
        .post(
            "/v1/invites/redeem",
            json!({"token": link, "identifier": "ada@example.com", "password": "another password", "sign_up": true}),
        )
        .await;
    assert_eq!(taken.code(), "CONFLICT", "{:?}", taken.body);
    let preview = app
        .post("/v1/invites/preview", json!({"token": link}))
        .await;
    assert_eq!(preview.body["state"], json!("pending"));

    // The owner joins with their password instead.
    let joined = app
        .post(
            "/v1/invites/redeem",
            json!({"token": link, "identifier": "ada@example.com", "password": PASSWORD}),
        )
        .await;
    assert_eq!(joined.status, StatusCode::OK, "{:?}", joined.body);
}

// r[verify authn.invite.sign-up]
// r[verify authn.invite.bearer]
#[tokio::test(flavor = "multi_thread")]
async fn only_a_sign_up_invite_signs_anyone_up() {
    let app = TestApp::new().await;
    let mine = tenant(&app).await;
    // Not one made without it.
    let plain = app
        .control(Method::POST, "/v1/invites", Some(json!({"tenant": mine})))
        .await;
    let link = plain.body["token"].as_str().unwrap();
    let refused = app
        .post(
            "/v1/invites/redeem",
            json!({"token": link, "identifier": "new@example.com", "password": PASSWORD, "sign_up": true}),
        )
        .await;
    assert_eq!(refused.code(), "INVALID_REQUEST", "{:?}", refused.body);
    let preview = app
        .post("/v1/invites/preview", json!({"token": link}))
        .await;
    assert_eq!(preview.body["sign_up"], json!(false));
    assert_eq!(preview.body["state"], json!("pending"));

    // An emailed invite can't be made to let anyone sign up.
    let emailed = app
        .control(
            Method::POST,
            "/v1/invites",
            Some(json!({"email": "bob@example.com", "sign_up": true})),
        )
        .await;
    assert_eq!(emailed.code(), "INVALID_REQUEST", "{:?}", emailed.body);

    // Nor does a signed-in redemption sign anyone up.
    let (_, link) = sign_up_invite(&app).await;
    app.human("ada@example.com", PASSWORD).await;
    let access = app.login("ada@example.com", PASSWORD).await.body["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let auth = format!("Bearer {access}");
    let signed_in = app
        .send(
            Method::POST,
            "/v1/invites/redeem",
            &[("authorization", &auth)],
            Some(json!({"token": link, "sign_up": true})),
        )
        .await;
    assert_eq!(signed_in.code(), "INVALID_REQUEST", "{:?}", signed_in.body);
}
