//! Tenant keys: set on the control plane, and taken instead of a tenant id
//! wherever a tenant is named.

#![allow(clippy::too_many_lines)]

mod common;

use std::collections::HashSet;

use axum::http::{Method, StatusCode, header};
use common::{ISSUER, TestApp};
use konklav_server::access_requests::Settings;
use konklav_server::oidc::OpenIdProvider;
use konklav_store::tenants::Reference;
use serde_json::json;

const PASSWORD: &str = "correct horse battery";
const ID_TOKEN_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUoptOOQL2DZqHV4Q
GpDMUYd6rsbhOjYqdxTU6xh4DmahRANCAARjr/UQTOoK84SKa5ZB1Rg9mLRWjzyy
p1XNGpwF1zXMHj8NrRZRBsdiy2jZvNVSLlPqzmK3P4YLDAtSoKNCeXst
-----END PRIVATE KEY-----";

async fn put_tenant(app: &TestApp, body: serde_json::Value) -> (String, common::Reply) {
    let id = uuid::Uuid::now_v7().to_string();
    let reply = app
        .control(Method::PUT, &format!("/v1/tenants/{id}"), Some(body))
        .await;
    (id, reply)
}

// r[verify tenant.key]
#[tokio::test(flavor = "multi_thread")]
async fn tenants_get_a_key_once() {
    let app = TestApp::new().await;
    let (acme, created) = put_tenant(&app, json!({"key": "acme"})).await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    assert_eq!(created.body["key"], "acme");
    let (_, invalid) = put_tenant(&app, json!({"key": "Acme 1"})).await;
    assert_eq!(invalid.status, StatusCode::BAD_REQUEST);
    let (_, taken) = put_tenant(&app, json!({"key": "acme"})).await;
    assert_eq!(taken.status, StatusCode::CONFLICT);

    let by_key = app.control(Method::GET, "/v1/tenants/acme", None).await;
    assert_eq!(by_key.status, StatusCode::OK);
    assert_eq!(by_key.body["id"], acme.as_str());

    // A key set later, then never changed.
    let (north, plain) = put_tenant(&app, json!({})).await;
    assert_eq!(plain.body["key"], serde_json::Value::Null);
    let path = format!("/v1/tenants/{north}/key");
    let set = app
        .control(Method::PUT, &path, Some(json!({"key": "acme-north"})))
        .await;
    assert_eq!(set.status, StatusCode::CREATED, "{:?}", set.body);
    assert_eq!(set.body["key"], "acme-north");
    let again = app
        .control(Method::PUT, &path, Some(json!({"key": "acme-north"})))
        .await;
    assert_eq!(again.status, StatusCode::OK);
    let renamed = app
        .control(Method::PUT, &path, Some(json!({"key": "acme-south"})))
        .await;
    assert_eq!(renamed.status, StatusCode::CONFLICT);
    let (other, _) = put_tenant(&app, json!({})).await;
    let stolen = app
        .control(
            Method::PUT,
            &format!("/v1/tenants/{other}/key"),
            Some(json!({"key": "acme"})),
        )
        .await;
    assert_eq!(stolen.status, StatusCode::CONFLICT);

    // A child under a parent named by its key.
    let (_, child) = put_tenant(&app, json!({"parent": "acme", "key": "acme-west"})).await;
    assert_eq!(child.status, StatusCode::CREATED, "{:?}", child.body);
    assert_eq!(child.body["parent_id"], acme.as_str());
    let unknown = app
        .control(Method::GET, "/v1/tenants/nobody-here", None)
        .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
}

// r[verify tenant.key.reference]
#[tokio::test(flavor = "multi_thread")]
async fn keys_name_tenants_on_every_surface() {
    let app = TestApp::with_auth(|auth| {
        auth.access_requests = Some(Settings {
            tenants: Some(HashSet::from([Reference::Key("acme-open".into())])),
            retry_after_denial: chrono::Duration::hours(1),
        });
        auth.oidc = Some(
            OpenIdProvider::from_pem(
                ID_TOKEN_KEY,
                "https://login.example/".into(),
                format!("{ISSUER}/.well-known/jwks.json"),
            )
            .unwrap(),
        );
    })
    .await;
    let (acme, _) = put_tenant(&app, json!({"key": "acme"})).await;
    let (open, _) = put_tenant(&app, json!({"key": "acme-open"})).await;

    // The control plane: memberships and roles by key.
    let ada = app.human("ada@example.com", PASSWORD).await;
    let membership = uuid::Uuid::now_v7();
    let joined = app
        .control(
            Method::PUT,
            &format!("/v1/memberships/{membership}"),
            Some(json!({"subject": ada, "tenant": "acme"})),
        )
        .await;
    assert!(joined.status.is_success(), "{:?}", joined.body);
    assert_eq!(joined.body["tenant_id"], acme.as_str());
    let listed = app
        .control(Method::GET, "/v1/tenants/acme/memberships", None)
        .await;
    assert_eq!(listed.body[0]["id"], membership.to_string());

    // The subject-facing surface: entering a tenant by key; tokens keep the
    // id. An unknown key is refused as an unknown id is.
    let token = app.login("ada@example.com", PASSWORD).await.body["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let auth = format!("Bearer {token}");
    let entered = app
        .send(
            Method::POST,
            "/v1/login/tenant",
            &[("authorization", &auth)],
            Some(json!({"tenant": "acme"})),
        )
        .await;
    assert_eq!(entered.status, StatusCode::OK, "{:?}", entered.body);
    let claims = app
        .verify(entered.body["access_token"].as_str().unwrap())
        .await;
    assert_eq!(claims.tid.map(|t| t.to_string()), Some(acme.clone()));
    let token = entered.body["access_token"].as_str().unwrap().to_owned();
    let auth = format!("Bearer {token}");
    let refusal = |tenant: String| {
        let app = &app;
        let auth = auth.clone();
        async move {
            app.send(
                Method::POST,
                "/v1/login/tenant",
                &[("authorization", &auth)],
                Some(json!({"tenant": tenant})),
            )
            .await
        }
    };
    let unknown_key = refusal("nobody-here".into()).await;
    let unknown_id = refusal(uuid::Uuid::now_v7().to_string()).await;
    assert_eq!(unknown_key.status, StatusCode::FORBIDDEN);
    assert_eq!(unknown_key.body, unknown_id.body);

    // Access requests: configured by key, asked by key.
    app.human("bo@example.com", PASSWORD).await;
    let bo = app.login("bo@example.com", PASSWORD).await.body["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let bo_auth = format!("Bearer {bo}");
    let asked = app
        .send(
            Method::POST,
            "/v1/tenants/acme-open/access-request",
            &[("authorization", &bo_auth)],
            None,
        )
        .await;
    assert_eq!(asked.status, StatusCode::CREATED, "{:?}", asked.body);
    assert_eq!(asked.body["tenant_id"], open.as_str());
    let elsewhere = app
        .send(
            Method::POST,
            "/v1/tenants/acme/access-request",
            &[("authorization", &bo_auth)],
            None,
        )
        .await;
    assert_eq!(elsewhere.status, StatusCode::FORBIDDEN, "not listed");

    // OIDC: `tenant:<key>` names the tenant; an unknown key goes on like a
    // UUID of no tenant.
    let registered = app
        .control(
            Method::PUT,
            "/v1/oidc/clients/cluster",
            Some(json!({
                "kind": "public",
                "redirect_uris": ["http://localhost:8000/callback"],
                "scopes": ["openid", "tenant"],
                "audience": "cluster",
            })),
        )
        .await;
    assert!(registered.status.is_success(), "{:?}", registered.body);
    let requested = |scope: &'static str| {
        let app = &app;
        async move {
            let url = reqwest::Url::parse_with_params(
                "http://x/v1/oauth2/authorize",
                [
                    ("response_type", "code"),
                    ("client_id", "cluster"),
                    ("redirect_uri", "http://localhost:8000/callback"),
                    ("scope", scope),
                    (
                        "code_challenge",
                        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                    ),
                    ("code_challenge_method", "S256"),
                ],
            )
            .unwrap();
            let started = app
                .send(
                    Method::GET,
                    url.as_str().trim_start_matches("http://x"),
                    &[],
                    None,
                )
                .await;
            assert_eq!(started.status, StatusCode::SEE_OTHER, "{:?}", started.body);
            let location = started.headers[header::LOCATION].to_str().unwrap();
            let id = reqwest::Url::parse(location)
                .unwrap()
                .query_pairs()
                .find(|(name, _)| name == "login_request")
                .unwrap()
                .1
                .into_owned();
            app.send(
                Method::GET,
                &format!("/v1/oauth2/login-requests/{id}"),
                &[],
                None,
            )
            .await
            .body
        }
    };
    assert_eq!(
        requested("openid tenant:acme").await["tenant"],
        acme.as_str()
    );
    let unknown = requested("openid tenant:nobody-here").await;
    assert!(unknown["tenant"].is_string(), "{unknown:?}");
    assert_ne!(unknown["tenant"], acme.as_str());
}
