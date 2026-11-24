//! `GET /v1/login/methods`: the sign-in methods an instance accepts, for
//! any login application or relying system to offer.

mod common;

use axum::http::{Method, StatusCode};
use common::{ISSUER, TestApp};
use konklav_server::federation::{GitHub, Protocol, Providers, Settings};
use serde_json::json;

// r[verify authn.login.offered]
#[tokio::test(flavor = "multi_thread")]
async fn anyone_reads_the_sign_in_methods_in_configuration_order() {
    let providers = Providers::from_settings([
        Settings {
            id: "ops".into(),
            name: Some("Ops directory".into()),
            issuer: "https://ops.example".into(),
            client_id: "konklav-prod".into(),
            client_secret: "never shown".into(),
            ..Settings::default()
        },
        Settings {
            id: "github".into(),
            protocol: Protocol::GitHub(GitHub::new("https://github.com").unwrap()),
            issuer: "https://github.com".into(),
            client_id: "Iv1.secretish".into(),
            ..Settings::default()
        },
    ]);
    let app = TestApp::with_identity_providers(providers).await;
    let reply = app
        .send(
            Method::GET,
            "/v1/login/methods",
            &[("origin", "https://somewhere-else.example")],
            None,
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    assert_eq!(
        reply.body,
        json!({
            "password": true,
            "passkeys": false,
            "identity_providers": [
                {
                    "id": "ops",
                    "name": "Ops directory",
                    "kind": "oidc",
                    "start_url": format!("{ISSUER}/v1/login/oidc/ops/start"),
                },
                {
                    "id": "github",
                    "name": "github",
                    "kind": "github",
                    "start_url": format!("{ISSUER}/v1/login/oidc/github/start"),
                },
            ],
        })
    );
    assert_eq!(reply.headers["access-control-allow-origin"], "*");
    let text = reply.body.to_string();
    for hidden in [
        "konklav-prod",
        "Iv1.secretish",
        "ops.example",
        "never shown",
    ] {
        assert!(!text.contains(hidden), "{hidden} shows");
    }

    // No identity providers: just a password.
    let plain = TestApp::new().await;
    let reply = plain
        .send(Method::GET, "/v1/login/methods", &[], None)
        .await;
    assert_eq!(reply.body["identity_providers"], json!([]));
}
