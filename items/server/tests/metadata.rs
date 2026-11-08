#![allow(clippy::too_many_lines)]

//! Metadata end to end: written on create and by merge patch, shown and
//! filtered on the control plane only, limited in size, announced on the
//! change feed to those who could read it, handed over by invites, and
//! recorded in history.

mod common;

use axum::http::{Method, StatusCode};
use common::{CONTROL_TOKEN, TestApp};
use serde_json::{Value, json};

const PASSWORD: &str = "correct horse battery";

fn id() -> String {
    uuid::Uuid::now_v7().to_string()
}

/// `?metadata=` with `filter` as its value.
fn filter(filter: &Value) -> String {
    use std::fmt::Write;
    let mut encoded = String::from("metadata=");
    for byte in filter.to_string().bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
            encoded.push(byte as char);
        } else {
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

async fn created(app: &TestApp, method: Method, uri: &str, body: Value) -> Value {
    let reply = app.control(method, uri, Some(body)).await;
    assert!(reply.status.is_success(), "{uri}: {:?}", reply.body);
    reply.body
}

async fn get(app: &TestApp, uri: &str) -> Value {
    let reply = app.control(Method::GET, uri, None).await;
    assert_eq!(reply.status, StatusCode::OK, "{uri}: {:?}", reply.body);
    reply.body
}

/// A merge patch of `uri`'s metadata, with `If-Match` when given.
async fn patch(app: &TestApp, uri: &str, body: Value, if_match: Option<&str>) -> common::Reply {
    let auth = format!("Bearer {CONTROL_TOKEN}");
    let tag = if_match.map(|tag| format!("\"{tag}\""));
    let mut headers = vec![("authorization", auth.as_str())];
    if let Some(tag) = &tag {
        headers.push(("if-match", tag.as_str()));
    }
    app.send(Method::PATCH, uri, &headers, Some(body)).await
}

/// A service principal holding the global roles `roles`, and an access
/// token for it.
async fn service(app: &TestApp, roles: &[&str]) -> String {
    let token = app.service_token().await;
    let subject = app.verify(&token).await.sub;
    for role in roles {
        let assigned = app
            .control(
                Method::POST,
                &format!("/v1/subjects/{subject}/global-assignments"),
                Some(json!({"role": role})),
            )
            .await;
        assert_eq!(assigned.status, StatusCode::CREATED, "{:?}", assigned.body);
    }
    token
}

/// The events of `kinds` a consumer with `token` reads from the start.
async fn events(app: &TestApp, token: &str, kinds: &str) -> Vec<Value> {
    let reply = app
        .with_bearer(
            Method::GET,
            &format!("/v1/events/batch?after=0&kinds={kinds}&limit=1000"),
            token,
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    reply.body["events"].as_array().unwrap().clone()
}

// r[verify metadata.objects]
// r[verify metadata.write.create]
// r[verify metadata.read]
// r[verify metadata.filter]
#[tokio::test(flavor = "multi_thread")]
async fn every_object_takes_metadata_on_create_and_lists_by_it() {
    let app = TestApp::new().await;
    created(
        &app,
        Method::PUT,
        "/v1/catalog",
        json!({"actions": [{"name": "document:read"}], "scope_kinds": [{"name": "project"}]}),
    )
    .await;

    let (acme, globex) = (id(), id());
    for (tenant, metadata) in [
        (&acme, json!({"billing_id": "b-1", "seats": 5})),
        (&globex, json!({})),
    ] {
        created(
            &app,
            Method::PUT,
            &format!("/v1/tenants/{tenant}"),
            json!({"metadata": metadata}),
        )
        .await;
    }
    let tenant = get(&app, &format!("/v1/tenants/{acme}")).await;
    assert_eq!(tenant["metadata"], json!({"billing_id": "b-1", "seats": 5}));
    assert_eq!(tenant["metadata_etag"].as_str().unwrap().len(), 32);
    let found = get(
        &app,
        &format!("/v1/tenants?{}", filter(&json!({"billing_id": "b-1"}))),
    )
    .await;
    let ids: Vec<&Value> = found["tenants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| &t["id"])
        .collect();
    assert_eq!(ids, [&json!(acme)]);
    let numbers = get(
        &app,
        &format!("/v1/tenants?{}", filter(&json!({"seats": 5}))),
    )
    .await;
    assert_eq!(
        numbers["tenants"].as_array().unwrap().len(),
        1,
        "numbers match by value"
    );

    // A repeated create must match, metadata included.
    let repeat = app
        .control(
            Method::PUT,
            &format!("/v1/tenants/{acme}"),
            Some(json!({"metadata": {"billing_id": "b-2"}})),
        )
        .await;
    assert_eq!(repeat.code(), "CONFLICT");

    let subject = id();
    created(
        &app,
        Method::PUT,
        &format!("/v1/subjects/{subject}"),
        json!({"kind": "service", "metadata": {"owner": "platform"}}),
    )
    .await;
    let key = created(
        &app,
        Method::POST,
        &format!("/v1/subjects/{subject}/credentials"),
        json!({"kind": "secret_key", "metadata": {"name": "Nightly sync"}}),
    )
    .await;
    assert_eq!(
        key["credential"]["metadata"],
        json!({"name": "Nightly sync"})
    );
    let detail = get(&app, &format!("/v1/subjects/{subject}")).await;
    assert_eq!(detail["metadata"], json!({"owner": "platform"}));
    assert_eq!(
        detail["credentials"][0]["metadata"],
        json!({"name": "Nightly sync"})
    );
    let subjects = get(
        &app,
        &format!("/v1/subjects?{}", filter(&json!({"owner": "platform"}))),
    )
    .await;
    assert_eq!(subjects["subjects"].as_array().unwrap().len(), 1);
    assert_eq!(subjects["subjects"][0]["id"], json!(subject));

    let person = app.human("ada@example.com", PASSWORD).await;
    let membership = id();
    created(
        &app,
        Method::PUT,
        &format!("/v1/memberships/{membership}"),
        json!({"subject": person, "tenant": acme, "metadata": {"title": "Owner"}}),
    )
    .await;
    let members = get(
        &app,
        &format!(
            "/v1/tenants/{acme}/memberships?{}",
            filter(&json!({"title": "Owner"}))
        ),
    )
    .await;
    assert_eq!(members.as_array().unwrap().len(), 1);
    let none = get(
        &app,
        &format!(
            "/v1/tenants/{acme}/memberships?{}",
            filter(&json!({"title": "Guest"}))
        ),
    )
    .await;
    assert_eq!(none, json!([]));

    created(
        &app,
        Method::PUT,
        "/v1/templates/reader",
        json!({"metadata": {"label": "Reader"}, "policies": [{"action": "document:read", "effect": "allow"}]}),
    )
    .await;
    created(
        &app,
        Method::PUT,
        &format!("/v1/tenants/{acme}/roles/editor"),
        json!({"metadata": {"label": "Editor"}}),
    )
    .await;
    created(
        &app,
        Method::PUT,
        &format!("/v1/tenants/{acme}/roles/viewer"),
        json!({}),
    )
    .await;
    let roles = get(
        &app,
        &format!(
            "/v1/tenants/{acme}/roles?{}",
            filter(&json!({"label": "Editor"}))
        ),
    )
    .await;
    let keys: Vec<&Value> = roles
        .as_array()
        .unwrap()
        .iter()
        .map(|r| &r["key"])
        .collect();
    assert_eq!(keys, [&json!("editor")]);
    let templates = get(
        &app,
        &format!("/v1/templates?{}", filter(&json!({"label": "Reader"}))),
    )
    .await;
    assert_eq!(templates.as_array().unwrap().len(), 1);

    let share = id();
    let offered = created(
        &app,
        Method::PUT,
        &format!("/v1/shares/{share}"),
        json!({
            "owner": acme, "scope": {"kind": "project", "id": "p-1"}, "recipient": globex,
            "actions": ["document:read"], "metadata": {"label": "Shared plan"},
        }),
    )
    .await;
    assert_eq!(offered["metadata"], json!({"label": "Shared plan"}));
    let shares = get(
        &app,
        &format!(
            "/v1/tenants/{acme}/shares?{}",
            filter(&json!({"label": "Shared plan"}))
        ),
    )
    .await;
    assert_eq!(shares["shares"].as_array().unwrap().len(), 1);

    let client = created(
        &app,
        Method::PUT,
        "/v1/oidc/clients/console",
        json!({
            "kind": "confidential", "redirect_uris": ["https://console.example/callback"],
            "audience": "console", "metadata": {"team": "ops"},
        }),
    )
    .await;
    assert_eq!(client["metadata"], json!({"team": "ops"}));
    let clients = get(
        &app,
        &format!("/v1/oidc/clients?{}", filter(&json!({"team": "ops"}))),
    )
    .await;
    assert_eq!(clients.as_array().unwrap().len(), 1);
    let clients = get(
        &app,
        &format!("/v1/oidc/clients?{}", filter(&json!({"team": "web"}))),
    )
    .await;
    assert_eq!(clients, json!([]));

    // Filters take a JSON object of scalars, nothing else.
    for refused in [
        json!([1]),
        json!({"nested": {"a": 1}}),
        json!({"none": null}),
    ] {
        let reply = app
            .control(
                Method::GET,
                &format!("/v1/tenants?{}", filter(&refused)),
                None,
            )
            .await;
        assert_eq!(reply.code(), "INVALID_REQUEST", "{refused}");
    }
}

// r[verify metadata.write.patch]
// r[verify metadata.write.precondition]
// r[verify metadata.write.replace]
// r[verify platform.batch.operations]
#[tokio::test(flavor = "multi_thread")]
async fn merge_patches_change_only_metadata_and_honour_preconditions() {
    let app = TestApp::new().await;
    let tenant = id();
    created(
        &app,
        Method::PUT,
        &format!("/v1/tenants/{tenant}"),
        json!({"metadata": {"plan": {"name": "team", "seats": 5}, "note": "x"}}),
    )
    .await;
    let uri = format!("/v1/tenants/{tenant}/metadata");
    let read = get(&app, &format!("/v1/tenants/{tenant}")).await;
    let tag = read["metadata_etag"].as_str().unwrap().to_owned();

    let patched = patch(
        &app,
        &uri,
        json!({"plan": {"seats": 10}, "note": null, "billing_id": "b-1"}),
        Some(&tag),
    )
    .await;
    assert_eq!(patched.status, StatusCode::OK, "{:?}", patched.body);
    assert_eq!(
        patched.body["metadata"],
        json!({"plan": {"name": "team", "seats": 10}, "billing_id": "b-1"})
    );
    assert_eq!(
        patched.body["state"], "active",
        "the tenant is otherwise untouched"
    );
    let new_tag = patched.body["metadata_etag"].as_str().unwrap();
    assert_ne!(new_tag, tag);
    assert_eq!(
        patched.headers["etag"].to_str().unwrap(),
        format!("\"{new_tag}\"")
    );

    // A patch made from the old tag fails and changes nothing.
    let stale = patch(&app, &uri, json!({"billing_id": "b-2"}), Some(&tag)).await;
    assert_eq!(stale.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(stale.code(), "PRECONDITION_FAILED");
    let now = get(&app, &format!("/v1/tenants/{tenant}")).await;
    assert_eq!(now["metadata"]["billing_id"], "b-1");
    assert_eq!(now["metadata_etag"], new_tag);
    assert_eq!(
        patch(&app, &uri, json!({"billing_id": "b-3"}), Some("*"))
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        patch(&app, &uri, json!({}), None).await.status,
        StatusCode::OK,
        "without If-Match, unconditionally"
    );
    assert_eq!(
        patch(&app, &uri, json!([1]), None).await.code(),
        "INVALID_REQUEST"
    );
    assert_eq!(
        patch(
            &app,
            &format!("/v1/tenants/{}/metadata", id()),
            json!({}),
            None
        )
        .await
        .code(),
        "NOT_FOUND"
    );

    // Equal metadata has one tag, however it was written.
    let other = id();
    created(
        &app,
        Method::PUT,
        &format!("/v1/tenants/{other}"),
        json!({"metadata": {"billing_id": "b-3", "plan": {"seats": 10, "name": "team"}}}),
    )
    .await;
    let current = get(&app, &format!("/v1/tenants/{tenant}")).await;
    assert_eq!(
        get(&app, &format!("/v1/tenants/{other}")).await["metadata_etag"],
        current["metadata_etag"]
    );

    // In a batch, the precondition rides along as `if_match`.
    let current_tag = current["metadata_etag"].as_str().unwrap();
    let batch = app
        .control(
            Method::POST,
            "/v1/batch",
            Some(json!({"operations": [
                {"method": "PATCH", "path": format!("/tenants/{tenant}/metadata"),
                 "body": {"batched": true}, "if_match": current_tag},
                {"method": "PATCH", "path": format!("/tenants/{tenant}/metadata"),
                 "body": {"again": true}, "if_match": current_tag},
            ]})),
        )
        .await;
    assert_eq!(batch.code(), "PRECONDITION_FAILED", "{:?}", batch.body);
    assert_eq!(batch.body["error"]["operation"], 1);
    assert!(
        get(&app, &format!("/v1/tenants/{tenant}")).await["metadata"]["batched"].is_null(),
        "a failed batch commits nothing"
    );
    let batch = app
        .control(
            Method::POST,
            "/v1/batch",
            Some(json!({"operations": [
                {"method": "PATCH", "path": format!("/tenants/{tenant}/metadata"),
                 "body": {"batched": true}, "if_match": current_tag},
            ]})),
        )
        .await;
    assert_eq!(batch.status, StatusCode::OK, "{:?}", batch.body);
    assert_eq!(
        batch.body["results"][0]["body"]["metadata"]["batched"],
        true
    );

    // Every kind of object has its patch; built-in roles have none.
    let subject = app.human("ada@example.com", PASSWORD).await;
    let detail = get(&app, &format!("/v1/subjects/{subject}")).await;
    let credential = detail["credentials"][0]["id"].as_str().unwrap().to_owned();
    let membership = id();
    created(
        &app,
        Method::PUT,
        &format!("/v1/memberships/{membership}"),
        json!({"subject": subject, "tenant": tenant}),
    )
    .await;
    created(&app, Method::PUT, "/v1/templates/reader", json!({})).await;
    created(
        &app,
        Method::PUT,
        &format!("/v1/tenants/{tenant}/roles/editor"),
        json!({}),
    )
    .await;
    let invite = created(
        &app,
        Method::POST,
        "/v1/invites",
        json!({"email": "bo@example.com", "tenant": tenant}),
    )
    .await["invite_id"]
        .as_str()
        .unwrap()
        .to_owned();
    created(
        &app,
        Method::PUT,
        "/v1/oidc/clients/console",
        json!({"kind": "confidential", "redirect_uris": ["https://console.example/callback"], "audience": "console"}),
    )
    .await;
    for uri in [
        format!("/v1/subjects/{subject}/metadata"),
        format!("/v1/credentials/{credential}/metadata"),
        format!("/v1/memberships/{membership}/metadata"),
        "/v1/templates/reader/metadata".to_owned(),
        format!("/v1/tenants/{tenant}/roles/editor/metadata"),
        format!("/v1/invites/{invite}/metadata"),
        "/v1/oidc/clients/console/metadata".to_owned(),
    ] {
        let reply = patch(&app, &uri, json!({"k": "v"}), None).await;
        assert_eq!(reply.status, StatusCode::OK, "{uri}: {:?}", reply.body);
        assert_eq!(reply.body["metadata"], json!({"k": "v"}), "{uri}");
    }
    let builtin = patch(
        &app,
        "/v1/tenants/root/roles/konklav.admin/metadata",
        json!({"k": "v"}),
        None,
    )
    .await;
    assert_eq!(builtin.code(), "INVALID_REQUEST");

    // A PUT that replaces a definition replaces its metadata; a share keeps
    // its acceptance when only its metadata changes.
    let replaced = created(
        &app,
        Method::PUT,
        &format!("/v1/tenants/{tenant}/roles/editor"),
        json!({"priority": 1}),
    )
    .await;
    assert_eq!(replaced["metadata"], json!({}));
    created(
        &app,
        Method::PUT,
        "/v1/catalog",
        json!({"actions": [{"name": "document:read"}], "scope_kinds": [{"name": "project"}]}),
    )
    .await;
    let share = id();
    let terms = json!({
        "owner": tenant, "scope": {"kind": "project", "id": "p-1"}, "recipient": other,
        "actions": ["document:read"],
    });
    created(
        &app,
        Method::PUT,
        &format!("/v1/shares/{share}"),
        terms.clone(),
    )
    .await;
    created(
        &app,
        Method::POST,
        &format!("/v1/shares/{share}/accept"),
        json!({}),
    )
    .await;
    let mut relabelled = terms.clone();
    relabelled["metadata"] = json!({"label": "Plan"});
    let kept = created(
        &app,
        Method::PUT,
        &format!("/v1/shares/{share}"),
        relabelled,
    )
    .await;
    assert_eq!(
        (kept["state"].as_str(), &kept["metadata"]),
        (Some("accepted"), &json!({"label": "Plan"}))
    );
    let patched = patch(
        &app,
        &format!("/v1/shares/{share}/metadata"),
        json!({"n": 1}),
        None,
    )
    .await;
    assert_eq!(patched.body["state"], "accepted");
    assert_eq!(patched.body["metadata"], json!({"label": "Plan", "n": 1}));
}

// r[verify metadata.limit]
#[tokio::test(flavor = "multi_thread")]
async fn metadata_over_the_limit_is_refused_on_every_write() {
    let app = TestApp::with_auth(|auth| auth.metadata_limit = 64).await;
    let large = json!({"note": "x".repeat(64)});
    let subject = id();
    let refused = app
        .control(
            Method::PUT,
            &format!("/v1/subjects/{subject}"),
            Some(json!({"kind": "human", "metadata": large})),
        )
        .await;
    assert_eq!(refused.code(), "METADATA_TOO_LARGE");
    assert_eq!(
        app.control(Method::GET, &format!("/v1/subjects/{subject}"), None)
            .await
            .status,
        StatusCode::NOT_FOUND,
        "nothing was created"
    );
    let fits = json!({"note": "x".repeat(40)});
    assert_eq!(serde_json::to_vec(&fits).unwrap().len(), 51);
    created(
        &app,
        Method::PUT,
        &format!("/v1/subjects/{subject}"),
        json!({"kind": "human", "metadata": fits}),
    )
    .await;
    let grown = patch(
        &app,
        &format!("/v1/subjects/{subject}/metadata"),
        json!({"more": "x".repeat(10)}),
        None,
    )
    .await;
    assert_eq!(
        grown.code(),
        "METADATA_TOO_LARGE",
        "the patched result counts"
    );
    assert_eq!(
        get(&app, &format!("/v1/subjects/{subject}")).await["metadata"],
        json!({"note": "x".repeat(40)})
    );
    for (uri, body) in [
        (
            "/v1/tenants/".to_owned() + &id(),
            json!({"metadata": large}),
        ),
        (
            "/v1/templates/reader".to_owned(),
            json!({"metadata": large}),
        ),
        (
            "/v1/invites".to_owned(),
            json!({"email": "a@example.com", "metadata": large}),
        ),
    ] {
        let method = if uri == "/v1/invites" {
            Method::POST
        } else {
            Method::PUT
        };
        let reply = app.control(method, &uri, Some(body)).await;
        assert_eq!(reply.code(), "METADATA_TOO_LARGE", "{uri}");
    }
    let imported = app
        .control(
            Method::POST,
            "/v1/import/subjects",
            Some(json!({"subjects": [{"id": id(), "kind": "human", "metadata": large}]})),
        )
        .await;
    assert_eq!(imported.code(), "METADATA_TOO_LARGE");
}

// r[verify metadata.control-plane-only]
// r[verify metadata.opaque]
#[tokio::test(flavor = "multi_thread")]
async fn metadata_stays_on_the_control_plane() {
    let app = TestApp::new().await;
    let subject = app.human("ada@example.com", PASSWORD).await;
    let detail = get(&app, &format!("/v1/subjects/{subject}")).await;
    let credential = detail["credentials"][0]["id"].as_str().unwrap().to_owned();
    let secret = "meta-secret-marker";
    for uri in [
        format!("/v1/subjects/{subject}/metadata"),
        format!("/v1/credentials/{credential}/metadata"),
    ] {
        assert_eq!(
            patch(&app, &uri, json!({"marker": secret}), None)
                .await
                .status,
            StatusCode::OK
        );
    }
    let tenant = id();
    created(
        &app,
        Method::PUT,
        &format!("/v1/tenants/{tenant}"),
        json!({"metadata": {"marker": secret}}),
    )
    .await;
    created(
        &app,
        Method::PUT,
        &format!("/v1/memberships/{}", id()),
        json!({"subject": subject, "tenant": tenant, "metadata": {"marker": secret}}),
    )
    .await;

    let login = app.login("ada@example.com", PASSWORD).await;
    assert_eq!(login.status, StatusCode::OK, "{:?}", login.body);
    let access = login.body["access_token"].as_str().unwrap().to_owned();
    let selected = app
        .send(
            Method::POST,
            "/v1/login/tenant",
            &[("authorization", &format!("Bearer {access}"))],
            Some(json!({"tenant": tenant})),
        )
        .await;
    assert_eq!(selected.status, StatusCode::OK, "{:?}", selected.body);
    let tenant_token = selected.body["access_token"].as_str().unwrap().to_owned();
    let service = app.service_token().await;
    let entitlements = app
        .with_bearer(
            Method::GET,
            &format!("/v1/subjects/{subject}/entitlements?tenant={tenant}"),
            &service,
        )
        .await;
    let mfa = app.with_bearer(Method::GET, "/v1/mfa", &access).await;
    let passkeys = app.with_bearer(Method::GET, "/v1/passkeys", &access).await;
    for (what, text) in [
        ("login", login.body.to_string()),
        ("tenant login", selected.body.to_string()),
        (
            "token claims",
            format!("{:?}", app.verify(&tenant_token).await),
        ),
        ("entitlements", entitlements.body.to_string()),
        ("factors", mfa.body.to_string()),
        ("passkeys", passkeys.body.to_string()),
    ] {
        assert!(!text.contains(secret), "{what} shows metadata: {text}");
    }

    // A subject can't write its own metadata.
    let own = app
        .send(
            Method::PATCH,
            &format!("/v1/subjects/{subject}/metadata"),
            &[("authorization", &format!("Bearer {access}"))],
            Some(json!({"marker": "mine"})),
        )
        .await;
    assert!(
        matches!(own.code(), "FORBIDDEN" | "UNAUTHENTICATED"),
        "{:?}",
        own.body
    );
    assert_eq!(
        get(&app, &format!("/v1/subjects/{subject}")).await["metadata"],
        json!({"marker": secret})
    );
}

// r[verify metadata.events]
// r[verify metadata.feed]
#[tokio::test(flavor = "multi_thread")]
async fn metadata_changes_are_events_withheld_from_who_cant_read_them() {
    let app = TestApp::new().await;
    created(
        &app,
        Method::PUT,
        "/v1/tenants/root/roles/tenant-admin",
        json!({"policies": [{"action": "konklav:tenants:manage", "effect": "allow"}]}),
    )
    .await;
    let plain = service(&app, &[]).await;
    let tenant_admin = service(&app, &["tenant-admin"]).await;
    let admin = service(&app, &["konklav.admin"]).await;

    let tenant = id();
    created(
        &app,
        Method::PUT,
        &format!("/v1/tenants/{tenant}"),
        json!({"metadata": {"billing_id": "b-1"}}),
    )
    .await;
    let subject = app.human("ada@example.com", PASSWORD).await;
    let membership = id();
    created(
        &app,
        Method::PUT,
        &format!("/v1/memberships/{membership}"),
        json!({"subject": subject, "tenant": tenant}),
    )
    .await;
    let before = events(&app, &admin, "entitlements.changed").await.len();
    patch(
        &app,
        &format!("/v1/memberships/{membership}/metadata"),
        json!({"title": "Owner"}),
        None,
    )
    .await;
    patch(
        &app,
        &format!("/v1/tenants/{tenant}/metadata"),
        json!({"billing_id": null}),
        None,
    )
    .await;
    patch(
        &app,
        &format!("/v1/subjects/{subject}/metadata"),
        json!({"locale": "sv"}),
        None,
    )
    .await;
    assert_eq!(
        events(&app, &admin, "entitlements.changed").await.len(),
        before,
        "metadata changes no one's entitlements"
    );

    let changes = |events: &[Value]| -> Vec<(String, Value)> {
        events
            .iter()
            .map(|e| {
                let payload = &e["payload"];
                (
                    payload["object"].as_str().unwrap().to_owned(),
                    payload
                        .get("metadata")
                        .cloned()
                        .unwrap_or(json!("withheld")),
                )
            })
            .collect()
    };
    assert_eq!(
        changes(&events(&app, &admin, "metadata.changed").await),
        [
            ("tenant".to_owned(), json!({"billing_id": "b-1"})),
            ("membership".to_owned(), json!({"title": "Owner"})),
            ("tenant".to_owned(), json!({})),
            ("subject".to_owned(), json!({"locale": "sv"})),
        ]
    );
    assert_eq!(
        changes(&events(&app, &tenant_admin, "metadata.changed").await),
        [
            ("tenant".to_owned(), json!({"billing_id": "b-1"})),
            ("membership".to_owned(), json!({"title": "Owner"})),
            ("tenant".to_owned(), json!({})),
            ("subject".to_owned(), json!("withheld")),
        ],
        "tenants:manage reads tenants' and memberships' metadata only"
    );
    let withheld = events(&app, &plain, "metadata.changed").await;
    assert_eq!(withheld.len(), 4);
    assert!(
        withheld
            .iter()
            .all(|e| e["payload"].get("metadata").is_none())
    );
    assert_eq!(withheld[1]["payload"]["id"], json!(membership));

    // Deleting an object announces it, with null.
    created(
        &app,
        Method::PUT,
        &format!("/v1/tenants/{tenant}/roles/editor"),
        json!({"metadata": {"label": "Editor"}}),
    )
    .await;
    app.control(
        Method::DELETE,
        &format!("/v1/tenants/{tenant}/roles/editor"),
        None,
    )
    .await;
    let roles: Vec<Value> = events(&app, &admin, "metadata.changed")
        .await
        .into_iter()
        .filter(|e| e["payload"]["object"] == "role")
        .map(|e| e["payload"]["metadata"].clone())
        .collect();
    assert_eq!(roles, [json!({"label": "Editor"}), Value::Null]);
}

// r[verify metadata.invites]
// r[verify metadata.filter]
#[tokio::test(flavor = "multi_thread")]
async fn invites_hand_their_metadata_to_delivery_and_redemption() {
    let app = TestApp::new().await;
    let mailer = service(&app, &["konklav.delivery"]).await;
    let admin = service(&app, &["konklav.admin"]).await;
    let plain = service(&app, &[]).await;
    let tenant = id();
    created(
        &app,
        Method::PUT,
        &format!("/v1/tenants/{tenant}"),
        json!({}),
    )
    .await;
    let membership = id();
    let invite = created(
        &app,
        Method::POST,
        "/v1/invites",
        json!({
            "email": "new@example.com", "tenant": tenant, "membership": membership,
            "metadata": {"tenant_id": "t-1", "invited_by": "u-9", "locale": "sv-SE"},
        }),
    )
    .await["invite_id"]
        .as_str()
        .unwrap()
        .to_owned();
    created(
        &app,
        Method::POST,
        "/v1/invites",
        json!({"email": "other@example.com", "metadata": {"tenant_id": "t-2"}}),
    )
    .await;

    let delivery = events(&app, &mailer, "delivery.requested").await;
    let request = delivery
        .iter()
        .find(|e| e["payload"]["recipient"] == "new@example.com")
        .unwrap();
    assert_eq!(request["payload"]["invite"], json!(invite));
    assert_eq!(
        request["payload"]["metadata"],
        json!({"tenant_id": "t-1", "invited_by": "u-9", "locale": "sv-SE"}),
        "the deliverer can write the message"
    );
    let token = request["payload"]["material"]["token"]
        .as_str()
        .unwrap()
        .to_owned();

    let listed = get(
        &app,
        &format!("/v1/invites?{}", filter(&json!({"tenant_id": "t-1"}))),
    )
    .await;
    let ids: Vec<&Value> = listed["invites"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| &i["id"])
        .collect();
    assert_eq!(ids, [&json!(invite)]);
    let to_tenant = get(&app, &format!("/v1/invites?tenant={tenant}")).await;
    assert_eq!(to_tenant["invites"].as_array().unwrap().len(), 1);
    let all = get(&app, "/v1/invites?limit=1").await;
    assert_eq!(all["invites"].as_array().unwrap().len(), 1);
    assert!(all["next"].is_string(), "paged");

    // A repeat with other metadata is a conflict and delivers nothing.
    let repeat = app
        .control(
            Method::POST,
            "/v1/invites",
            Some(
                json!({"id": invite, "email": "new@example.com", "tenant": tenant,
                        "membership": membership, "metadata": {"tenant_id": "t-9"}}),
            ),
        )
        .await;
    assert_eq!(repeat.code(), "CONFLICT");

    let patched = patch(
        &app,
        &format!("/v1/invites/{invite}/metadata"),
        json!({"locale": null, "accepted_terms": "v2"}),
        None,
    )
    .await;
    assert_eq!(patched.status, StatusCode::OK, "{:?}", patched.body);
    let redeemed = app
        .post(
            "/v1/invites/redeem",
            json!({"token": token, "password": "my new password"}),
        )
        .await;
    assert_eq!(redeemed.status, StatusCode::OK, "{:?}", redeemed.body);
    assert!(
        !redeemed.body.to_string().contains("invited_by"),
        "the redeemer isn't shown the invite's metadata"
    );
    let subject = app
        .verify(redeemed.body["access_token"].as_str().unwrap())
        .await
        .sub;

    let handed = events(&app, &admin, "invite.redeemed").await;
    assert_eq!(handed.len(), 1);
    assert_eq!(
        handed[0]["payload"],
        json!({
            "invite": invite,
            "subject": subject,
            "tenant": tenant,
            "membership": membership,
            "metadata": {"tenant_id": "t-1", "invited_by": "u-9", "accepted_terms": "v2"},
        })
    );
    let unprivileged = events(&app, &plain, "invite.redeemed").await;
    assert!(unprivileged[0]["payload"].get("metadata").is_none());
    assert_eq!(unprivileged[0]["payload"]["membership"], json!(membership));
    assert_eq!(
        get(&app, &format!("/v1/invites/{invite}")).await["metadata"]["accepted_terms"],
        "v2"
    );
}

// r[verify metadata.history]
#[tokio::test(flavor = "multi_thread")]
async fn history_records_metadata() {
    use diesel_async::RunQueryDsl;

    #[derive(diesel::QueryableByName)]
    struct Version {
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        data: Value,
    }

    let app = TestApp::new().await;
    {
        let mut conn = app.db.pool().get().await.unwrap();
        konklav_store::history::configure(&mut conn, Some(chrono::Duration::days(1)))
            .await
            .unwrap();
    }
    let tenant = id();
    created(
        &app,
        Method::PUT,
        &format!("/v1/tenants/{tenant}"),
        json!({"metadata": {"v": 1}}),
    )
    .await;
    patch(
        &app,
        &format!("/v1/tenants/{tenant}/metadata"),
        json!({"v": 2}),
        None,
    )
    .await;
    let mut conn = app.db.pool().get().await.unwrap();
    let versions: Vec<Version> = diesel::sql_query(
        "select data from row_version where relation = 'tenant'::regclass \
         and key ->> 'id' = $1 order by id",
    )
    .bind::<diesel::sql_types::Text, _>(&tenant)
    .load(&mut conn)
    .await
    .unwrap();
    let metadata: Vec<&Value> = versions.iter().map(|v| &v.data["metadata"]).collect();
    // Writes in one test transaction may be one version; the last is current.
    assert_eq!(metadata.last(), Some(&&json!({"v": 2})), "{metadata:?}");
    assert!(metadata.contains(&&json!({"v": 1})) || metadata.len() == 1);
}

// r[verify import.metadata]
#[tokio::test(flavor = "multi_thread")]
async fn imports_carry_metadata_and_leave_it_on_a_rerun() {
    let app = TestApp::new().await;
    let subject = id();
    let credential = id();
    let import = |metadata: Value| json!({"subjects": [{"id": subject, "kind": "human", "metadata": metadata}]});
    created(
        &app,
        Method::POST,
        "/v1/import/subjects",
        import(json!({"legacy_id": 7})),
    )
    .await;
    created(
        &app,
        Method::POST,
        "/v1/import/credentials",
        json!({"credentials": [{
            "id": credential, "subject": subject, "identifier": "old@example.com",
            "kind": "email_link", "metadata": {"source": "legacy"},
        }]}),
    )
    .await;
    let again = created(
        &app,
        Method::POST,
        "/v1/import/subjects",
        import(json!({"legacy_id": 8})),
    )
    .await;
    assert_eq!(again["skipped"], 1);
    let detail = get(&app, &format!("/v1/subjects/{subject}")).await;
    assert_eq!(detail["metadata"], json!({"legacy_id": 7}));
    assert_eq!(
        detail["credentials"][0]["metadata"],
        json!({"source": "legacy"})
    );
}

// r[verify metadata.erasure]
// r[verify retention.delivery-material]
#[tokio::test(flavor = "multi_thread")]
async fn metadata_goes_with_its_object_and_its_delivery_material() {
    let app = TestApp::new().await;
    let mailer = service(&app, &["konklav.delivery"]).await;
    let tenant = id();
    created(
        &app,
        Method::PUT,
        &format!("/v1/tenants/{tenant}"),
        json!({}),
    )
    .await;
    created(
        &app,
        Method::PUT,
        &format!("/v1/tenants/{tenant}/roles/editor"),
        json!({"metadata": {"label": "Editor"}}),
    )
    .await;
    app.control(
        Method::DELETE,
        &format!("/v1/tenants/{tenant}/roles/editor"),
        None,
    )
    .await;
    created(
        &app,
        Method::PUT,
        &format!("/v1/tenants/{tenant}/roles/editor"),
        json!({}),
    )
    .await;
    assert_eq!(
        get(&app, &format!("/v1/tenants/{tenant}/roles/editor")).await["metadata"],
        json!({}),
        "a role made again under the same key starts empty"
    );

    created(
        &app,
        Method::POST,
        "/v1/invites",
        json!({"email": "new@example.com", "metadata": {"invited_by": "u-9"}}),
    )
    .await;
    let delivery = events(&app, &mailer, "delivery.requested").await;
    assert_eq!(
        delivery[0]["payload"]["metadata"],
        json!({"invited_by": "u-9"})
    );
    let mut conn = app.db.pool().get().await.unwrap();
    let later = chrono::Utc::now() + chrono::Duration::days(31);
    let erased = konklav_store::sweep::delivery_material(&mut conn, later, 100)
        .await
        .unwrap();
    assert_eq!(erased, 1);
    let delivery = events(&app, &mailer, "delivery.requested").await;
    let payload = &delivery[0]["payload"];
    assert!(
        payload.get("metadata").is_none() && payload.get("material").is_none(),
        "{payload}"
    );
}
