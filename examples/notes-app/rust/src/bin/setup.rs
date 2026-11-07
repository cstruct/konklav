//! Seeds Konklav for the example over the control-plane surface, with the
//! bootstrap token, as the Python version's `setup.py` does:
//!
//! - the action catalog and the global roles
//! - Ada (member, editor, admin) and Bob (member)
//! - the `app` (public) and `admin` (confidential) OIDC clients, both
//!   requiring DPoP
//! - the `app-api` and `admin-api` service principals
//!
//! It writes the secrets the apps need to `SECRETS_FILE`, and does nothing
//! if that file exists, since secrets are shown only once.

use std::path::Path;
use std::time::Duration;

use konklav_sso_example::env;
use reqwest::{Client, Method};
use serde_json::{Value, json};
use uuid::Uuid;

const APP: &str = "http://localhost:3000";
const ADMIN: &str = "http://localhost:4000";

// Stable ids, so a second run after a lost secrets file doesn't duplicate.
const NAMESPACE: Uuid = Uuid::from_u128(0x6f1d_3c3e_3b8e_4c2a_9d1c_5b0a_8e7f_2a10);

fn stable_id(name: &str) -> String {
    Uuid::new_v5(&NAMESPACE, name.as_bytes()).to_string()
}

const PEOPLE: [(&str, &str, &[&str]); 2] = [
    (
        "ada@example.com",
        "correct horse battery",
        &["member", "editor", "admin"],
    ),
    ("bob@example.com", "bob's long password", &["member"]),
];

const ROLES: [(&str, &[&str]); 4] = [
    ("member", &["notes:read"]),
    ("editor", &["notes:read", "notes:write"]),
    ("admin", &["admin:access"]),
    // The admin page's service principal: managing people, their roles and
    // their sessions, and nothing else of the control plane.
    (
        "admin-api",
        &[
            "konklav:subjects:manage",
            "konklav:authz:manage",
            "konklav:sessions:manage",
        ],
    ),
];

struct ControlPlane {
    http: Client,
    url: String,
    token: String,
}

impl ControlPlane {
    async fn call(&self, method: Method, path: &str, body: Option<Value>) -> Value {
        let mut request = self
            .http
            .request(method.clone(), format!("{}/v1{path}", self.url))
            .bearer_auth(&self.token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.expect("reaching the control plane");
        let status = response.status();
        let body: Value = response.json().await.unwrap_or(Value::Null);
        assert!(status.is_success(), "{method} {path}: {status} {body}");
        body
    }

    async fn put(&self, path: &str, body: Value) -> Value {
        self.call(Method::PUT, path, Some(body)).await
    }

    async fn post(&self, path: &str, body: Option<Value>) -> Value {
        self.call(Method::POST, path, body).await
    }

    /// A service principal with a fresh secret key: `<key id>.<secret>`.
    async fn service_principal(&self, name: &str, roles: &[&str]) -> String {
        let subject = stable_id(&format!("service:{name}"));
        self.put(&format!("/subjects/{subject}"), json!({"kind": "service"}))
            .await;
        let created = self
            .post(
                &format!("/subjects/{subject}/credentials"),
                Some(json!({"kind": "secret_key"})),
            )
            .await;
        for role in roles {
            self.post(
                &format!("/subjects/{subject}/global-assignments"),
                Some(json!({"role": role})),
            )
            .await;
        }
        created["secret_keys"]["a"]
            .as_str()
            .expect("a secret key")
            .to_owned()
    }
}

async fn wait_until_ready(http: &Client, subject_url: &str) {
    for _ in 0..120 {
        if let Ok(response) = http.get(format!("{subject_url}/readyz")).send().await
            && response.status().is_success()
        {
            return;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    panic!("Konklav never became ready");
}

#[tokio::main]
async fn main() {
    let secrets_file = env("SECRETS_FILE");
    if Path::new(&secrets_file).exists() {
        println!("{secrets_file} exists; Konklav is already set up");
        return;
    }
    let http = Client::new();
    wait_until_ready(&http, &env("KONKLAV_SUBJECT_URL")).await;
    let control = ControlPlane {
        http,
        url: env("KONKLAV_CONTROL_URL"),
        token: env("KONKLAV_BOOTSTRAP_TOKEN"),
    };

    control
        .put(
            "/catalog",
            json!({"actions": [
                {"name": "notes:read", "description": "Read the app's notes"},
                {"name": "notes:write", "description": "Write notes in the app"},
                {"name": "admin:access", "description": "Use the admin page"},
            ]}),
        )
        .await;
    for (key, actions) in ROLES {
        let policies: Vec<Value> = actions
            .iter()
            .map(|action| json!({"action": action, "effect": "allow"}))
            .collect();
        control
            .put(
                &format!("/tenants/root/roles/{key}"),
                json!({"policies": policies}),
            )
            .await;
    }

    for (email, password, roles) in PEOPLE {
        let subject = stable_id(&format!("person:{email}"));
        control
            .put(&format!("/subjects/{subject}"), json!({"kind": "human"}))
            .await;
        control
            .post(
                &format!("/subjects/{subject}/credentials"),
                Some(json!({
                    "id": stable_id(&format!("password:{email}")),
                    "kind": "password",
                    "identifier": email,
                    "password": password,
                })),
            )
            .await;
        for role in roles {
            control
                .post(
                    &format!("/subjects/{subject}/global-assignments"),
                    Some(json!({"id": stable_id(&format!("{email}:{role}")), "role": role})),
                )
                .await;
        }
        println!("{email}: {}", roles.join(", "));
    }

    control
        .put(
            "/oidc/clients/app",
            json!({
                "kind": "public",
                "redirect_uris": [format!("{APP}/callback")],
                "post_logout_redirect_uris": [format!("{APP}/")],
                "audience": "app-api",
                "scopes": ["openid", "email"],
                "refresh": true,
                "require_dpop": true,
            }),
        )
        .await;
    control
        .put(
            "/oidc/clients/admin",
            json!({
                "kind": "confidential",
                "redirect_uris": [format!("{ADMIN}/callback")],
                "post_logout_redirect_uris": [format!("{ADMIN}/")],
                "audience": "admin",
                "scopes": ["openid", "email"],
                "refresh": true,
                "require_dpop": true,
                "require_pkce": true,
            }),
        )
        .await;
    let admin_secret =
        control.post("/oidc/clients/admin/secret", None).await["client_secret"].clone();

    let secrets = json!({
        "app_api_key": control.service_principal("app-api", &[]).await,
        "admin_api_key": control.service_principal("admin-api", &["admin-api"]).await,
        "admin_client_secret": admin_secret,
    });
    write_secrets(&secrets_file, &secrets);
    println!("wrote {secrets_file}");
}

/// Writes the file readable by this user only, all at once.
fn write_secrets(path: &str, secrets: &Value) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let temporary = format!("{path}.tmp");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temporary)
        .expect("creating the secrets file");
    file.write_all(secrets.to_string().as_bytes())
        .expect("writing the secrets");
    std::fs::rename(&temporary, path).expect("moving the secrets file into place");
}
