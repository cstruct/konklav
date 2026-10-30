//! One Konklav signing people in to another.
//!
//! An operators' instance (the upstream) is an OpenID provider. An
//! environment's instance (the downstream) lets people sign in through it,
//! creating their subject on first sign-in and granting a local role from
//! the upstream's `groups` claim. This scenario plays both the browser and
//! the upstream's login page, so every hop is visible.

use std::path::Path;

use reqwest::{Method, StatusCode, header};
use serde_json::{Value, json};

use crate::harness::{Server, Setup};
use crate::{Result, check, fail, step};

const EMAIL: &str = "ada@ops.example";
const PASSWORD: &str = "correct horse battery";
/// The upstream's login page, which the scenario plays.
const LOGIN_PAGE: &str = "http://login.ops.example";
/// The downstream's app, where a sign-in returns.
const APP: &str = "http://app.env.example";

fn location(reply: &reqwest::Response) -> Result<String> {
    reply
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .ok_or_else(|| {
            fail(format!(
                "{} has no redirect ({})",
                reply.url(),
                reply.status()
            ))
        })
}

/// The `name=value` of a cookie the reply sets.
fn cookie(reply: &reqwest::Response, name: &str) -> Result<String> {
    reply
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with(&format!("{name}=")))
        .and_then(|value| value.split(';').next())
        .map(str::to_owned)
        .ok_or_else(|| fail(format!("{} sets no {name} cookie", reply.url())))
}

fn query(url: &str, key: &str) -> Result<String> {
    reqwest::Url::parse(url)?
        .query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
        .ok_or_else(|| fail(format!("{url} has no {key}")))
}

/// Starts the upstream with an operator in the `sre` global role.
async fn upstream(binary: &Path) -> Result<Server> {
    let up = Server::start(&Setup {
        binary: Some(binary.to_owned()),
        login_url: Some(format!("{LOGIN_PAGE}/sign-in")),
        browser_origins: vec![LOGIN_PAGE.into()],
        ..Setup::default()
    })
    .await?;
    let ada = up
        .human(json!({"kind": "password", "identifier": EMAIL, "password": PASSWORD}))
        .await?;
    up.control(Method::PUT, "/v1/tenants/root/roles/sre", Some(json!({})))
        .await?;
    up.control(
        Method::POST,
        &format!("/v1/subjects/{ada}/global-assignments"),
        Some(json!({"role": "sre"})),
    )
    .await?;
    Ok(up)
}

/// Prepares the downstream, registers it as a client of the upstream, and
/// starts it with the upstream as an identity provider.
async fn downstream(binary: &Path, up: &Server) -> Result<Server> {
    let mut down = Server::prepare(&Setup {
        binary: Some(binary.to_owned()),
        browser_origins: vec![APP.into()],
        ..Setup::default()
    })
    .await?;
    let callback = format!("{}/v1/login/oidc/ops/callback", down.subject);
    up.control(
        Method::PUT,
        "/v1/oidc/clients/env",
        Some(json!({
            "kind": "confidential",
            "redirect_uris": [callback],
            "scopes": ["openid", "groups"],
            "audience": "env",
            "visible_groups": ["sre"],
        })),
    )
    .await?;
    let secret = up
        .control(Method::POST, "/v1/oidc/clients/env/secret", None)
        .await?["client_secret"]
        .as_str()
        .ok_or_else(|| fail("no client secret"))?
        .to_owned();
    down.extend(
        &format!(
            "identity_providers ({{\n    id ops\n    issuer {issuer:?}\n    client_id env\n    \
             redirect_uri {callback:?}\n    scopes (openid groups)\n    return_urls (\"{APP}/\")\n    \
             provisioning create\n    local_mfa_factors 0\n    \
             grants ({{claim groups, contains sre, global_role operator}})\n}})\n",
            issuer = up.subject,
        ),
        &format!("identity_provider_secrets ({{provider ops, client_secret {secret:?}}})\n"),
    )
    .await?;
    down.serve().await?;
    down.control(
        Method::PUT,
        "/v1/catalog",
        Some(json!({"actions": [{"name": "env:operate"}]})),
    )
    .await?;
    down.control(
        Method::PUT,
        "/v1/tenants/root/roles/operator",
        Some(json!({"policies": [{"action": "env:operate", "effect": "allow"}]})),
    )
    .await?;
    Ok(down)
}

/// The browser signs in at the downstream through the upstream, with the
/// scenario playing the upstream's login page. Returns the downstream's
/// refresh cookie.
async fn sign_in(up: &Server, down: &Server) -> Result<String> {
    let http = &down.http;
    step("the browser starts signing in at the downstream");
    let started = http
        .get(format!("{}/v1/login/oidc/ops/start", down.subject))
        .send()
        .await?;
    let state = cookie(&started, "konklav_oidc")?;
    let authorize = location(&started)?;
    println!("    redirected to {authorize}");

    step("the upstream hands the request to its login page");
    let handed_off = http.get(&authorize).send().await?;
    let login_page = location(&handed_off)?;
    let browser = cookie(&handed_off, "konklav_authorize")?;
    let request = query(&login_page, "login_request")?;
    println!("    redirected to {login_page}");

    step("the login page signs the operator in and accepts the request");
    let (status, login) = up
        .post(
            "/v1/login/password",
            &json!({"identifier": EMAIL, "password": PASSWORD}),
        )
        .await?;
    check(status.is_success(), || {
        format!("signing in upstream: {status} {login}")
    })?;
    let token = login["access_token"].as_str().unwrap_or_default();
    let accepted: Value = http
        .post(format!(
            "{}/v1/oauth2/login-requests/{request}/accept",
            up.subject
        ))
        .bearer_auth(token)
        .header(header::ORIGIN, LOGIN_PAGE)
        .header("x-konklav-client", "web")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let resume = accepted["redirect_to"]
        .as_str()
        .ok_or_else(|| fail(format!("no redirect in {accepted}")))?;

    step("the browser resumes the authorization and returns to the downstream");
    let resumed = http
        .get(resume)
        .header(header::COOKIE, &browser)
        .send()
        .await?;
    let callback = location(&resumed)?;
    check(callback.starts_with(&down.subject), || {
        format!("the upstream sent the browser to {callback}")
    })?;
    let signed_in = http
        .get(&callback)
        .header(header::COOKIE, &state)
        .send()
        .await?;
    check(signed_in.status() == StatusCode::SEE_OTHER, || {
        format!("the callback answered {}", signed_in.status())
    })?;
    let back = location(&signed_in)?;
    println!("    back at {back}");
    check(query(&back, "signed_in").is_ok_and(|v| v == "true"), || {
        format!("the sign-in failed: {back}\n{}", down.log())
    })?;
    let refresh = cookie(&signed_in, "konklav_refresh")?;
    Ok(refresh)
}

/// Runs the scenario against servers started from `binary`.
pub async fn run(binary: &Path) -> Result<()> {
    step("starting the upstream, an OpenID provider with an operator in `sre`");
    let up = upstream(binary).await?;
    step("starting the downstream, which signs people in through the upstream");
    let down = downstream(binary, &up).await?;

    let refresh = sign_in(&up, &down).await?;
    let http = &down.http;

    step("the app gets an access token for the new subject");
    let tokens: Value = http
        .post(format!("{}/v1/refresh", down.subject))
        .header(header::COOKIE, &refresh)
        .header(header::ORIGIN, APP)
        .header("x-konklav-client", "web")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let access = tokens["access_token"].as_str().unwrap_or_default();
    let me: Value = http
        .get(format!("{}/v1/capabilities", down.subject))
        .bearer_auth(access)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let subject = me["subject"].as_str().unwrap_or_default();

    step("the downstream's operator sees what the upstream's `sre` granted");
    let entitlements = down
        .control(
            Method::GET,
            &format!("/v1/subjects/{subject}/entitlements"),
            None,
        )
        .await?;
    check(entitlements["global"] == json!(["env:operate"]), || {
        format!("the subject holds {entitlements}, not env:operate")
    })?;
    step("signed in at the downstream, holding env:operate through the upstream's `sre`");
    Ok(())
}
