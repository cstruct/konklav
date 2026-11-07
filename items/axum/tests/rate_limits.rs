//! Rate limits on routes, key templates and client addresses, against a
//! fake relying host.

mod support;

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::ConnectInfo;
use axum::http::StatusCode;
use axum::routing::get;
use konklav_axum::{
    Denied, Konklav, Policy, RoutePolicy, RoutePolicyError, RouteRateLimit, RouterPolicy,
    retry_after_seconds,
};
use konklav_relying_client::rate_limit::{RateLimit, RateLimitConfig, RateLimitWindow};
use konklav_token::TokenKind;
use serde_json::json;
use support::{FakeHost, SUBJECT, bearer, get as request, send};

fn limit(name: &str, size: u32) -> RateLimit {
    RateLimit::new(RateLimitConfig::new(
        name,
        vec![RateLimitWindow {
            size,
            period_ms: 3_600_000,
        }],
    ))
    .unwrap()
}

fn konklav(host: &Arc<FakeHost>, proxies: &[&str]) -> Konklav {
    Konklav::builder(host.clone())
        .trusted_proxies(proxies.iter().copied())
        .build()
        .unwrap()
}

async fn ok() -> &'static str {
    "ok"
}

// r[verify item.axum.rate-limit]
// r[verify item.axum.rate-limited]
// r[verify item.axum.rate-limit-template]
#[tokio::test]
async fn policy_limits_key_on_the_verified_token_and_answer_429() {
    let host = FakeHost::allowing();
    let exports = limit("export", 1);
    let route = RoutePolicy::new(&Policy::new())
        .unwrap()
        .rate_limit(RouteRateLimit::new(exports.clone(), "{token:sub}/{path:project}").unwrap())
        .unwrap();
    let app = Router::new()
        .route("/projects/{project}/export", get(ok).route_layer(route))
        .layer(konklav(&host, &[]).layer());
    let token = bearer("tenant");
    let headers = [("authorization", token.as_str())];
    assert_eq!(
        send(&app, request("/projects/p-1/export", &headers))
            .await
            .status,
        StatusCode::OK
    );
    let limited = send(&app, request("/projects/p-1/export", &headers)).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.body, json!({"error": {"code": "rate_limited"}}));
    let retry_after: u64 = limited.header("retry-after").unwrap().parse().unwrap();
    assert!((3600..=3600 + 360).contains(&retry_after), "{retry_after}");
    assert_eq!(
        send(&app, request("/projects/p-2/export", &headers))
            .await
            .status,
        StatusCode::OK,
        "another project, another key"
    );
    // The key is the parts as a JSON array, as konklav-fastapi renders it.
    let key = format!(r#"["{SUBJECT}","/","p-1"]"#);
    assert!(exports.add(key).await.is_err(), "the template's key");

    let denied = send(&app, request("/projects/p-3/export", &[])).await;
    assert_eq!(
        denied.status,
        StatusCode::UNAUTHORIZED,
        "denied requests aren't counted"
    );
}

// r[verify item.axum.rate-limit]
// r[verify item.axum.client-address]
#[tokio::test]
async fn layer_limits_key_on_the_client_address_behind_trusted_proxies() {
    let host = FakeHost::allowing();
    let login = limit("login", 1);
    let app = Router::new()
        .route(
            "/login",
            get(ok)
                .route_layer(RouteRateLimit::new(login, "{client:address}").unwrap())
                .route_layer(RoutePolicy::public()),
        )
        .layer(konklav(&host, &["203.0.113.0/24"]).layer());
    let from = |forwarded: &str| request("/login", &[("x-forwarded-for", forwarded)]);
    assert_eq!(
        send(&app, from("198.51.100.1")).await.status,
        StatusCode::OK
    );
    assert_eq!(
        send(&app, from("1.2.3.4, 198.51.100.1")).await.status,
        StatusCode::TOO_MANY_REQUESTS,
        "the same client behind the trusted proxy"
    );
    assert_eq!(
        send(&app, from("198.51.100.2")).await.status,
        StatusCode::OK
    );

    let mut direct = request("/login", &[("x-forwarded-for", "198.51.100.9")]);
    direct
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from(([192, 0, 2, 1], 1))));
    assert_eq!(send(&app, direct).await.status, StatusCode::OK);
    let mut again = request("/login", &[("x-forwarded-for", "198.51.100.10")]);
    again
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from(([192, 0, 2, 1], 2))));
    assert_eq!(
        send(&app, again).await.status,
        StatusCode::TOO_MANY_REQUESTS,
        "an untrusted peer is the client, whatever it claims"
    );

    // r[verify item.axum.misconfiguration]
    let mut no_peer = request("/login", &[]);
    no_peer
        .extensions_mut()
        .remove::<ConnectInfo<std::net::SocketAddr>>();
    assert_eq!(
        send(&app, no_peer).await.status,
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

#[tokio::test]
async fn keys_can_come_from_a_function_of_the_request_and_token() {
    let host = FakeHost::allowing();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = seen.clone();
    let per_subject = RouteRateLimit::keyed(limit("subject", 1), move |parts, token| {
        record.lock().unwrap().push((
            parts.uri.path().to_owned(),
            token.map(|token| token.sub.to_string()),
        ));
        let key = token.map_or_else(Vec::new, |token| token.sub.to_string().into_bytes());
        async move { key }
    });
    let app = Router::new()
        .route(
            "/",
            get(ok).route_layer(
                RoutePolicy::new(&Policy::new())
                    .unwrap()
                    .rate_limit(per_subject)
                    .unwrap(),
            ),
        )
        .layer(konklav(&host, &[]).layer());
    let headers = [("authorization", "Bearer tenant")];
    assert_eq!(
        send(&app, request("/", &headers)).await.status,
        StatusCode::OK
    );
    assert_eq!(
        send(&app, request("/", &headers)).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        seen.lock().unwrap()[0],
        ("/".to_owned(), Some(SUBJECT.to_owned()))
    );
}

// r[verify item.axum.rate-limited]
#[tokio::test]
async fn limits_added_in_handlers_answer_alike() {
    let host = FakeHost::allowing();
    let login = limit("handler", 1);
    let handler = move || {
        let login = login.clone();
        async move {
            login.add("a@example.com").await?;
            Ok::<_, Denied>("ok")
        }
    };
    let app = Router::new()
        .route("/", get(handler).route_layer(RoutePolicy::public()))
        .layer(konklav(&host, &[]).layer());
    assert_eq!(send(&app, request("/", &[])).await.status, StatusCode::OK);
    let limited = send(&app, request("/", &[])).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(limited.header("retry-after").is_some());
}

#[test]
fn retry_after_rounds_up_and_adds_jitter() {
    for _ in 0..100 {
        assert!((1..=2).contains(&retry_after_seconds(1)));
        assert!((1..=2).contains(&retry_after_seconds(1000)));
        assert!((2..=3).contains(&retry_after_seconds(1001)));
        assert!((100..=110).contains(&retry_after_seconds(100_000)));
    }
    assert!(
        (0..200).any(|_| retry_after_seconds(100_000) != 100),
        "jittered"
    );
}

// r[verify item.axum.rate-limit-template-validation]
#[test]
fn route_policies_refuse_templates_they_cant_render() {
    let template = |text| RouteRateLimit::new(limit("t", 1), text).unwrap();
    let public = RoutePolicy::public().rate_limit(template("{token:sub}"));
    assert!(
        matches!(&public, Err(RoutePolicyError::RateLimit { problem, .. }) if problem.contains("public")),
        "{:?}",
        public.err()
    );
    let either = RouterPolicy::default()
        .route(&Policy::new().token_kinds([TokenKind::Identity, TokenKind::Tenant]))
        .unwrap();
    let tid = either.clone().rate_limit(template("{token:tid}"));
    assert!(matches!(tid, Err(RoutePolicyError::RateLimit { .. })));
    assert!(either.rate_limit(template("{token:sub}/{path:p}")).is_ok());
    let tenant_only = RoutePolicy::new(&Policy::new()).unwrap();
    assert!(tenant_only.rate_limit(template("{token:tid}")).is_ok());
    assert!(
        RoutePolicy::public()
            .rate_limit(template("{client:address}"))
            .is_ok()
    );
}

// r[verify item.axum.rate-limit-template-validation]
// r[verify item.axum.misconfiguration]
#[tokio::test]
async fn templates_a_request_cant_render_fail_closed() {
    let host = FakeHost::allowing();
    let app = Router::new()
        .route(
            "/missing",
            get(ok).route_layer(
                RoutePolicy::new(&Policy::new())
                    .unwrap()
                    .rate_limit(RouteRateLimit::new(limit("path", 5), "{path:project}").unwrap())
                    .unwrap(),
            ),
        )
        .route(
            "/outside",
            // Applied after, so outside the policy: no token yet.
            get(ok)
                .route_layer(RoutePolicy::new(&Policy::new()).unwrap())
                .route_layer(RouteRateLimit::new(limit("outside", 5), "{token:sub}").unwrap()),
        )
        .layer(konklav(&host, &[]).layer());
    for path in ["/missing", "/outside"] {
        let answer = send(&app, request(path, &[("authorization", "Bearer tenant")])).await;
        assert_eq!(answer.status, StatusCode::INTERNAL_SERVER_ERROR, "{path}");
    }
}

#[test]
fn invalid_trusted_proxies_are_refused() {
    let error = Konklav::builder(FakeHost::allowing())
        .trusted_proxies(["10.0.0.0/8", "proxy.internal"])
        .build()
        .err()
        .unwrap();
    assert_eq!(error.0, "proxy.internal");
}
