//! Route policies, evaluation, outcomes and extractors, against a fake
//! relying host.

mod support;

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use konklav_authz::{Decision, DenyReason, StepUp};
use konklav_axum::{
    CurrentToken, Denied, IdentityToken, Konklav, OptionalToken, Policy, PolicyError,
    ResolvedScope, RoutePolicy, RoutePolicyError, RouterPolicy, TenantToken, path_param,
};
use konklav_core::TenantId;
use konklav_relying_client::Error;
use konklav_token::TokenKind;
use serde_json::json;
use support::{FakeHost, OTHER_TENANT, SUBJECT, TENANT, bearer, get as request, send};

fn app(konklav: &Konklav, routes: Router) -> Router {
    routes.layer(konklav.layer())
}

fn konklav(host: &Arc<FakeHost>) -> Konklav {
    Konklav::builder(host.clone()).build().unwrap()
}

fn strings(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

async fn ok() -> &'static str {
    "ok"
}

// r[verify item.axum.route-policy]
// r[verify item.axum.single-decision]
// r[verify item.axum.relying-host]
// r[verify item.axum.configuration]
#[tokio::test]
async fn router_policies_merge_outermost_first_into_one_decision() {
    let host = FakeHost::allowing();
    let api = RouterPolicy::new(
        Policy::new()
            .tenant_actions(["project:read"])
            .token_kinds([TokenKind::Identity, TokenKind::Tenant]),
    );
    let projects = api.nest(Policy::new().scope_actions("project", ["document:read"]));
    let route = projects
        .route(
            &Policy::new()
                .tenant_actions(["project:write"])
                .token_kinds([TokenKind::Tenant])
                .admit_flags(["personal_only"]),
        )
        .unwrap();
    let app = app(
        &konklav(&host),
        Router::new().route("/projects/{project}", get(ok).route_layer(route)),
    );
    let answer = send(
        &app,
        request("/projects/p-1", &[("authorization", &bearer("tenant"))]),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(host.accepted().len(), 1, "accepted once");
    let decided = host.decided();
    assert_eq!(decided.len(), 1, "decided once");
    let requirements = &decided[0];
    assert_eq!(
        requirements.tenant,
        strings(&["project:read", "project:write"])
    );
    assert_eq!(
        requirements.token_kinds,
        Some(BTreeSet::from([TokenKind::Tenant]))
    );
    assert_eq!(requirements.admit_flags, strings(&["personal_only"]));
    assert_eq!(requirements.scopes[0].kind, "project");
    assert_eq!(requirements.scopes[0].id, "p-1", "from the path parameter");
}

// r[verify item.axum.admit-flags-operation]
// r[verify item.axum.validation]
#[test]
fn building_a_route_policy_refuses_what_its_policies_show() {
    let admitting = RouterPolicy::new(Policy::new().admit_flags(["kiosk"]));
    assert_eq!(
        admitting.route(&Policy::new()).err(),
        Some(RoutePolicyError::AdmitFlagsOutsideRoute),
        "only the route's own policy admits flags"
    );
    let nested = RouterPolicy::new(Policy::new()).nest(Policy::new().admit_flags(["kiosk"]));
    assert_eq!(
        nested.route(&Policy::new()).err(),
        Some(RoutePolicyError::AdmitFlagsOutsideRoute)
    );
    let public = RouterPolicy::new(Policy::public());
    assert_eq!(
        public.route(&Policy::new().tenant_actions(["a"])).err(),
        Some(RoutePolicyError::Policy(PolicyError::PublicMerged))
    );
    assert!(
        public
            .route(&Policy::overriding().tenant_actions(["a"]))
            .is_ok(),
        "an override replaces a public router's policy"
    );
    let identity = RouterPolicy::new(Policy::new().token_kinds([TokenKind::Identity]));
    assert_eq!(
        identity
            .route(&Policy::new().token_kinds([TokenKind::Tenant]))
            .err(),
        Some(RoutePolicyError::Policy(PolicyError::NoTokenKind))
    );
    let tier = RouterPolicy::new(Policy::new().tenant_fact("tier", [1_i64]));
    assert_eq!(
        tier.route(&Policy::new().tenant_fact("tier", [2_i64]))
            .err(),
        Some(RoutePolicyError::Policy(PolicyError::FactContradiction {
            fact: "tier".into()
        }))
    );
}

// r[verify item.axum.public]
#[tokio::test]
async fn public_routes_read_no_token() {
    let host = FakeHost::allowing();
    let within = RouterPolicy::new(Policy::new().tenant_actions(["a"]));
    let app = app(
        &konklav(&host),
        Router::new()
            .route("/health", get(ok).route_layer(RoutePolicy::public()))
            .route(
                "/login",
                get(ok).route_layer(within.route(&Policy::override_public()).unwrap()),
            ),
    );
    for path in ["/health", "/login"] {
        let answer = send(
            &app,
            request(path, &[("authorization", &bearer("invalid"))]),
        )
        .await;
        assert_eq!(answer.status, StatusCode::OK, "{path}");
    }
    assert_eq!((host.accepted().len(), host.verified().len()), (0, 0));
    assert_eq!(host.decided().len(), 0);
}

// r[verify item.axum.token-extraction]
// r[verify item.axum.verify-then-decide]
// r[verify item.axum.websockets]
#[tokio::test]
async fn tokens_come_from_the_header_the_cookie_hook_or_a_websockets_query() {
    let host = FakeHost::allowing();
    let konklav = Konklav::builder(host.clone())
        .cookie(|parts| {
            parts
                .headers
                .get("cookie")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("session="))
                .map(str::to_owned)
        })
        .build()
        .unwrap();
    let policy = RoutePolicy::new(&Policy::new()).unwrap();
    let app = app(
        &konklav,
        Router::new().route("/socket", get(ok).route_layer(policy)),
    );

    let header = send(
        &app,
        request(
            "/socket?x=1",
            &[("authorization", "DPoP tenant"), ("dpop", "proof")],
        ),
    )
    .await;
    assert_eq!(header.status, StatusCode::OK);
    let presented = host.accepted().pop().unwrap();
    assert_eq!(presented.authorization, "DPoP tenant");
    assert_eq!(presented.dpop.as_deref(), Some("proof"));
    let descriptor = presented.request.unwrap();
    assert_eq!(descriptor.method, "GET");
    assert_eq!(descriptor.url, "http://api.example/socket?x=1");

    let cookie = send(&app, request("/socket", &[("cookie", "session=tenant")])).await;
    assert_eq!(cookie.status, StatusCode::OK);
    assert_eq!(
        host.accepted().pop().unwrap().authorization,
        "Bearer tenant"
    );

    let http_query = send(&app, request("/socket?token=tenant", &[])).await;
    assert_eq!(
        http_query.status,
        StatusCode::UNAUTHORIZED,
        "not read for HTTP"
    );
    assert_eq!(http_query.body, json!({"error": {"code": "missing_token"}}));

    let upgrade = [("connection", "upgrade"), ("upgrade", "websocket")];
    let websocket = send(&app, request("/socket?token=tenant", &upgrade)).await;
    assert_eq!(websocket.status, StatusCode::OK);
    assert_eq!(
        host.accepted().pop().unwrap().authorization,
        "Bearer tenant"
    );
    let bound = [("upgrade", "websocket"), ("dpop", "proof")];
    send(&app, request("/socket?token=tenant", &bound)).await;
    assert_eq!(host.accepted().pop().unwrap().authorization, "DPoP tenant");

    let refused = send(&app, request("/socket?token=invalid", &upgrade)).await;
    assert_eq!(
        refused.status,
        StatusCode::UNAUTHORIZED,
        "a refused upgrade is answered with its status"
    );
}

#[tokio::test]
async fn proofs_are_checked_against_the_public_url() {
    let host = FakeHost::allowing();
    let konklav = Konklav::builder(host.clone())
        .public_url(|parts| format!("https://public.example{}", parts.uri.path()))
        .build()
        .unwrap();
    let app = app(
        &konklav,
        Router::new().route(
            "/things",
            axum::routing::post(ok).route_layer(RoutePolicy::new(&Policy::new()).unwrap()),
        ),
    );
    let mut post = request("/things", &[("authorization", &bearer("tenant"))]);
    *post.method_mut() = axum::http::Method::POST;
    send(&app, post).await;
    let descriptor = host.accepted().pop().unwrap().request.unwrap();
    assert_eq!(descriptor.method, "POST");
    assert_eq!(descriptor.url, "https://public.example/things");
}

fn deciding(decision: Result<Decision, Error>) -> Arc<FakeHost> {
    let decision = Mutex::new(Some(decision));
    FakeHost::deciding(move |_| decision.lock().unwrap().take().unwrap())
}

/// A token, the decision for it, and the status, body and challenge it is
/// answered with.
type Case = (
    &'static str,
    Result<Decision, Error>,
    StatusCode,
    serde_json::Value,
    Option<&'static str>,
);

// r[verify item.axum.outcomes]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn outcomes_answer_as_konklav_fastapi_does() {
    let deny = |reason| Ok(Decision::Deny { reason });
    let cases: Vec<Case> = vec![
        (
            "tenant",
            deny(DenyReason::InvalidToken),
            StatusCode::UNAUTHORIZED,
            json!({"error": {"code": "invalid_token"}}),
            Some(r#"Bearer error="invalid_token""#),
        ),
        (
            "tenant",
            deny(DenyReason::InvalidDpopProof),
            StatusCode::UNAUTHORIZED,
            json!({"error": {"code": "invalid_dpop_proof"}}),
            Some(r#"DPoP error="invalid_dpop_proof""#),
        ),
        (
            "tenant",
            deny(DenyReason::MissingActions {
                actions: strings(&["a"]),
            }),
            StatusCode::FORBIDDEN,
            json!({"error": {"code": "forbidden", "reason": {"missing_actions": {"actions": ["a"]}}}}),
            None,
        ),
        (
            "tenant",
            deny(DenyReason::NoTenant),
            StatusCode::FORBIDDEN,
            json!({"error": {"code": "forbidden", "reason": "no_tenant"}}),
            None,
        ),
        (
            "tenant",
            Ok(Decision::StepUp {
                requirement: StepUp {
                    min_methods: Some(2),
                    allowed_methods: None,
                    max_age_seconds: Some(300),
                },
            }),
            StatusCode::UNAUTHORIZED,
            json!({"error": {"code": "step_up", "requirement": {"min_methods": 2, "max_age_seconds": 300}}}),
            Some(r#"Bearer error="insufficient_user_authentication", max_age=300"#),
        ),
        (
            "tenant",
            Ok(Decision::StepUp {
                requirement: StepUp {
                    min_methods: Some(2),
                    ..StepUp::default()
                },
            }),
            StatusCode::UNAUTHORIZED,
            json!({"error": {"code": "step_up", "requirement": {"min_methods": 2}}}),
            Some(r#"Bearer error="insufficient_user_authentication""#),
        ),
        (
            "tenant",
            Err(Error::Exhausted),
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error": {"code": "konklav_unavailable"}}),
            None,
        ),
        (
            "invalid",
            Ok(Decision::allow()),
            StatusCode::UNAUTHORIZED,
            json!({"error": {"code": "invalid_token"}}),
            Some(r#"Bearer error="invalid_token""#),
        ),
        (
            "bad-proof",
            Ok(Decision::allow()),
            StatusCode::UNAUTHORIZED,
            json!({"error": {"code": "invalid_dpop_proof"}}),
            Some(r#"DPoP error="invalid_dpop_proof""#),
        ),
        (
            "unreachable",
            Ok(Decision::allow()),
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error": {"code": "konklav_unavailable"}}),
            None,
        ),
    ];
    for (token, decision, status, body, challenge) in cases {
        let host = deciding(decision);
        let app = app(
            &konklav(&host),
            Router::new().route(
                "/",
                get(ok).route_layer(RoutePolicy::new(&Policy::new()).unwrap()),
            ),
        );
        let answer = send(&app, request("/", &[("authorization", &bearer(token))])).await;
        assert_eq!(answer.status, status, "{body}");
        assert_eq!(answer.body, body);
        assert_eq!(answer.header("www-authenticate"), challenge, "{body}");
    }

    // A refused token is challenged in the scheme it came in, a missing
    // one with both.
    let host = deciding(Ok(Decision::Deny {
        reason: DenyReason::InvalidToken,
    }));
    let app = app(
        &konklav(&host),
        Router::new().route(
            "/",
            get(ok).route_layer(RoutePolicy::new(&Policy::new()).unwrap()),
        ),
    );
    let dpop = send(&app, request("/", &[("authorization", "DPoP tenant")])).await;
    assert_eq!(
        dpop.header("www-authenticate"),
        Some(r#"DPoP error="invalid_token""#)
    );
    let missing = send(&app, request("/", &[])).await;
    assert_eq!(missing.status, StatusCode::UNAUTHORIZED);
    assert_eq!(missing.header("www-authenticate"), Some("Bearer, DPoP"));
}

// r[verify item.axum.respond-with]
#[tokio::test]
async fn the_application_can_answer_denials_itself() {
    let host = deciding(Ok(Decision::Deny {
        reason: DenyReason::TokenKind,
    }));
    let konklav = Konklav::builder(host.clone())
        .respond_with(|denied: Denied| {
            (StatusCode::IM_A_TEAPOT, format!("no: {}", denied.code())).into_response()
        })
        .build()
        .unwrap();
    let app = app(
        &konklav,
        Router::new().route(
            "/",
            get(ok).route_layer(RoutePolicy::new(&Policy::new()).unwrap()),
        ),
    );
    let answer = send(&app, request("/", &[("authorization", &bearer("tenant"))])).await;
    assert_eq!(answer.status, StatusCode::IM_A_TEAPOT);
    assert_eq!(answer.body, json!("no: forbidden"));
    let missing = send(&app, request("/", &[])).await;
    assert_eq!(missing.status, StatusCode::IM_A_TEAPOT);
}

// r[verify item.axum.token-tenant]
#[tokio::test]
async fn a_route_tenant_other_than_the_tokens_is_denied_before_deciding() {
    let host = FakeHost::allowing();
    let konklav = Konklav::builder(host.clone())
        .route_tenant(|parts, _| {
            let tenant =
                path_param(parts, "tenant").and_then(|tenant| tenant.parse::<TenantId>().ok());
            async move { Ok(tenant) }
        })
        .build()
        .unwrap();
    let app = app(
        &konklav,
        Router::new()
            .route(
                "/tenants/{tenant}",
                get(ok).route_layer(RoutePolicy::new(&Policy::new()).unwrap()),
            )
            .route(
                "/elsewhere",
                get(ok).route_layer(RoutePolicy::new(&Policy::new()).unwrap()),
            ),
    );
    let token = [("authorization", bearer("tenant"))];
    let headers: Vec<(&str, &str)> = token.iter().map(|(n, v)| (*n, v.as_str())).collect();
    let other = send(&app, request(&format!("/tenants/{OTHER_TENANT}"), &headers)).await;
    assert_eq!(other.status, StatusCode::FORBIDDEN);
    assert_eq!(
        other.body,
        json!({"error": {"code": "forbidden", "reason": "token_tenant"}})
    );
    assert_eq!(host.decided().len(), 0, "denied before deciding");
    let own = send(&app, request(&format!("/tenants/{TENANT}"), &headers)).await;
    assert_eq!(own.status, StatusCode::OK);
    let none = send(&app, request("/elsewhere", &headers)).await;
    assert_eq!(
        none.status,
        StatusCode::OK,
        "no route tenant, nothing to compare"
    );
}

// r[verify item.axum.scope-resolvers]
#[tokio::test]
async fn scope_resolvers_name_ids_kinds_and_owner_tenants() {
    let host = FakeHost::allowing();
    let owner: TenantId = OTHER_TENANT.parse().unwrap();
    let konklav = Konklav::builder(host.clone())
        .scope_resolver("document", move |parts, token| {
            let document = path_param(parts, "document").unwrap_or_default().to_owned();
            let subject = token.sub;
            async move {
                assert_eq!(subject.to_string(), SUBJECT, "given the verified token");
                Ok(ResolvedScope::new(document)
                    .of_kind("personal_document")
                    .owned_by(owner))
            }
        })
        .build()
        .unwrap();
    let policy = Policy::new()
        .scope_actions("document", ["document:read"])
        .scope_actions("project", ["project:read"]);
    let app = app(
        &konklav,
        Router::new()
            .route(
                "/projects/{project}/documents/{document}",
                get(ok).route_layer(RoutePolicy::new(&policy).unwrap()),
            )
            .route(
                "/documents/{document}",
                get(ok).route_layer(RoutePolicy::new(&policy).unwrap()),
            ),
    );
    let answer = send(
        &app,
        request(
            "/projects/p-1/documents/d-1",
            &[("authorization", &bearer("tenant"))],
        ),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK);
    let scopes = &host.decided()[0].scopes;
    let document = scopes.iter().find(|scope| scope.id == "d-1").unwrap();
    assert_eq!(document.kind, "personal_document");
    assert_eq!(document.tenant, Some(owner));
    let project = scopes.iter().find(|scope| scope.id == "p-1").unwrap();
    assert_eq!((project.kind.as_str(), project.tenant), ("project", None));

    // r[verify item.axum.misconfiguration]
    let unresolved = send(
        &app,
        request("/documents/d-1", &[("authorization", &bearer("tenant"))]),
    )
    .await;
    assert_eq!(
        unresolved.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "no `project` resolver or path parameter"
    );
    assert_eq!(host.accepted().len(), 1, "refused before reading the token");
}

// r[verify item.axum.hooks]
// r[verify item.axum.verify-then-decide]
#[tokio::test]
async fn hooks_run_in_order_on_verified_tokens_before_deciding_and_can_refuse() {
    let host = FakeHost::allowing();
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let (first, second, resolver) = (seen.clone(), seen.clone(), seen.clone());
    let konklav = Konklav::builder(host.clone())
        .on_verified(move |_, token| {
            first.lock().unwrap().push(format!("first {}", token.sub));
            async { Ok(()) }
        })
        .on_verified(move |parts, _| {
            second.lock().unwrap().push("second".into());
            let refuse = parts.headers.contains_key("x-refuse");
            async move {
                if refuse {
                    Err(StatusCode::PAYMENT_REQUIRED.into_response())
                } else {
                    Ok(())
                }
            }
        })
        .scope_resolver("project", move |_, _| {
            resolver.lock().unwrap().push("resolver".into());
            async { Ok(ResolvedScope::new("p-1")) }
        })
        .build()
        .unwrap();
    let app = app(
        &konklav,
        Router::new().route(
            "/",
            get(ok).route_layer(
                RoutePolicy::new(&Policy::new().scope_actions("project", ["read"])).unwrap(),
            ),
        ),
    );
    let answer = send(&app, request("/", &[("authorization", &bearer("tenant"))])).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(
        *seen.lock().unwrap(),
        [
            format!("first {SUBJECT}"),
            "second".into(),
            "resolver".into()
        ]
    );
    seen.lock().unwrap().clear();

    let refused = send(
        &app,
        request(
            "/",
            &[("authorization", &bearer("tenant")), ("x-refuse", "1")],
        ),
    )
    .await;
    assert_eq!(refused.status, StatusCode::PAYMENT_REQUIRED);
    assert_eq!(
        *seen.lock().unwrap(),
        [format!("first {SUBJECT}"), "second".to_owned()]
    );
    assert_eq!(host.decided().len(), 1, "a refused token isn't decided for");

    let invalid = send(&app, request("/", &[("authorization", &bearer("invalid"))])).await;
    assert_eq!(invalid.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        seen.lock().unwrap().len(),
        2,
        "hooks never see unverified claims"
    );
}

async fn kinds(current: CurrentToken, optional: OptionalToken) -> String {
    format!(
        "{} {}",
        serde_json::to_value(current.knd).unwrap(),
        optional.is_some()
    )
}

async fn identity(token: IdentityToken) -> String {
    token.sub.to_string()
}

async fn tenant(token: TenantToken) -> String {
    token.tid.unwrap().to_string()
}

async fn optional(token: OptionalToken) -> String {
    token
        .0
        .map_or_else(|| "anonymous".to_owned(), |token| token.sub.to_string())
}

// r[verify item.axum.injected-tokens]
#[tokio::test]
async fn extractors_inject_the_verified_token() {
    let host = FakeHost::allowing();
    let hooked = Arc::new(Mutex::new(0));
    let counter = hooked.clone();
    let konklav = Konklav::builder(host.clone())
        .on_verified(move |_, _| {
            *counter.lock().unwrap() += 1;
            async { Ok(()) }
        })
        .build()
        .unwrap();
    let any = Policy::new().token_kinds([TokenKind::Identity, TokenKind::Tenant]);
    let app = app(
        &konklav,
        Router::new()
            .route(
                "/any",
                get(kinds).route_layer(RoutePolicy::new(&any).unwrap()),
            )
            .route(
                "/identity",
                get(identity).route_layer(
                    RoutePolicy::new(&Policy::new().token_kinds([TokenKind::Identity])).unwrap(),
                ),
            )
            .route(
                "/tenant",
                get(tenant).route_layer(RoutePolicy::new(&Policy::new()).unwrap()),
            )
            .route("/public", get(optional).route_layer(RoutePolicy::public())),
    );
    let as_identity = [("authorization", "Bearer identity")];
    let as_tenant = [("authorization", "Bearer tenant")];
    assert_eq!(
        send(&app, request("/any", &as_identity)).await.body,
        json!("\"identity\" true")
    );
    assert_eq!(
        send(&app, request("/identity", &as_identity)).await.body,
        json!(SUBJECT)
    );
    assert_eq!(
        send(&app, request("/tenant", &as_tenant)).await.body,
        json!(TENANT)
    );
    assert_eq!(*hooked.lock().unwrap(), 3);

    assert_eq!(
        send(&app, request("/public", &[])).await.body,
        json!("anonymous")
    );
    assert!(
        host.verified().is_empty(),
        "nothing presented, nothing verified"
    );
    assert_eq!(
        send(&app, request("/public", &as_tenant)).await.body,
        json!(SUBJECT)
    );
    assert_eq!(host.verified().len(), 1, "verified, without a decision");
    assert_eq!(
        *hooked.lock().unwrap(),
        4,
        "hooks run on public routes' tokens too"
    );
    let invalid = send(
        &app,
        request("/public", &[("authorization", "Bearer invalid")]),
    )
    .await;
    assert_eq!(invalid.status, StatusCode::UNAUTHORIZED);
    assert_eq!(host.decided().len(), 3, "public routes decide nothing");
}

// r[verify item.axum.injected-kinds]
// r[verify item.axum.misconfiguration]
#[tokio::test]
async fn extractors_that_dont_match_their_routes_policy_fail_closed() {
    let host = FakeHost::allowing();
    let either = Policy::new().token_kinds([TokenKind::Identity, TokenKind::Tenant]);
    let app = app(
        &konklav(&host),
        Router::new()
            .route(
                "/either",
                get(tenant).route_layer(RoutePolicy::new(&either).unwrap()),
            )
            .route(
                "/default",
                get(identity).route_layer(RoutePolicy::new(&Policy::new()).unwrap()),
            )
            .route("/public", get(tenant).route_layer(RoutePolicy::public()))
            .route("/bare", get(tenant)),
    );
    for path in ["/either", "/default", "/public", "/bare"] {
        let answer = send(&app, request(path, &[("authorization", "Bearer tenant")])).await;
        assert_eq!(answer.status, StatusCode::INTERNAL_SERVER_ERROR, "{path}");
        assert_eq!(
            answer.body,
            json!({"error": {"code": "route_policy_error"}})
        );
    }
}

// r[verify item.axum.misconfiguration]
// r[verify item.axum.single-decision]
#[tokio::test]
async fn routes_set_up_wrongly_fail_closed() {
    let host = FakeHost::allowing();
    let policy = RoutePolicy::new(&Policy::new()).unwrap();
    let uninstalled = Router::new().route("/", get(ok).route_layer(policy.clone()));
    let answer = send(
        &uninstalled,
        request("/", &[("authorization", "Bearer tenant")]),
    )
    .await;
    assert_eq!(
        answer.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "no Konklav installed"
    );

    let twice = app(
        &konklav(&host),
        Router::new()
            .route("/", get(ok).route_layer(policy.clone()))
            .route_layer(policy),
    );
    let answer = send(&twice, request("/", &[("authorization", "Bearer tenant")])).await;
    assert_eq!(
        answer.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "two RoutePolicys"
    );
    assert_eq!(host.decided().len(), 1, "never decided twice");
}

// r[verify item.axum.describe]
#[test]
fn route_policies_describe_themselves_as_konklav_fastapi_publishes_them() {
    assert_eq!(RoutePolicy::public().describe(), json!({"public": true}));
    let route = RouterPolicy::new(Policy::new().tenant_actions(["project:read"]))
        .route(
            &Policy::new()
                .scope_actions("project", ["document:read"])
                .admit_flags(["personal_only"]),
        )
        .unwrap();
    assert_eq!(
        route.describe(),
        json!({
            "public": false,
            "tenant": ["project:read"],
            "scopes": [{"kind": "project", "actions": ["document:read"]}],
            "admit_flags": ["personal_only"],
        })
    );
}
