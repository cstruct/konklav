//! Spans and metrics for HTTP requests, served and sent.

use std::sync::Arc;
use std::time::Instant;

use axum::extract::{MatchedPath, Request, State};
use axum::middleware::Next;
use axum::response::Response;
use opentelemetry::{KeyValue, global};
use opentelemetry_http::{HeaderExtractor, HeaderInjector};
use tracing::Instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;

use super::metrics::{METRICS, seconds};
use crate::error::ErrorCode;

/// The route a request matched, as its template; never its path, which
/// may carry ids.
fn route(request: &Request) -> String {
    request
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "unmatched".to_owned(), |path| path.as_str().to_owned())
}

/// The stable code of an error response, from the extension `ApiError`
/// sets.
fn error_code(response: &Response) -> Option<String> {
    let code = response.extensions().get::<ErrorCode>()?;
    serde_json::to_value(code)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
}

/// Serves `request` in a server span named by its method and route
/// template, continuing the caller's trace, and records its duration.
/// `surfaces` names the surfaces of the listener it came in on.
// r[impl telemetry.traces.requests]
// r[impl telemetry.metrics.requests]
// r[impl telemetry.privacy]
pub async fn serve(State(surfaces): State<Arc<str>>, request: Request, next: Next) -> Response {
    let started = Instant::now();
    let method = request.method().as_str().to_owned();
    let route = route(&request);
    let parent = global::get_text_map_propagator(|propagator| {
        propagator.extract(&HeaderExtractor(request.headers()))
    });
    let span = tracing::info_span!(
        "request",
        otel.name = format!("{method} {route}"),
        otel.kind = "server",
        otel.status_code = tracing::field::Empty,
        http.request.method = method,
        http.route = route,
        http.response.status_code = tracing::field::Empty,
        error.r#type = tracing::field::Empty,
        konklav.surfaces = &*surfaces,
    );
    let _ = span.set_parent(parent);
    let response = next.run(request).instrument(span.clone()).await;

    let status = response.status();
    let code = error_code(&response);
    span.record("http.response.status_code", status.as_u16());
    if let Some(code) = &code {
        span.record("error.type", code.as_str());
    }
    if status.is_server_error() {
        span.record("otel.status_code", "ERROR");
    }
    let mut attributes = vec![
        KeyValue::new("http.request.method", method),
        KeyValue::new("http.route", route),
        KeyValue::new("http.response.status_code", i64::from(status.as_u16())),
        KeyValue::new("konklav.surfaces", surfaces.to_string()),
    ];
    if let Some(code) = code {
        attributes.push(KeyValue::new("error.type", code));
    }
    METRICS
        .requests
        .record(seconds(started.elapsed()), &attributes);
    response
}

/// Sends `request` in a client span named by `operation`, carrying the
/// trace in `traceparent`, and records its duration and outcome.
// r[impl telemetry.traces.outbound]
pub async fn send(
    request: reqwest::RequestBuilder,
    operation: &'static str,
) -> reqwest::Result<reqwest::Response> {
    let (client, request) = request.build_split();
    let mut request = request?;
    let span = tracing::info_span!(
        "outbound",
        otel.name = operation,
        otel.kind = "client",
        otel.status_code = tracing::field::Empty,
        http.request.method = request.method().as_str(),
        server.address = request.url().host_str().unwrap_or_default(),
        http.response.status_code = tracing::field::Empty,
    );
    global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&span.context(), &mut HeaderInjector(request.headers_mut()));
    });
    let started = Instant::now();
    let sent = client.execute(request).instrument(span.clone()).await;
    let outcome = match &sent {
        Ok(response) => {
            span.record("http.response.status_code", response.status().as_u16());
            if response.status().is_success() {
                "ok"
            } else {
                span.record("otel.status_code", "ERROR");
                "error_status"
            }
        }
        Err(_) => {
            span.record("otel.status_code", "ERROR");
            "failed"
        }
    };
    METRICS.outbound.record(
        seconds(started.elapsed()),
        &[
            KeyValue::new("konklav.operation", operation),
            KeyValue::new("konklav.outcome", outcome),
        ],
    );
    sent
}
