//! Traces, metrics and logs exported over OTLP to a fake collector.
//!
//! One test in a binary of its own, since telemetry installs global
//! providers and the global tracing subscriber.

#![allow(clippy::too_many_lines)]

mod common;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::routing::post;
use common::TestApp;
use konklav_server::config::{LogFormat, Logs, MetricsExport, Otlp, Telemetry, TracesExport};
use konklav_server::telemetry;
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value::Value};
use opentelemetry_proto::tonic::metrics::v1::metric::Data;
use opentelemetry_proto::tonic::trace::v1::span::SpanKind;
use opentelemetry_proto::tonic::trace::v1::{Span, status::StatusCode as SpanStatus};
use prost::Message;
use serde_json::json;

const PASSWORD: &str = "correct horse battery";
const TRACE_ID: &str = "0af7651916cd43dd8448eb211c80319c";

#[derive(Clone, Default)]
struct Collector {
    metrics: Arc<Mutex<Vec<ExportMetricsServiceRequest>>>,
    spans: Arc<Mutex<Vec<ExportTraceServiceRequest>>>,
    logs: Arc<Mutex<Vec<ExportLogsServiceRequest>>>,
    /// The headers of requests to `/outbound`.
    outbound: Arc<Mutex<Vec<HeaderMap>>>,
    /// Every body received, to search for what must never be exported.
    raw: Arc<Mutex<Vec<u8>>>,
}

async fn start_collector() -> (SocketAddr, Collector) {
    let collector = Collector::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = axum::Router::new()
        .route(
            "/v1/metrics",
            post(|State(c): State<Collector>, body: Bytes| async move {
                c.raw.lock().unwrap().extend_from_slice(&body);
                let request = ExportMetricsServiceRequest::decode(body).unwrap();
                c.metrics.lock().unwrap().push(request);
                StatusCode::OK
            }),
        )
        .route(
            "/v1/traces",
            post(|State(c): State<Collector>, body: Bytes| async move {
                c.raw.lock().unwrap().extend_from_slice(&body);
                let request = ExportTraceServiceRequest::decode(body).unwrap();
                c.spans.lock().unwrap().push(request);
                StatusCode::OK
            }),
        )
        .route(
            "/v1/logs",
            post(|State(c): State<Collector>, body: Bytes| async move {
                c.raw.lock().unwrap().extend_from_slice(&body);
                let request = ExportLogsServiceRequest::decode(body).unwrap();
                c.logs.lock().unwrap().push(request);
                StatusCode::OK
            }),
        )
        .route(
            "/outbound",
            post(
                |State(c): State<Collector>, headers: HeaderMap| async move {
                    c.outbound.lock().unwrap().push(headers);
                    StatusCode::OK
                },
            ),
        )
        .with_state(collector.clone());
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (addr, collector)
}

fn text(value: Option<&AnyValue>) -> String {
    match value.and_then(|value| value.value.as_ref()) {
        Some(Value::StringValue(value)) => value.clone(),
        Some(Value::IntValue(value)) => value.to_string(),
        other => format!("{other:?}"),
    }
}

fn attributes(attributes: &[KeyValue]) -> HashMap<String, String> {
    attributes
        .iter()
        .map(|kv| (kv.key.clone(), text(kv.value.as_ref())))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

async fn flush(telemetry: &Arc<telemetry::Telemetry>) {
    let telemetry = telemetry.clone();
    tokio::task::spawn_blocking(move || telemetry.flush())
        .await
        .unwrap();
}

fn spans(collector: &Collector) -> Vec<Span> {
    collector
        .spans
        .lock()
        .unwrap()
        .iter()
        .flat_map(|r| &r.resource_spans)
        .flat_map(|r| &r.scope_spans)
        .flat_map(|s| s.spans.clone())
        .collect()
}

/// The attributes of each data point of metric `name`.
fn points(collector: &Collector, name: &str) -> Vec<HashMap<String, String>> {
    let requests = collector.metrics.lock().unwrap();
    let mut points = Vec::new();
    for metric in requests
        .iter()
        .flat_map(|r| &r.resource_metrics)
        .flat_map(|r| &r.scope_metrics)
        .flat_map(|s| &s.metrics)
        .filter(|m| m.name == name)
    {
        match metric.data.as_ref().unwrap() {
            Data::Sum(sum) => {
                points.extend(sum.data_points.iter().map(|p| attributes(&p.attributes)));
            }
            Data::Histogram(histogram) => {
                points.extend(
                    histogram
                        .data_points
                        .iter()
                        .map(|p| attributes(&p.attributes)),
                );
            }
            Data::Gauge(gauge) => {
                points.extend(gauge.data_points.iter().map(|p| attributes(&p.attributes)));
            }
            other => panic!("unexpected metric data {other:?}"),
        }
    }
    points
}

// r[verify telemetry.init]
// r[verify telemetry.metrics]
// r[verify telemetry.metrics.requests]
// r[verify telemetry.metrics.internals]
// r[verify telemetry.traces.requests]
// r[verify telemetry.traces.outbound]
// r[verify telemetry.logs.export]
// r[verify telemetry.privacy]
#[tokio::test(flavor = "multi_thread")]
async fn requests_are_traced_and_measured_without_identifiers() {
    let (addr, collector) = start_collector().await;
    let telemetry = Arc::new(
        telemetry::init(&Telemetry {
            service_name: "konklav-test".into(),
            resource: Vec::new(),
            otlp: Otlp {
                endpoint: Some(format!("http://{addr}")),
                ..Otlp::default()
            },
            metrics: MetricsExport {
                enabled: true,
                endpoint: None,
                interval_seconds: 3600,
            },
            traces: TracesExport {
                enabled: true,
                endpoint: None,
                sample_ratio: 1.0,
            },
            logs: Logs {
                level: "info".into(),
                format: LogFormat::Json,
                export: true,
                endpoint: None,
            },
        })
        .unwrap(),
    );
    let _pool =
        konklav_server::telemetry::metrics::observe_pool(TestApp::new().await.db.pool().clone());
    let app = TestApp::new().await;
    app.human("ada@telemetry.example", PASSWORD).await;

    // A refused login, continuing the caller's trace.
    let traceparent = format!("00-{TRACE_ID}-b7ad6b7169203331-01");
    let refused = app
        .send(
            Method::POST,
            "/v1/login/password",
            &[("traceparent", &traceparent)],
            Some(json!({"identifier": "ada@telemetry.example", "password": "wrong"})),
        )
        .await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    let login = app.login("ada@telemetry.example", PASSWORD).await;
    assert_eq!(login.status, StatusCode::OK);
    // A path with an id in it is named by its template.
    let subject = uuid::Uuid::now_v7();
    app.control(Method::GET, &format!("/v1/subjects/{subject}"), None)
        .await;

    // An outbound request in a span carries the trace.
    let http = reqwest::Client::new();
    async {
        tracing::info!(target: "konklav_server", "sending outbound");
        telemetry::http::send(
            http.post(format!("http://{addr}/outbound")),
            "test_outbound",
        )
        .await
        .unwrap();
    }
    .instrument_in("outbound_parent")
    .await;

    flush(&telemetry).await;

    // Traces.
    let spans = spans(&collector);
    let login_spans = spans
        .iter()
        .filter(|s| s.name == "POST /v1/login/password")
        .collect::<Vec<_>>();
    assert_eq!(
        login_spans.len(),
        2,
        "{:?}",
        spans.iter().map(|s| &s.name).collect::<Vec<_>>()
    );
    let continued = login_spans
        .iter()
        .find(|s| hex(&s.trace_id) == TRACE_ID)
        .expect("the refused login continues the caller's trace");
    assert_eq!(continued.kind, SpanKind::Server as i32);
    let fields = attributes(&continued.attributes);
    assert_eq!(fields["http.response.status_code"], "401");
    assert_eq!(fields["error.type"], "INVALID_CREDENTIALS");
    assert_eq!(fields["http.route"], "/v1/login/password");
    assert!(
        spans.iter().any(|s| s.name == "GET /v1/subjects/{id}"),
        "named by route template"
    );
    let outbound = spans
        .iter()
        .find(|s| s.name == "test_outbound")
        .expect("an outbound client span");
    assert_eq!(outbound.kind, SpanKind::Client as i32);
    assert_ne!(
        outbound.status.as_ref().map(|s| s.code),
        Some(SpanStatus::Error as i32)
    );
    let sent = collector.outbound.lock().unwrap()[0].clone();
    let header = sent["traceparent"].to_str().unwrap().to_owned();
    assert!(
        header.contains(&hex(&outbound.trace_id)),
        "{header} carries the outbound span's trace"
    );

    // Metrics.
    let requests = points(&collector, "http.server.request.duration");
    assert!(
        requests
            .iter()
            .any(|a| a["http.route"] == "/v1/login/password"
                && a.get("error.type").map(String::as_str) == Some("INVALID_CREDENTIALS")
                && a["http.response.status_code"] == "401"
                && a["konklav.surfaces"] == "subject,relying,control"),
        "{requests:?}"
    );
    assert_ne!(points(&collector, "konklav.hashing.wait"), Vec::new());
    assert!(
        points(&collector, "konklav.tokens.issued")
            .iter()
            .any(|a| a["konklav.token.kind"] == "identity")
    );
    assert!(
        points(&collector, "konklav.db.pool.connections")
            .iter()
            .any(|a| a["konklav.state"] == "idle")
    );
    assert!(
        points(&collector, "http.client.request.duration")
            .iter()
            .any(|a| a["konklav.operation"] == "test_outbound" && a["konklav.outcome"] == "ok")
    );

    // Logs, with the trace of the span they were logged in.
    let logs = collector.logs.lock().unwrap().clone();
    let record = logs
        .iter()
        .flat_map(|r| &r.resource_logs)
        .flat_map(|r| &r.scope_logs)
        .flat_map(|s| &s.log_records)
        .find(|r| text(r.body.as_ref()) == "sending outbound")
        .expect("the log was exported");
    assert_eq!(record.trace_id, outbound.trace_id);

    // Nothing anywhere names who signed in or with what.
    let raw = collector.raw.lock().unwrap().clone();
    let raw = String::from_utf8_lossy(&raw);
    for secret in [
        "ada@telemetry.example",
        PASSWORD,
        "wrong",
        &subject.to_string(),
    ] {
        assert!(!raw.contains(secret), "`{secret}` was exported");
    }
    telemetry.shutdown();
}

trait InSpan: std::future::Future + Sized {
    fn instrument_in(self, name: &'static str) -> tracing::instrument::Instrumented<Self> {
        tracing::Instrument::instrument(
            self, // Spans are exported for the server's target only.
            tracing::info_span!(target: "konklav_server", "parent", otel.name = name),
        )
    }
}

impl<F: std::future::Future> InSpan for F {}
