//! The metrics Konklav records, with the global meter provider.
//!
//! Attributes stay low-cardinality: surfaces, route templates, methods,
//! status and error codes, kinds and outcomes. Never identifiers, ids or
//! addresses.

use std::sync::LazyLock;
use std::time::Duration;

use opentelemetry::metrics::{Counter, Histogram, Meter, ObservableGauge, UpDownCounter};
use opentelemetry::{KeyValue, global};

/// The meter the instruments are created with, from the global provider at
/// first use.
fn meter() -> Meter {
    global::meter("konklav")
}

pub struct Metrics {
    pub requests: Histogram<f64>,
    pub refused: Counter<u64>,
    pub outbound: Histogram<f64>,
    pub hashing_wait: Histogram<f64>,
    pub hashing_busy: UpDownCounter<i64>,
    pub tokens_issued: Counter<u64>,
    pub feed_streams: UpDownCounter<i64>,
    pub logout_deliveries: Counter<u64>,
    pub retention_deleted: Counter<u64>,
}

/// The instruments, created from the global meter provider at first use, so
/// telemetry must be set up before the server records anything.
// r[impl telemetry.metrics]
// r[impl telemetry.metrics.internals]
pub static METRICS: LazyLock<Metrics> = LazyLock::new(|| {
    let meter = meter();
    Metrics {
        requests: meter
            .f64_histogram("http.server.request.duration")
            .with_unit("s")
            .with_description("Duration of HTTP requests")
            .build(),
        refused: meter
            .u64_counter("konklav.http.refused")
            .with_description("Requests refused before routing, by reason")
            .build(),
        outbound: meter
            .f64_histogram("http.client.request.duration")
            .with_unit("s")
            .with_description("Duration of outbound HTTP requests, by operation and outcome")
            .build(),
        hashing_wait: meter
            .f64_histogram("konklav.hashing.wait")
            .with_unit("s")
            .with_description("Time password hashing waited for a slot")
            .build(),
        hashing_busy: meter
            .i64_up_down_counter("konklav.hashing.busy")
            .with_description("Password hashing slots in use")
            .build(),
        tokens_issued: meter
            .u64_counter("konklav.tokens.issued")
            .with_description("Access tokens issued, by kind")
            .build(),
        feed_streams: meter
            .i64_up_down_counter("konklav.feed.streams")
            .with_description("Open change-feed streams")
            .build(),
        logout_deliveries: meter
            .u64_counter("konklav.backchannel_logout.deliveries")
            .with_description("Back-channel logout deliveries, by outcome")
            .build(),
        retention_deleted: meter
            .u64_counter("konklav.retention.deleted")
            .with_description("Rows the sweeper deleted or erased, by kind")
            .build(),
    }
});

/// Reports the database pool's connections, by whether they are in use,
/// for as long as the returned gauge is kept.
#[must_use]
pub fn observe_pool(pool: konklav_store::Pool) -> ObservableGauge<i64> {
    meter()
        .i64_observable_gauge("konklav.db.pool.connections")
        .with_description("Database connections, by whether they are in use")
        .with_callback(move |observer| {
            let status = pool.status();
            let idle = i64::try_from(status.available).unwrap_or(i64::MAX);
            let size = i64::try_from(status.size).unwrap_or(i64::MAX);
            observer.observe(size - idle, &[KeyValue::new("konklav.state", "in_use")]);
            observer.observe(idle, &[KeyValue::new("konklav.state", "idle")]);
        })
        .build()
}

#[must_use]
pub fn seconds(duration: Duration) -> f64 {
    duration.as_secs_f64()
}

/// Counts one occurrence with a single attribute.
pub fn count(counter: &Counter<u64>, key: &'static str, value: &'static str) {
    counter.add(1, &[KeyValue::new(key, value)]);
}
