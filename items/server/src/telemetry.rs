//! Telemetry for operators: logs to stderr, and traces, metrics and logs
//! exported over OTLP when configured.

mod export;
pub mod http;
mod logs;
pub mod metrics;

pub use export::{InitError, Telemetry, init};
