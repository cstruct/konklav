use serde::{Deserialize, Serialize};

/// Control-plane operations to apply in order, all or nothing.
// r[impl platform.batch.operations]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Batch {
    pub operations: Vec<BatchOperation>,
    /// Chosen by the caller, so that repeating the batch answers what it
    /// first answered instead of applying it again. Remembered per caller,
    /// for committed batches only. At most 255 characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    /// How long to remember the key, up to the server's maximum (an hour
    /// unless configured otherwise); the server's default (ten minutes)
    /// when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_seconds: Option<u32>,
}

/// One operation of a batch, as it would be sent on its own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct BatchOperation {
    pub method: BatchMethod,
    /// A control-plane path without `/v1`, such as `/subjects/{id}`, with an
    /// optional query string.
    pub path: String,
    /// The operation's request body, if it takes one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub body: Option<serde_json::Value>,
}

/// The methods a batch accepts: only writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "UPPERCASE")]
pub enum BatchMethod {
    Put,
    Post,
    Delete,
}

/// What every operation of a committed batch answered, in order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct BatchResults {
    pub results: Vec<BatchResult>,
}

/// One operation's answer, as it would have answered alone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct BatchResult {
    pub status: u16,
    /// The operation's response body, including its own `cursor`.
    #[schema(value_type = Object)]
    pub body: serde_json::Value,
}
