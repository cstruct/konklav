use konklav_core::Cursor;
use serde::{Deserialize, Serialize};

/// A write's result and the cursor of the last event it produced, if any.
// r[impl platform.idempotency.write-cursor]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Written<T> {
    #[serde(flatten)]
    pub value: T,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
}
