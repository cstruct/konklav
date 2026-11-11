use serde::{Deserialize, Serialize};

/// The metadata filter of a list without other query parameters.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct MetadataQuery {
    /// A JSON object of strings, numbers and booleans, such as
    /// `{"tenant_id":"t-1"}`: only objects whose metadata has each of its
    /// keys at the top level with an equal value.
    pub metadata: Option<String>,
}

pub(crate) fn empty_object() -> serde_json::Value {
    serde_json::json!({})
}
