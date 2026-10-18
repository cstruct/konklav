//! Pieces every page uses.

use leptos::prelude::*;
use serde_json::Value;

use super::console::use_console;
use crate::api::ApiError;
use crate::grants::{CONTROL_ALL, Capability};

pub type Loaded<T> = LocalResource<Result<T, ApiError>>;

/// A form-input problem, reported like a refusal from Conclave.
pub fn invalid_input(message: impl Into<String>) -> ApiError {
    ApiError::Api {
        status: 0,
        code: "INVALID_INPUT".to_owned(),
        message: message.into(),
    }
}

/// Parses a JSON text field, treating a blank field as `{}`.
pub fn parse_json(text: &str, what: &str) -> Result<Value, ApiError> {
    if text.trim().is_empty() {
        return Ok(Value::Object(serde_json::Map::new()));
    }
    serde_json::from_str(text).map_err(|error| invalid_input(format!("{what}: {error}")))
}

#[must_use]
pub fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_default()
}

/// An RFC 3339 timestamp to the minute, in UTC.
///
/// ```
/// use conclave_console::ui::common::timestamp;
/// assert_eq!(timestamp("2026-10-18T02:12:48.831317Z"), "2026-10-18 02:12");
/// assert_eq!(timestamp("soon"), "soon");
/// ```
#[must_use]
pub fn timestamp(value: &str) -> String {
    match value.get(..16) {
        Some(minute) if value.as_bytes().get(10) == Some(&b'T') => minute.replacen('T', " ", 1),
        _ => value.to_owned(),
    }
}

/// The start of an identifier, which is usually enough to tell it apart.
///
/// ```
/// use conclave_console::ui::common::short;
/// assert_eq!(short("0193a2f1-0000-7fff-bfff-ffffffffffff"), "0193a2f1…");
/// assert_eq!(short("root"), "root");
/// ```
#[must_use]
pub fn short(id: &str) -> String {
    match id.get(..8) {
        Some(start) if id.len() > 12 => format!("{start}…"),
        _ => id.to_owned(),
    }
}

/// Asks the operator to confirm a destructive action.
pub fn confirm(message: &str) -> bool {
    window().confirm_with_message(message).unwrap_or(false)
}

#[component]
pub fn Id(#[prop(into)] id: String) -> impl IntoView {
    view! { <code class="id" title=id.clone()>{short(&id)}</code> }
}

#[component]
pub fn Loading() -> impl IntoView {
    view! { <p class="muted">"Loading…"</p> }
}

/// Explains a capability the operator lacks.
// r[impl item.console.capability-gating]
#[component]
pub fn Denied(#[prop(into)] capability: String) -> impl IntoView {
    view! {
        <div class="notice denied" role="note">
            <strong>"Not available to you. "</strong>
            "This needs " <code>{capability}</code> " or " <code>{CONTROL_ALL}</code>
            ", granted through a global role. An operator who manages authorization can assign one."
        </div>
    }
}

/// Shows a failed call; refusals for a missing capability say which.
#[component]
pub fn Failure(error: ApiError) -> impl IntoView {
    match error.missing_capability() {
        Some(capability) => view! { <Denied capability=capability.to_owned()/> }.into_any(),
        None => {
            view! { <div class="notice error" role="alert">{error.to_string()}</div> }.into_any()
        }
    }
}

/// The latest failure of a form's action, if any.
#[component]
pub fn Problem(error: RwSignal<Option<ApiError>>) -> impl IntoView {
    move || error.get().map(|error| view! { <Failure error/> })
}

/// Renders `children` only if the operator holds `capability`, and says
/// what's missing otherwise.
#[component]
pub fn Gated(capability: Capability, children: ChildrenFn) -> impl IntoView {
    let console = use_console();
    move || {
        if console.allows(capability) {
            children().into_any()
        } else {
            view! { <Denied capability=capability.action()/> }.into_any()
        }
    }
}

/// A secret Conclave shows only once.
#[component]
pub fn Secret(#[prop(into)] label: String, #[prop(into)] value: String) -> impl IntoView {
    view! {
        <div class="notice secret">
            <strong>{label}</strong>
            " is shown only now. Copy it somewhere safe."
            <pre class="secret-value">{value}</pre>
        </div>
    }
}

/// Renders a resource: loading, its failure, or `render` of its value.
pub fn loaded<T, V>(
    resource: Loaded<T>,
    render: impl Fn(T) -> V + Send + Sync + 'static,
) -> impl IntoView
where
    T: Clone + 'static,
    V: IntoView + 'static,
{
    move || match resource.get() {
        None => view! { <Loading/> }.into_any(),
        Some(Err(error)) => view! { <Failure error/> }.into_any(),
        Some(Ok(value)) => render(value).into_any(),
    }
}

/// A labelled text input bound to `value`.
#[component]
pub fn Field(
    #[prop(into)] label: String,
    value: RwSignal<String>,
    #[prop(optional, into)] placeholder: String,
    #[prop(optional, into)] kind: Option<String>,
) -> impl IntoView {
    view! {
        <label class="field">
            <span>{label}</span>
            <input
                type=kind.unwrap_or_else(|| "text".to_owned())
                placeholder=placeholder
                bind:value=value
            />
        </label>
    }
}

/// A labelled JSON text area bound to `value`.
#[component]
pub fn JsonField(
    #[prop(into)] label: String,
    value: RwSignal<String>,
    #[prop(default = 6)] rows: u32,
) -> impl IntoView {
    view! {
        <label class="field wide">
            <span>{label}</span>
            <textarea class="json" rows=rows spellcheck="false" bind:value=value></textarea>
        </label>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blank_json_fields_are_empty_objects() {
        assert_eq!(parse_json("  ", "facts").unwrap(), serde_json::json!({}));
        assert_eq!(
            parse_json("{", "facts").unwrap_err().code(),
            Some("INVALID_INPUT")
        );
    }
}
