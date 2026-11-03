//! Checks control-plane responses against the committed API document.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex, PoisonError};

use axum::http::{Method, StatusCode};
use jsonschema::{Draft, Validator};
use serde_json::Value;

static DOCUMENT: LazyLock<Value> = LazyLock::new(|| {
    let text = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/openapi/control-plane.json"
    ));
    serde_json::from_str(text).expect("the API document is JSON")
});

/// One validator per response schema, by JSON pointer into the document.
static VALIDATORS: LazyLock<Mutex<HashMap<String, &'static Validator>>> =
    LazyLock::new(Default::default);

/// [`check`] for each result of a committed batch, against the operation
/// that produced it.
pub fn check_batch(sent: Option<&Value>, answer: &Value) {
    let operations = sent
        .and_then(|sent| sent["operations"].as_array())
        .expect("a batch sends operations");
    let results = answer["results"]
        .as_array()
        .expect("a batch answers results");
    assert_eq!(operations.len(), results.len(), "one result per operation");
    for (operation, result) in operations.iter().zip(results) {
        let method: Method = operation["method"].as_str().unwrap().parse().unwrap();
        let uri = format!("/v1{}", operation["path"].as_str().unwrap());
        let status =
            StatusCode::from_u16(u16::try_from(result["status"].as_u64().unwrap()).unwrap())
                .unwrap();
        check(&method, &uri, status, &result["body"]);
    }
}

/// Panics unless `body` matches what the API document says the operation
/// answering `method` and `uri` returns with `status`. Requests that match
/// no documented operation, such as the subject-facing surface's, pass.
// r[impl item.api.responses]
pub fn check(method: &Method, uri: &str, status: StatusCode, body: &Value) {
    let path = uri.split('?').next().unwrap_or(uri);
    let Some(template) = operation(method, path) else {
        return;
    };
    let method = method.as_str().to_ascii_lowercase();
    let responses = &DOCUMENT["paths"][template][&method]["responses"];
    let key = if responses.get(status.as_str()).is_some() {
        status.as_str()
    } else if responses.get("default").is_some() && !status.is_success() {
        "default"
    } else {
        panic!("{method} {template} answered {status}, which the API document doesn't list");
    };
    let pointer = format!(
        "/paths/{}/{method}/responses/{key}/content/application~1json/schema",
        escape(template)
    );
    if DOCUMENT.pointer(&pointer).is_none() {
        assert!(
            body.is_null(),
            "{method} {template} answered {status} with a body the API document doesn't list: {body}"
        );
        return;
    }
    let validator = validator(&pointer);
    let errors: Vec<String> = validator
        .iter_errors(body)
        .map(|error| format!("{} at {}", error, error.instance_path()))
        .collect();
    assert!(
        errors.is_empty(),
        "{method} {template} answered {status} with a body that doesn't match the API document:\n{}\n{body:#}",
        errors.join("\n")
    );
}

/// The document's path template for `path`, preferring literal segments,
/// so `/v1/sessions/revoke` matches itself rather than `/v1/sessions/{id}`.
fn operation(method: &Method, path: &str) -> Option<&'static str> {
    let method = method.as_str().to_ascii_lowercase();
    let segments: Vec<&str> = path.split('/').collect();
    DOCUMENT["paths"]
        .as_object()?
        .iter()
        .filter(|(_, item)| item.get(&method).is_some())
        .map(|(template, _)| template.as_str())
        .filter(|template| {
            let parts: Vec<&str> = template.split('/').collect();
            parts.len() == segments.len()
                && parts
                    .iter()
                    .zip(&segments)
                    .all(|(part, segment)| part.starts_with('{') || part == segment)
        })
        .min_by_key(|template| template.matches('{').count())
}

fn validator(pointer: &str) -> &'static Validator {
    let mut validators = VALIDATORS.lock().unwrap_or_else(PoisonError::into_inner);
    validators.entry(pointer.to_owned()).or_insert_with(|| {
        // The whole document is the root, so its `#/components/...`
        // references resolve; the `$ref` picks out one response schema.
        let mut root = DOCUMENT.clone();
        // A URI fragment can't hold the template's braces as they are.
        let fragment = pointer.replace('{', "%7B").replace('}', "%7D");
        root["$ref"] = Value::String(format!("#{fragment}"));
        let validator = jsonschema::options()
            .with_draft(Draft::Draft202012)
            .should_validate_formats(true)
            .build(&root)
            .unwrap_or_else(|error| panic!("{pointer} isn't a valid schema: {error}"));
        Box::leak(Box::new(validator))
    })
}

/// Escapes a path template as a JSON pointer segment.
fn escape(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}
