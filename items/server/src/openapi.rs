//! The `OpenAPI` document for the control-plane surface.

use utoipa::openapi::extensions::ExtensionsBuilder;
use utoipa::openapi::path::{Operation, PathItem};
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::openapi::{ContentBuilder, Ref, ResponseBuilder};
use utoipa::{Modify, OpenApi};
use utoipa_axum::router::OpenApiRouter;

use crate::{AppState, control_api};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Konklav control plane",
        description = "Every operation's `x-konklav-capability` names the capability its caller needs. The bootstrap token and `konklav:control:all` hold them all. A batch (`POST /v1/batch`) needs none of its own: each of its operations needs the capability it needs alone.",
    ),
    components(schemas(konklav_api::ErrorResponse)),
    security(("bearer" = [])),
)]
struct ControlPlaneDoc;

/// Adds what every control-plane operation shares: bearer authentication
/// and the error envelope as the default response.
struct ControlPlane;

impl Modify for ControlPlane {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer",
            SecurityScheme::Http(HttpBuilder::new().scheme(HttpAuthScheme::Bearer).build()),
        );
        let error = ResponseBuilder::new()
            .description("An error; branch on `error.code`")
            .content(
                "application/json",
                ContentBuilder::new()
                    .schema(Some(Ref::from_schema_name("ErrorResponse")))
                    .build(),
            )
            .build();
        for operation in openapi.paths.paths.values_mut().flat_map(operations) {
            operation
                .responses
                .responses
                .insert("default".into(), error.clone().into());
        }
    }
}

/// Every operation on a path.
fn operations(item: &mut PathItem) -> impl Iterator<Item = &mut Operation> {
    [
        &mut item.get,
        &mut item.put,
        &mut item.post,
        &mut item.delete,
        &mut item.patch,
    ]
    .into_iter()
    .flatten()
}

/// Records on each of a group's operations the capability its guard
/// requires, as `x-konklav-capability`.
// r[impl item.api.capabilities]
fn requires(mut group: OpenApiRouter<AppState>, capability: &str) -> OpenApiRouter<AppState> {
    for operation in group
        .get_openapi_mut()
        .paths
        .paths
        .values_mut()
        .flat_map(operations)
    {
        let extension = ExtensionsBuilder::new()
            .add("x-konklav-capability", capability)
            .build();
        operation
            .extensions
            .get_or_insert_with(Default::default)
            .merge(extension);
    }
    group
}

/// The control-plane surface's `OpenAPI` document, as pretty-printed JSON.
///
/// # Panics
///
/// Never: the document is built from types that always serialize.
// r[impl item.api.document]
#[must_use]
pub fn control_plane() -> String {
    let mut openapi = control_api::groups()
        .into_iter()
        .fold(
            OpenApiRouter::with_openapi(ControlPlaneDoc::openapi()),
            |doc, (group, capability)| doc.nest("/v1", requires(group, capability)),
        )
        // Any operator may send a batch; each operation needs its own.
        .nest("/v1", crate::batch_api::batch())
        .into_openapi();
    ControlPlane.modify(&mut openapi);
    openapi.to_pretty_json().expect("the document serializes")
}

#[cfg(test)]
mod tests {
    const COMMITTED: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/openapi/control-plane.json");

    /// The committed document matches the code. Rerun with
    /// `KONKLAV_UPDATE_OPENAPI=1` to rewrite it after an API change.
    // r[verify item.api.document]
    // r[verify item.api.schemas]
    #[test]
    fn committed_document_is_current() {
        let generated = super::control_plane() + "\n";
        if std::env::var_os("KONKLAV_UPDATE_OPENAPI").is_some() {
            std::fs::write(COMMITTED, &generated).expect("writes the document");
            return;
        }
        let committed = std::fs::read_to_string(COMMITTED).unwrap_or_default();
        assert!(
            committed == generated,
            "{COMMITTED} is stale; rerun with KONKLAV_UPDATE_OPENAPI=1"
        );
    }

    /// Every operation names the capability its guard requires.
    // r[verify item.api.capabilities]
    #[test]
    fn every_operation_names_its_capability() {
        let document: serde_json::Value =
            serde_json::from_str(&super::control_plane()).expect("the document is JSON");
        let guarded: std::collections::BTreeSet<&str> = crate::control_api::groups()
            .iter()
            .map(|(_, capability)| *capability)
            .collect();
        for (path, item) in document["paths"].as_object().expect("paths") {
            for (method, operation) in item.as_object().expect("operations") {
                let capability = operation["x-konklav-capability"].as_str();
                if path == "/v1/batch" {
                    assert_eq!(capability, None, "a batch needs only an operator");
                    continue;
                }
                assert!(
                    capability.is_some_and(|capability| guarded.contains(capability)),
                    "{method} {path} names no guarding capability"
                );
            }
        }
        let sessions = &document["paths"]["/v1/sessions"]["get"]["x-konklav-capability"];
        assert_eq!(sessions, crate::capabilities::SESSIONS);
    }
}
