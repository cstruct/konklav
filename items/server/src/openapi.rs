//! The `OpenAPI` document for the control-plane surface.
//!
//! Spike: only tenants and memberships are described so far.

use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::openapi::{ContentBuilder, Ref, ResponseBuilder};
use utoipa::{Modify, OpenApi};
use utoipa_axum::router::OpenApiRouter;

use crate::control_authz;

#[derive(OpenApi)]
#[openapi(
    info(title = "Konklav control plane"),
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
        for item in openapi.paths.paths.values_mut() {
            for operation in [
                &mut item.get,
                &mut item.put,
                &mut item.post,
                &mut item.delete,
            ]
            .into_iter()
            .flatten()
            {
                operation
                    .responses
                    .responses
                    .insert("default".into(), error.clone().into());
            }
        }
    }
}

/// The control-plane surface's `OpenAPI` document, as pretty-printed JSON.
///
/// # Panics
///
/// Never: the document is built from types that always serialize.
// r[impl item.api.document]
#[must_use]
pub fn control_plane() -> String {
    let mut openapi = OpenApiRouter::with_openapi(ControlPlaneDoc::openapi())
        .nest("/v1", control_authz::tenancy())
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
}
