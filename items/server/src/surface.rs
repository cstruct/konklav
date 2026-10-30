//! The three HTTP surfaces and how they are grouped onto listeners.

use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::middleware;
use axum::routing::get;

use crate::config::Listen;
use crate::{
    AppState, capabilities, control_api, control_authz, error, federation_api, feed, flows, health,
    import_api, invites, keys, oidc_api, oidc_clients_api, passkeys_api, relying_api, subject_api,
    telemetry,
};

/// One of Konklav's groups of endpoints.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Surface {
    /// Login and session flows used by people and software.
    Subject,
    /// Keys, entitlements, checks and events for relying systems.
    Relying,
    /// Administration of the Konklav control plane.
    Control,
}

impl Surface {
    pub const ALL: [Self; 3] = [Self::Subject, Self::Relying, Self::Control];

    /// The surface's versioned endpoints, relative to `/v1`. Surfaces that
    /// share a listener are merged, so their paths must not overlap.
    fn v1_routes(self, state: &AppState) -> Router<AppState> {
        match self {
            Self::Subject => subject_api::routes(state)
                .merge(federation_api::routes())
                .merge(oidc_api::routes())
                .merge(flows::routes(state))
                .merge(passkeys_api::routes(state))
                .merge(invites::subject_routes(state))
                .merge(capabilities::routes()),
            Self::Relying => relying_api::routes().merge(feed::routes()),
            Self::Control => control_api::routes(state)
                .merge(control_authz::routes(state))
                .merge(invites::control_routes(state))
                .merge(import_api::routes(state))
                .merge(oidc_clients_api::routes(state)),
        }
    }

    /// Unversioned endpoints at fixed, well-known paths.
    fn root_routes(self) -> Router<AppState> {
        match self {
            Self::Subject => Router::new().route(
                "/.well-known/openid-configuration",
                get(oidc_api::discovery),
            ),
            Self::Relying | Self::Control => Router::new(),
        }
    }
}

impl fmt::Display for Surface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Subject => "subject",
            Self::Relying => "relying",
            Self::Control => "control",
        })
    }
}

/// Builds the router for a listener that serves `surfaces`.
// r[impl platform.server.versioned-paths]
pub fn router(surfaces: &[Surface], state: AppState) -> Router {
    let v1 = surfaces.iter().fold(Router::new(), |router, surface| {
        router.merge(surface.v1_routes(&state))
    });
    let mut root = surfaces.iter().fold(Router::new(), |router, surface| {
        router.merge(surface.root_routes())
    });
    // Relying systems verify access tokens with it, and OpenID clients,
    // which know only the issuer, ID tokens. Once per listener, since
    // surfaces sharing one are merged.
    // r[impl oidc.provider.jwks]
    if surfaces
        .iter()
        .any(|s| matches!(s, Surface::Relying | Surface::Subject))
    {
        root = root.route("/.well-known/jwks.json", get(keys::jwks));
    }
    let names: Arc<str> = surfaces
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
        .into();
    root.route("/healthz", get(health::healthz))
        .route("/readyz", get(health::readyz))
        .nest("/v1", v1)
        .fallback(error::not_found)
        .method_not_allowed_fallback(error::method_not_allowed)
        .layer(middleware::from_fn_with_state(
            names,
            telemetry::http::serve,
        ))
        .with_state(state)
}

/// Groups surfaces by listen address. Port 0 asks the OS for a free port,
/// so surfaces on port 0 always get a listener of their own.
// r[impl platform.server.surface-separation]
#[must_use]
pub fn listeners(listen: &Listen) -> Vec<(SocketAddr, Vec<Surface>)> {
    let mut shared: BTreeMap<SocketAddr, Vec<Surface>> = BTreeMap::new();
    let mut own = Vec::new();
    for surface in Surface::ALL {
        let addr = match surface {
            Surface::Subject => listen.subject,
            Surface::Relying => listen.relying,
            Surface::Control => listen.control,
        };
        if addr.port() == 0 {
            own.push((addr, vec![surface]));
        } else {
            shared.entry(addr).or_default().push(surface);
        }
    }
    shared.into_iter().chain(own).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listen(subject: &str, relying: &str, control: &str) -> Listen {
        Listen {
            subject: subject.parse().unwrap(),
            relying: relying.parse().unwrap(),
            control: control.parse().unwrap(),
            trusted_proxies: Vec::new(),
        }
    }

    // r[verify platform.server.surface-separation]
    #[test]
    fn distinct_addresses_get_distinct_listeners() {
        let groups = listeners(&listen("127.0.0.1:1", "127.0.0.1:2", "127.0.0.1:3"));
        assert_eq!(
            groups.iter().map(|(_, s)| s.clone()).collect::<Vec<_>>(),
            vec![
                vec![Surface::Subject],
                vec![Surface::Relying],
                vec![Surface::Control]
            ]
        );
    }

    #[test]
    fn shared_addresses_share_a_listener() {
        let groups = listeners(&listen("127.0.0.1:1", "127.0.0.1:1", "127.0.0.1:3"));
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].1, vec![Surface::Subject, Surface::Relying]);
        assert_eq!(groups[1].1, vec![Surface::Control]);
    }

    #[test]
    fn port_zero_is_never_shared() {
        let groups = listeners(&listen("127.0.0.1:0", "127.0.0.1:0", "127.0.0.1:0"));
        assert_eq!(groups.len(), 3);
    }
}
