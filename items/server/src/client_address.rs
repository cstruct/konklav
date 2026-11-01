//! The address of the client behind a request, for rate limiting.
//!
//! The socket's peer is the client unless it is a configured trusted proxy.
//! Then the client is the last address in `X-Forwarded-For` that isn't a
//! trusted proxy too, so a client can't hide behind a header it wrote
//! itself: proxies append, and everything before the last untrusted hop
//! is the client's own claim.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::HeaderMap;
use axum::http::request::Parts;

use crate::AppState;

/// The client's address, if the request came over a socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ClientAddress(pub Option<IpAddr>);

impl ClientAddress {
    /// The address as stored with login attempts.
    pub(crate) fn key(self) -> Option<String> {
        self.0.map(|address| address.to_string())
    }
}

impl FromRequestParts<AppState> for ClientAddress {
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0.ip());
        let address = peer.map(|peer| resolve(peer, &parts.headers, &state.auth.trusted_proxies));
        std::future::ready(Ok(Self(address)))
    }
}

// r[impl platform.server.client-address]
fn resolve(peer: IpAddr, headers: &HeaderMap, trusted: &[IpAddr]) -> IpAddr {
    let trusted = |address: &IpAddr| trusted.contains(&address.to_canonical());
    if !trusted(&peer) {
        return peer;
    }
    let forwarded: Vec<IpAddr> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|hop| hop.trim().parse().ok())
        .collect();
    forwarded
        .iter()
        .rev()
        .find(|hop| !trusted(hop))
        .or(forwarded.first())
        .copied()
        .unwrap_or(peer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(forwarded: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", forwarded.parse().unwrap());
        headers
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn an_untrusted_peer_is_the_client_whatever_it_claims() {
        let resolved = resolve(ip("203.0.113.9"), &headers("198.51.100.1"), &[]);
        assert_eq!(resolved, ip("203.0.113.9"));
    }

    #[test]
    fn a_trusted_proxy_names_the_last_untrusted_hop() {
        let proxy = ip("10.0.0.1");
        let resolved = resolve(
            proxy,
            &headers("1.2.3.4, 203.0.113.9, 10.0.0.2"),
            &[proxy, ip("10.0.0.2")],
        );
        assert_eq!(resolved, ip("203.0.113.9"), "1.2.3.4 is the client's claim");
    }

    #[test]
    fn a_trusted_proxy_without_a_header_is_the_client() {
        let proxy = ip("10.0.0.1");
        assert_eq!(resolve(proxy, &HeaderMap::new(), &[proxy]), proxy);
    }
}
