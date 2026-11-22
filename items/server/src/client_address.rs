//! The address of the client behind a request, for rate limiting.
//!
//! The socket's peer is the client unless it is a configured trusted proxy.
//! Then the client is the last address in `X-Forwarded-For` that isn't a
//! trusted proxy too, so a client can't hide behind a header it wrote
//! itself: proxies append, and everything before the last untrusted hop
//! is the client's own claim. A hop that isn't an address ends the walk
//! for the same reason: what lies before it can't be vouched for.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::HeaderMap;
use axum::http::request::Parts;

use crate::AppState;

/// The client's address, if the request came over a socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ClientAddress(pub Option<IpAddr>);

impl ClientAddress {
    /// The address as stored with login attempts and counted by the
    /// per-address limits. An IPv6 address is keyed by its /64 prefix,
    /// since whoever holds one address there usually holds them all, and
    /// an IPv4-mapped one as the IPv4 address it maps.
    // r[impl authn.login.rate-limit]
    pub(crate) fn key(self) -> Option<String> {
        self.0.map(|address| match address.to_canonical() {
            IpAddr::V4(address) => address.to_string(),
            IpAddr::V6(address) => {
                let prefix = u128::from(address) & !u128::from(u64::MAX);
                format!("{}/64", Ipv6Addr::from(prefix))
            }
        })
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
    // Header values that aren't text are kept as hops that don't parse.
    let hops: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .flat_map(|value| value.to_str().unwrap_or("").split(','))
        .collect();
    // From the peer backwards, each trusted proxy vouches for the hop
    // before it. The walk ends at the first hop that isn't trusted, which
    // is the client, or that isn't an address, such as `ip:port`: skipping
    // that one would hand the choice to a hop the client wrote. Then the
    // client is the nearest proxy that was vouched for.
    let mut client = peer;
    for hop in hops.iter().rev() {
        let Ok(hop) = hop.trim().parse::<IpAddr>() else {
            break;
        };
        client = hop;
        if !trusted(&hop) {
            break;
        }
    }
    client
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

    // r[verify platform.server.client-address]
    #[test]
    fn a_hop_that_is_not_an_address_ends_the_walk() {
        let (proxy, inner) = (ip("10.0.0.1"), ip("10.0.0.2"));
        // The proxy appended `ip:port`; 1.2.3.4 is the client's claim.
        let resolved = resolve(proxy, &headers("1.2.3.4, 203.0.113.9:4711"), &[proxy]);
        assert_eq!(resolved, proxy, "nothing vouched for is left but the peer");
        let resolved = resolve(
            proxy,
            &headers("1.2.3.4, 203.0.113.9:4711, 10.0.0.2"),
            &[proxy, inner],
        );
        assert_eq!(resolved, inner, "the last hop a trusted proxy vouched for");
        let resolved = resolve(proxy, &headers("1.2.3.4, unknown"), &[proxy]);
        assert_eq!(resolved, proxy);
    }

    #[test]
    fn a_later_header_line_is_nearer_than_an_earlier_one() {
        let proxy = ip("10.0.0.1");
        let mut headers = headers("1.2.3.4");
        headers.append("x-forwarded-for", "203.0.113.9".parse().unwrap());
        assert_eq!(resolve(proxy, &headers, &[proxy]), ip("203.0.113.9"));
    }

    #[test]
    fn only_trusted_hops_fall_back_to_the_farthest_one() {
        let (proxy, inner) = (ip("10.0.0.1"), ip("10.0.0.2"));
        let resolved = resolve(proxy, &headers("10.0.0.2, 10.0.0.1"), &[proxy, inner]);
        assert_eq!(resolved, inner);
    }

    fn key(address: &str) -> String {
        ClientAddress(Some(ip(address))).key().unwrap()
    }

    // r[verify authn.login.rate-limit]
    #[test]
    fn ipv6_addresses_are_keyed_by_their_64_bit_prefix() {
        assert_eq!(key("2001:db8:1:2:3:4:5:6"), "2001:db8:1:2::/64");
        assert_eq!(key("2001:db8:1:2::1"), key("2001:db8:1:2:ffff::9"));
        assert_ne!(key("2001:db8:1:2::1"), key("2001:db8:1:3::1"));
    }

    #[test]
    fn ipv4_and_ipv4_mapped_addresses_share_a_key() {
        assert_eq!(key("203.0.113.9"), "203.0.113.9");
        assert_eq!(key("::ffff:203.0.113.9"), "203.0.113.9");
        assert_eq!(ClientAddress(None).key(), None);
    }
}
