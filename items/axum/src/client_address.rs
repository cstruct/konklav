//! The address of the client behind a request, for rate limiting.
//!
//! The socket's peer is the client unless it is a trusted proxy. Then the
//! client is the last address in `X-Forwarded-For` that isn't a trusted
//! proxy too, since proxies append and everything before the last untrusted
//! hop is the client's own claim. The Konklav server takes its own clients'
//! addresses alike (`platform.server.client-address`).

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::HeaderMap;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};

use crate::{Konklav, RoutePolicyError};

/// An address or a network in CIDR notation, such as `10.0.0.0/8`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Network {
    address: IpAddr,
    prefix: u8,
}

/// A trusted proxy that doesn't parse as an address or a network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidProxy(pub String);

impl fmt::Display for InvalidProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "trusted proxy `{}` is not an address or a network such as 10.0.0.0/8",
            self.0
        )
    }
}

impl std::error::Error for InvalidProxy {}

impl Network {
    pub(crate) fn parse(text: &str) -> Result<Self, InvalidProxy> {
        let invalid = || InvalidProxy(text.to_owned());
        let (address, prefix) = match text.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (text, None),
        };
        let address: IpAddr = address.trim().parse().map_err(|_| invalid())?;
        let bits = if address.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(prefix) => prefix.trim().parse().map_err(|_| invalid())?,
            None => bits,
        };
        if prefix > bits {
            return Err(invalid());
        }
        Ok(Self { address, prefix })
    }

    fn contains(self, address: IpAddr) -> bool {
        match (self.address, address.to_canonical()) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(network) & mask == u32::from(address) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(network) & mask == u128::from(address) & mask
            }
            _ => false,
        }
    }
}

// r[impl item.axum.client-address]
// r[depends platform.server.client-address]
pub(crate) fn resolve(peer: IpAddr, headers: &HeaderMap, trusted: &[Network]) -> IpAddr {
    let is_trusted = |address: IpAddr| trusted.iter().any(|network| network.contains(address));
    if !is_trusted(peer) {
        return peer.to_canonical();
    }
    let hops: Vec<IpAddr> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|hop| hop.trim().parse().ok())
        .collect();
    hops.iter()
        .rev()
        .find(|hop| !is_trusted(**hop))
        .or(hops.first())
        .copied()
        .unwrap_or(peer)
        .to_canonical()
}

impl Konklav {
    /// The address of the client behind the request, or `None` without a
    /// peer address (serve with
    /// `into_make_service_with_connect_info::<SocketAddr>()`). It is the
    /// peer, unless the peer is a trusted proxy.
    #[must_use]
    pub fn client_address(&self, parts: &Parts) -> Option<IpAddr> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0.ip())?;
        Some(resolve(peer, &parts.headers, &self.inner.trusted_proxies))
    }
}

/// The client's address ([`Konklav::client_address`]), as an extractor.
/// Without a peer address the request fails closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientAddress(pub IpAddr);

impl<S: Send + Sync> FromRequestParts<S> for ClientAddress {
    type Rejection = Response;

    fn from_request_parts(
        parts: &mut Parts,
        _: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let address = Konklav::of(parts)
            .map_err(IntoResponse::into_response)
            .and_then(|konklav| {
                konklav
                    .client_address(parts)
                    .map(Self)
                    .ok_or_else(|| RoutePolicyError::NoClientAddress.into_response())
            });
        std::future::ready(address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(forwarded: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in forwarded {
            headers.append("x-forwarded-for", value.parse().unwrap());
        }
        headers
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn networks(texts: &[&str]) -> Vec<Network> {
        texts
            .iter()
            .map(|text| Network::parse(text).unwrap())
            .collect()
    }

    // r[verify item.axum.client-address]
    #[test]
    fn the_peer_is_the_client_unless_it_is_a_trusted_proxy() {
        let trusted = networks(&["10.0.0.0/8", "fd00::/8"]);
        assert_eq!(
            resolve(ip("203.0.113.9"), &headers(&["198.51.100.1"]), &trusted),
            ip("203.0.113.9"),
            "an untrusted peer is the client, whatever it claims"
        );
        assert_eq!(
            resolve(
                ip("10.0.0.1"),
                &headers(&["1.2.3.4, 203.0.113.9", "10.0.0.2"]),
                &trusted
            ),
            ip("203.0.113.9"),
            "the last untrusted hop, across headers; 1.2.3.4 is the client's claim"
        );
        assert_eq!(
            resolve(ip("10.0.0.1"), &headers(&["10.0.0.3, 10.0.0.2"]), &trusted),
            ip("10.0.0.3"),
            "the first hop when every hop is trusted"
        );
        assert_eq!(
            resolve(ip("10.0.0.1"), &HeaderMap::new(), &trusted),
            ip("10.0.0.1"),
            "a trusted proxy without a header is the client"
        );
        assert_eq!(
            resolve(
                ip("::ffff:10.0.0.1"),
                &headers(&["garbage, 2001:db8::1"]),
                &trusted
            ),
            ip("2001:db8::1"),
            "IPv4-mapped peers are IPv4, and hops that don't parse are skipped"
        );
        assert_eq!(
            resolve(ip("::ffff:203.0.113.9"), &HeaderMap::new(), &[]),
            ip("203.0.113.9"),
            "without trusted proxies the peer is the client, as IPv4"
        );
    }

    #[test]
    fn networks_parse_addresses_and_cidr_and_refuse_anything_else() {
        assert!(Network::parse("10.1.2.3").unwrap().contains(ip("10.1.2.3")));
        assert!(!Network::parse("10.1.2.3").unwrap().contains(ip("10.1.2.4")));
        assert!(
            Network::parse("10.1.2.3/8")
                .unwrap()
                .contains(ip("10.200.0.1"))
        );
        assert!(Network::parse("0.0.0.0/0").unwrap().contains(ip("8.8.8.8")));
        assert!(Network::parse("::/0").unwrap().contains(ip("2001:db8::1")));
        assert!(!Network::parse("::/0").unwrap().contains(ip("8.8.8.8")));
        for invalid in ["10.0.0.0/33", "proxy", "10.0.0.0/x", "::/129", ""] {
            assert_eq!(
                Network::parse(invalid),
                Err(InvalidProxy(invalid.to_owned()))
            );
        }
    }
}
