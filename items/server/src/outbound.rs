//! Outbound HTTP: the clients Konklav fetches with, and which URLs it may fetch.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::{Response, StatusCode, Url};
use serde::de::DeserializeOwned;

/// The largest response body Konklav reads. Discovery documents, key sets,
/// token responses, claims and peer-feed pages are a few kilobytes.
pub(crate) const BODY_LIMIT: usize = 1024 * 1024;

/// Why an answer to an outbound request wasn't used.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ResponseError {
    #[error("answered {0}")]
    Status(StatusCode),
    #[error("the answer is larger than {0} bytes")]
    TooLarge(usize),
    #[error(transparent)]
    Transport(#[from] reqwest::Error),
    #[error("the answer isn't the expected JSON: {0}")]
    Json(#[from] serde_json::Error),
}

/// Starts an HTTP client that gives up on a request after `timeout` and
/// follows no redirects, so a request and what it carries only go where
/// Konklav was told to send them.
// r[impl federation.outbound.redirects]
pub(crate) fn builder(timeout: Duration) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
}

/// An HTTP client from [`builder`].
pub(crate) fn client(timeout: Duration) -> reqwest::Result<reqwest::Client> {
    builder(timeout).build()
}

/// The response if it is a success. A redirect isn't: none are followed.
// r[impl federation.outbound.redirects]
pub(crate) fn succeeded(response: Response) -> Result<Response, ResponseError> {
    if response.status().is_success() {
        Ok(response)
    } else {
        Err(ResponseError::Status(response.status()))
    }
}

/// Reads a response body of at most `limit` bytes, failing as soon as it
/// turns out longer.
// r[impl federation.outbound.size]
pub(crate) async fn body(mut response: Response, limit: usize) -> Result<Vec<u8>, ResponseError> {
    let fits = |length: u64| usize::try_from(length).is_ok_and(|length| length <= limit);
    if response
        .content_length()
        .is_some_and(|length| !fits(length))
    {
        return Err(ResponseError::TooLarge(limit));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > limit {
            return Err(ResponseError::TooLarge(limit));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// The JSON body of a successful response, of at most [`BODY_LIMIT`] bytes.
pub(crate) async fn json<T: DeserializeOwned>(response: Response) -> Result<T, ResponseError> {
    let body = body(succeeded(response)?, BODY_LIMIT).await?;
    Ok(serde_json::from_slice(&body)?)
}

/// A URL's host: an address, or a name in lower case without the root dot.
enum Host {
    Address(IpAddr),
    Name(String),
}

fn host(url: &Url) -> Option<Host> {
    let host = url.host_str().filter(|host| !host.is_empty())?;
    let address = host.trim_start_matches('[').trim_end_matches(']');
    Some(match address.parse() {
        Ok(address) => Host::Address(address),
        Err(_) => Host::Name(host.trim_end_matches('.').to_ascii_lowercase()),
    })
}

/// Whether a host is this machine itself: `localhost`, a name under it, or
/// a loopback address.
fn is_loopback(host: &Host) -> bool {
    match host {
        Host::Name(name) => name == "localhost" || name.ends_with(".localhost"),
        Host::Address(address) => address.is_loopback(),
    }
}

/// Parses a URL an OIDC client registers for browsers to be sent to or
/// for Konklav to call: `https`, or plain `http` on a loopback host, or on
/// any host when `plain_http` is set. No other scheme is ever accepted, so
/// `javascript:`, `data:` and the like can't be registered.
// r[impl oidc.provider.client-urls]
pub(crate) fn client_url(url: &str, plain_http: bool) -> Result<Url, String> {
    let parsed = Url::parse(url).map_err(|_| format!("`{url}` is not a URL"))?;
    let Some(host) = host(&parsed) else {
        return Err(format!("`{url}` has no host"));
    };
    match parsed.scheme() {
        "https" => Ok(parsed),
        "http" if plain_http || is_loopback(&host) => Ok(parsed),
        "http" => Err(format!(
            "`{url}` must be an `https` URL: plain HTTP is only for loopback hosts"
        )),
        _ => Err(format!("`{url}` must be an `https` URL")),
    }
}

/// Whether `address` is on the public internet: not loopback, private,
/// link-local (cloud metadata services among them), shared, multicast,
/// unspecified or otherwise reserved.
fn is_global(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => is_global_v4(v4),
        IpAddr::V6(v6) => {
            // Addresses that carry an IPv4 one are judged by it: mapped,
            // compatible, and the NAT64 prefix 64:ff9b::/96.
            let segments = v6.segments();
            let embedded = v6.to_ipv4().or_else(|| {
                (segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0])
                    .then(|| Ipv4Addr::from(u32::from(segments[6]) << 16 | u32::from(segments[7])))
            });
            match embedded {
                Some(v4) => is_global_v4(v4),
                None => is_global_v6(v6),
            }
        }
    }
}

fn is_global_v4(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_private()
        || address.is_link_local()
        || address.is_broadcast()
        || address.is_documentation()
        || address.is_multicast()
        // "This network", shared address space, protocol assignments,
        // benchmarking and reserved.
        || a == 0
        || (a == 100 && (b & 0xc0) == 64)
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && (b & 0xfe) == 18)
        || a >= 240)
}

fn is_global_v6(address: Ipv6Addr) -> bool {
    let first = address.segments()[0];
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        // Unique local, link-local and site-local.
        || (first & 0xfe00) == 0xfc00
        || (first & 0xffc0) == 0xfe80
        || (first & 0xffc0) == 0xfec0
        // Documentation.
        || (first == 0x2001 && address.segments()[1] == 0xdb8))
}

/// Refuses `url` as a destination when its host is an address that isn't
/// public, or a loopback name. Other names are judged when they are
/// resolved, by a client from [`public_only`].
// r[impl oidc.provider.logout.destinations]
pub(crate) fn public_destination(url: &Url) -> Result<(), String> {
    let public = match host(url) {
        Some(Host::Address(address)) => is_global(address),
        Some(name) => !is_loopback(&name),
        None => false,
    };
    if public {
        Ok(())
    } else {
        Err(format!(
            "`{}` is not a public address",
            url.host_str().unwrap_or_default()
        ))
    }
}

/// Resolves names with the system's resolver and refuses those with an
/// address that isn't public. The client connects to the addresses checked
/// here, so a name can't answer differently between check and use.
struct PublicOnly;

impl Resolve for PublicOnly {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let addresses: Vec<SocketAddr> =
                tokio::net::lookup_host((name.as_str(), 0)).await?.collect();
            if addresses.iter().any(|address| !is_global(address.ip())) {
                return Err(format!("`{}` is not a public address", name.as_str()).into());
            }
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

/// Makes a client connect only to public addresses: names are resolved by
/// [`PublicOnly`], and no proxy is used, since a proxy would resolve them
/// instead. URLs whose host is an address must be checked with
/// [`public_destination`] before each request, as they are never resolved.
// r[impl oidc.provider.logout.destinations]
pub(crate) fn public_only(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    builder
        .dns_resolver(std::sync::Arc::new(PublicOnly))
        .no_proxy()
}

#[cfg(test)]
mod tests {
    use super::*;

    // r[verify oidc.provider.client-urls]
    #[test]
    fn client_urls_are_https_or_loopback_http() {
        for url in [
            "https://app.example/callback",
            "http://localhost:3000/callback",
            "http://app.localhost/callback",
            "http://127.0.0.1:3000/callback",
            "http://127.8.8.8/callback",
            "http://[::1]:3000/callback",
        ] {
            assert!(client_url(url, false).is_ok(), "{url}");
        }
        for url in [
            "http://app.example/callback",
            "http://localhost.example/callback",
            "http://10.0.0.1/callback",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "file:///etc/passwd",
            "vbscript:msgbox(1)",
            "com.example.app:/callback",
            "/callback",
        ] {
            assert!(client_url(url, false).is_err(), "{url}");
        }
        // Plain HTTP anywhere is all a development deployment adds.
        assert!(client_url("http://app.example/callback", true).is_ok());
        assert!(client_url("javascript:alert(1)", true).is_err());
        assert!(client_url("com.example.app:/callback", true).is_err());
    }

    // r[verify oidc.provider.logout.destinations]
    #[test]
    fn only_public_addresses_are_public_destinations() {
        let public = |url: &str| public_destination(&Url::parse(url).unwrap()).is_ok();
        for url in [
            "https://rp.example/logout",
            "https://93.184.215.14/logout",
            "https://[2606:2800:21f:cb07:6820:80da:af6b:8b2c]/logout",
        ] {
            assert!(public(url), "{url}");
        }
        for url in [
            "http://localhost/logout",
            "http://rp.localhost./logout",
            "http://127.0.0.1/logout",
            "http://0.0.0.0/logout",
            "http://10.1.2.3/logout",
            "http://172.16.0.1/logout",
            "http://192.168.1.1/logout",
            "http://169.254.169.254/latest/meta-data/",
            "http://100.64.0.1/logout",
            "http://2130706433/logout",
            "http://[::1]/logout",
            "http://[::ffff:127.0.0.1]/logout",
            "http://[64:ff9b::a00:1]/logout",
            "http://[fe80::1]/logout",
            "http://[fd00:ec2::254]/logout",
        ] {
            assert!(!public(url), "{url}");
        }
    }

    // r[verify oidc.provider.logout.destinations]
    #[tokio::test]
    async fn names_with_private_addresses_are_not_resolved() {
        let http = public_only(builder(Duration::from_secs(5)))
            .build()
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let error = http
            .get(format!("http://localhost:{port}/"))
            .send()
            .await
            .unwrap_err();
        assert!(error.is_connect(), "{error:?}");
        assert!(format!("{error:?}").contains("is not a public address"));
    }

    async fn serve(router: axum::Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        origin
    }

    // r[verify federation.outbound.size]
    #[tokio::test]
    async fn bodies_are_read_up_to_the_limit_only() {
        use axum::routing::get;
        let origin = serve(
            axum::Router::new()
                .route("/fits", get(|| async { "12345678" }))
                .route("/declared", get(|| async { "123456789" }))
                // Chunked, so the length is only known by reading.
                .route(
                    "/streamed",
                    get(|| async {
                        let chunks = (0..1000).map(|_| Ok::<_, std::io::Error>("1234"));
                        axum::body::Body::from_stream(futures_util::stream::iter(chunks))
                    }),
                ),
        )
        .await;
        let http = client(Duration::from_secs(5)).unwrap();
        let get = async |path: &str| {
            let response = http.get(format!("{origin}{path}")).send().await.unwrap();
            body(response, 8).await
        };
        assert_eq!(get("/fits").await.unwrap(), b"12345678");
        assert!(matches!(
            get("/declared").await,
            Err(ResponseError::TooLarge(8))
        ));
        assert!(matches!(
            get("/streamed").await,
            Err(ResponseError::TooLarge(8))
        ));
    }

    // r[verify federation.outbound.redirects]
    #[tokio::test]
    async fn redirects_are_answers_that_failed() {
        use axum::response::Redirect;
        use axum::routing::get;
        let origin = serve(
            axum::Router::new()
                .route("/moved", get(|| async { Redirect::temporary("/there") }))
                .route("/there", get(|| async { "{}" })),
        )
        .await;
        let http = client(Duration::from_secs(5)).unwrap();
        let response = http.get(format!("{origin}/moved")).send().await.unwrap();
        assert!(matches!(
            json::<serde_json::Value>(response).await,
            Err(ResponseError::Status(StatusCode::TEMPORARY_REDIRECT))
        ));
    }
}
