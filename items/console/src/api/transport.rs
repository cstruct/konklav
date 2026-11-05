//! Sending requests with the browser's `fetch`.

use gloo_net::http::{Request as Fetch, RequestBuilder};

use super::dpop::{proof, scheme};
use super::error::ApiError;
use super::request::{CLIENT_HEADER, Method, Request};

/// Sends `request`, presenting `token` when it's authenticated, and returns
/// the status and body. Cookies go along because the console and Konklav
/// share an origin.
///
/// Every request carries a DPoP proof: one with an access token proves the
/// token is the console's, and one without binds the session a login
/// starts, or refreshes, to the console's key.
pub async fn send(request: &Request, token: Option<&str>) -> Result<(u16, String), ApiError> {
    let url = request.url();
    let (mut builder, method): (RequestBuilder, _) = match request.method {
        Method::Get => (Fetch::get(&url), "GET"),
        Method::Post => (Fetch::post(&url), "POST"),
        Method::Put => (Fetch::put(&url), "PUT"),
        Method::Delete => (Fetch::delete(&url), "DELETE"),
    };
    builder = builder.header(CLIENT_HEADER.0, CLIENT_HEADER.1);
    let presented = token.filter(|_| request.authenticated);
    match presented {
        Some(token) if scheme(token) == "DPoP" => {
            builder = builder
                .header("authorization", &format!("DPoP {token}"))
                .header("dpop", &proof(method, &url, Some(token)).await?);
        }
        Some(token) => builder = builder.header("authorization", &format!("Bearer {token}")),
        None => builder = builder.header("dpop", &proof(method, &url, None).await?),
    }
    let prepared = match &request.body {
        Some(body) => builder.json(body),
        None => builder.build(),
    }
    .map_err(|error| ApiError::Network(error.to_string()))?;
    let response = prepared
        .send()
        .await
        .map_err(|error| ApiError::Network(error.to_string()))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|error| ApiError::Network(error.to_string()))?;
    Ok((status, body))
}
