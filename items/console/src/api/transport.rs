//! Sending requests with the browser's `fetch`.

use gloo_net::http::{Request as Fetch, RequestBuilder};

use super::error::ApiError;
use super::request::{CLIENT_HEADER, Method, Request};

/// Sends `request`, presenting `token` when it's authenticated, and returns
/// the status and body. Cookies go along because the console and Conclave
/// share an origin.
pub async fn send(request: &Request, token: Option<&str>) -> Result<(u16, String), ApiError> {
    let url = request.url();
    let mut builder: RequestBuilder = match request.method {
        Method::Get => Fetch::get(&url),
        Method::Post => Fetch::post(&url),
        Method::Put => Fetch::put(&url),
        Method::Delete => Fetch::delete(&url),
    }
    .header(CLIENT_HEADER.0, CLIENT_HEADER.1);
    if request.authenticated
        && let Some(token) = token
    {
        builder = builder.header("authorization", &format!("Bearer {token}"));
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
