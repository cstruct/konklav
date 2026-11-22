//! Outbound HTTP: the clients Konklav fetches with, and which URLs it may fetch.

use std::time::Duration;

use reqwest::{Response, StatusCode};
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

#[cfg(test)]
mod tests {
    use super::*;

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
