//! Describing calls to Conclave without making them.

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::Value;

/// Sent with every request. Conclave requires it on cookie endpoints, where
/// it forces a CORS preflight that other sites can't pass.
pub const CLIENT_HEADER: (&str, &str) = ("x-conclave-client", "console");

/// Characters left alone in path segments and query values.
const UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
}

/// The Conclave surface a request goes to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Surface {
    Subject,
    Control,
}

impl Surface {
    /// Where the console reaches the surface, relative to its own origin.
    ///
    /// The subject-facing surface keeps its own `/v1` paths, because the
    /// refresh cookie is scoped to `/v1/refresh` and `/v1/sign-out`. The
    /// control-plane surface shares those paths, so it moves under
    /// `/control`.
    // r[impl item.console.same-origin]
    #[must_use]
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Subject => "/v1",
            Self::Control => "/control/v1",
        }
    }
}

/// One call to Conclave, independent of how it's sent.
#[derive(Clone, Debug, PartialEq)]
pub struct Request {
    pub method: Method,
    pub surface: Surface,
    /// Relative to the surface's `/v1`, starting with `/`.
    pub path: String,
    pub query: Vec<(&'static str, String)>,
    pub body: Option<Value>,
    /// Whether to present the operator's access token.
    pub authenticated: bool,
}

impl Request {
    #[must_use]
    pub fn new(method: Method, surface: Surface, path: impl Into<String>) -> Self {
        Self {
            method,
            surface,
            path: path.into(),
            query: Vec::new(),
            body: None,
            authenticated: true,
        }
    }

    #[must_use]
    pub fn control(method: Method, path: impl Into<String>) -> Self {
        Self::new(method, Surface::Control, path)
    }

    #[must_use]
    pub fn subject(method: Method, path: impl Into<String>) -> Self {
        Self::new(method, Surface::Subject, path)
    }

    #[must_use]
    pub fn json(mut self, body: Value) -> Self {
        self.body = Some(body);
        self
    }

    /// Adds a query parameter, unless `value` is absent or blank.
    #[must_use]
    pub fn query(mut self, key: &'static str, value: Option<impl ToString>) -> Self {
        if let Some(value) = value.map(|v| v.to_string())
            && !value.trim().is_empty()
        {
            self.query.push((key, value.trim().to_owned()));
        }
        self
    }

    /// Sends no access token, as for logging in.
    #[must_use]
    pub fn anonymous(mut self) -> Self {
        self.authenticated = false;
        self
    }

    /// The URL relative to the console's origin.
    ///
    /// ```
    /// use conclave_console::api::{Method, Request};
    /// let request = Request::control(Method::Get, "/subjects")
    ///     .query("identifier", Some("ada+ops@example.com"))
    ///     .query("before", None::<String>);
    /// assert_eq!(request.url(), "/control/v1/subjects?identifier=ada%2Bops%40example.com");
    /// ```
    #[must_use]
    pub fn url(&self) -> String {
        let mut url = format!("{}{}", self.surface.prefix(), self.path);
        for (index, (key, value)) in self.query.iter().enumerate() {
            url.push(if index == 0 { '?' } else { '&' });
            url.push_str(key);
            url.push('=');
            url.push_str(&encode(value));
        }
        url
    }
}

/// Percent-encodes a path segment or query value.
#[must_use]
pub fn encode(value: &str) -> String {
    utf8_percent_encode(value, UNRESERVED).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // r[verify item.console.same-origin]
    #[test]
    fn surfaces_share_the_console_origin_without_overlapping() {
        assert_eq!(
            Request::subject(Method::Post, "/refresh").url(),
            "/v1/refresh"
        );
        assert_eq!(
            Request::control(Method::Get, "/sessions").url(),
            "/control/v1/sessions"
        );
    }

    #[test]
    fn blank_query_values_are_left_out() {
        let request = Request::control(Method::Get, "/sessions")
            .query("subject", Some("  "))
            .query("active", Some(true))
            .query("limit", Some(20));
        assert_eq!(request.url(), "/control/v1/sessions?active=true&limit=20");
    }

    #[test]
    fn path_segments_are_encoded() {
        assert_eq!(encode("a/b c"), "a%2Fb%20c");
        assert_eq!(encode("kid-1_x.y~"), "kid-1_x.y~");
    }
}
