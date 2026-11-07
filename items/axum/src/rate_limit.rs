//! Rate limits on axum routes, with
//! [`konklav_relying_client::rate_limit::RateLimit`].
//!
//! [`RouteRateLimit`] adds one event per request, for a key that is either
//! a template or an async function:
//!
//! - a template of literal text and `{source:name}` fields:
//!   - `{path:project}`: a path parameter;
//!   - `{token:sub}`: a claim of the verified token (`sub`, `sid`, `knd`, or
//!     `tid` on routes that admit only tenant tokens);
//!   - `{client:address}`: the client's address
//!     ([`Konklav::client_address`], which honours trusted proxies);
//!   - `{{` and `}}` for literal braces;
//! - a function of the request's parts and the verified token, if any.
//!
//! Attach it to a [`RoutePolicy`](crate::RoutePolicy) with
//! [`RoutePolicy::rate_limit`](crate::RoutePolicy::rate_limit) to count the
//! requests the policy allows, with the token it verified, or apply it as a
//! layer of its own, such as on a public login route. Code in a handler can
//! call `limit.add(...)` itself and answer with [`Denied`]:
//!
//! ```no_run
//! # async fn example(login: konklav_relying_client::rate_limit::RateLimit, email: String) -> Result<(), konklav_axum::Denied> {
//! login.add(email).await?;
//! # Ok(())
//! # }
//! ```

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::fmt::{self, Write as _};
use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::extract::Request;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use konklav_relying_client::rate_limit::RateLimit;
use konklav_token::{AccessClaims, TokenKind};
use tower::{Layer, Service};

use crate::evaluate::{Evaluation, path_param, read_path_params};
use crate::host::BoxFuture;
use crate::{Denied, Konklav, RoutePolicyError};

/// A token claim a template can name: those a verified token always has
/// (`tid` on tenant tokens).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Claim {
    Sub,
    Sid,
    Knd,
    Tid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Part {
    Literal(String),
    Path(String),
    Token(Claim),
    ClientAddress,
}

impl fmt::Display for Part {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Literal(text) => f.write_str(text),
            Self::Path(name) => write!(f, "{{path:{name}}}"),
            Self::Token(claim) => write!(
                f,
                "{{token:{}}}",
                match claim {
                    Claim::Sub => "sub",
                    Claim::Sid => "sid",
                    Claim::Knd => "knd",
                    Claim::Tid => "tid",
                }
            ),
            Self::ClientAddress => f.write_str("{client:address}"),
        }
    }
}

/// A malformed rate-limit key template.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateError {
    pub template: String,
    pub why: String,
}

impl fmt::Display for TemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rate-limit key template {:?}: {}",
            self.template, self.why
        )
    }
}

impl std::error::Error for TemplateError {}

/// Reads `{source:name}` at the start of `chars`, returning the source,
/// the name and the characters it took.
fn field(chars: &[char]) -> Option<(String, String, usize)> {
    let mut at = 1;
    let source_start = at;
    while chars.get(at).is_some_and(char::is_ascii_lowercase) {
        at += 1;
    }
    if at == source_start || chars.get(at) != Some(&':') {
        return None;
    }
    let source: String = chars[source_start..at].iter().collect();
    at += 1;
    let name_start = at;
    if !chars
        .get(at)
        .is_some_and(|c| c.is_ascii_alphabetic() || *c == '_')
    {
        return None;
    }
    while chars
        .get(at)
        .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_')
    {
        at += 1;
    }
    if chars.get(at) != Some(&'}') {
        return None;
    }
    let name: String = chars[name_start..at].iter().collect();
    Some((source, name, at + 1))
}

// r[impl item.axum.rate-limit-template]
fn parse(template: &str) -> Result<Vec<Part>, TemplateError> {
    let refuse = |why: String| TemplateError {
        template: template.to_owned(),
        why,
    };
    let chars: Vec<char> = template.chars().collect();
    let mut parts = Vec::new();
    let mut literal = String::new();
    let mut at = 0;
    while at < chars.len() {
        let next = chars.get(at + 1);
        match chars[at] {
            brace @ ('{' | '}') if next == Some(&brace) => {
                literal.push(brace);
                at += 2;
            }
            '{' => {
                let Some((source, name, taken)) = field(&chars[at..]) else {
                    return Err(refuse(format!("expected {{source:name}} at {at}")));
                };
                let part = match source.as_str() {
                    "path" => Part::Path(name),
                    "token" => Part::Token(match name.as_str() {
                        "sub" => Claim::Sub,
                        "sid" => Claim::Sid,
                        "knd" => Claim::Knd,
                        "tid" => Claim::Tid,
                        _ => {
                            return Err(refuse(format!(
                                "{{token:{name}}}: a token claim must be one of knd, sid, sub, tid"
                            )));
                        }
                    }),
                    "client" if name == "address" => Part::ClientAddress,
                    "client" => {
                        return Err(refuse(format!(
                            "{{client:{name}}}: the only client field is {{client:address}}"
                        )));
                    }
                    _ => {
                        return Err(refuse(format!(
                            "{{{source}:{name}}}: the source must be path, token or client"
                        )));
                    }
                };
                if !literal.is_empty() {
                    parts.push(Part::Literal(std::mem::take(&mut literal)));
                }
                parts.push(part);
                at += taken;
            }
            '}' => {
                return Err(refuse(format!(
                    "unmatched '}}' at {at}; write '}}}}' for a literal one"
                )));
            }
            c => {
                literal.push(c);
                at += 1;
            }
        }
    }
    if !literal.is_empty() {
        parts.push(Part::Literal(literal));
    }
    Ok(parts)
}

/// `value` as a JSON string with every character outside printable ASCII
/// escaped, as Python's `json.dumps` writes it, so both integrations render
/// the same key.
fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(c),
            c => {
                let mut units = [0; 2];
                for unit in c.encode_utf16(&mut units) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
        }
    }
    out.push('"');
}

/// The key for rendered `values`: a compact JSON array, so that different
/// values can't render the same key.
fn encode(values: &[String]) -> String {
    let mut out = String::from("[");
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        push_json_string(&mut out, value);
    }
    out.push(']');
    out
}

fn claim(token: &AccessClaims, claim: Claim) -> Option<String> {
    match claim {
        Claim::Sub => Some(token.sub.to_string()),
        Claim::Sid => Some(token.sid.to_string()),
        Claim::Knd => serde_json::to_value(token.knd)
            .ok()
            .and_then(|kind| kind.as_str().map(str::to_owned)),
        Claim::Tid => token.tid.map(|tenant| tenant.to_string()),
    }
}

type KeyFunction =
    Arc<dyn Fn(&Parts, Option<&AccessClaims>) -> BoxFuture<'static, Vec<u8>> + Send + Sync>;

#[derive(Clone)]
enum Key {
    Template(Arc<[Part]>),
    Function(KeyFunction),
}

/// One event per request on a rate limit, for a templated or computed key.
// r[impl item.axum.rate-limit]
#[derive(Clone)]
pub struct RouteRateLimit {
    limit: RateLimit,
    key: Key,
}

impl fmt::Debug for RouteRateLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouteRateLimit")
            .field("limit", &self.limit.name())
            .finish_non_exhaustive()
    }
}

impl RouteRateLimit {
    /// A limit keyed by `template`, refused if it is malformed.
    pub fn new(limit: RateLimit, template: &str) -> Result<Self, TemplateError> {
        Ok(Self {
            limit,
            key: Key::Template(parse(template)?.into()),
        })
    }

    /// A limit keyed by what `key` returns for the request's parts and the
    /// verified token, if any.
    pub fn keyed<F, Fut, K>(limit: RateLimit, key: F) -> Self
    where
        F: Fn(&Parts, Option<&AccessClaims>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = K> + Send + 'static,
        K: Into<Vec<u8>>,
    {
        let key: KeyFunction = Arc::new(move |parts, token| {
            let key = key(parts, token);
            Box::pin(async move { key.await.into() })
        });
        Self {
            limit,
            key: Key::Function(key),
        }
    }

    pub(crate) fn name(&self) -> String {
        self.limit.name()
    }

    /// Why the template can't be rendered on a route admitting `admitted`
    /// (`None` when public).
    pub(crate) fn problem(&self, admitted: Option<&BTreeSet<TokenKind>>) -> Option<String> {
        let Key::Template(parts) = &self.key else {
            return None;
        };
        parts.iter().find_map(|part| match (part, admitted) {
            (Part::Token(_), None) => Some(format!("uses {part}, but its policy is public")),
            (Part::Token(Claim::Tid), Some(admitted))
                if admitted.iter().any(|kind| *kind != TokenKind::Tenant) =>
            {
                Some(format!(
                    "uses {part}, which only tenant tokens carry, but its policy admits other kinds"
                ))
            }
            _ => None,
        })
    }

    /// The key for the request.
    async fn key(
        &self,
        konklav: &Konklav,
        parts: &Parts,
        token: Option<&AccessClaims>,
    ) -> Result<Vec<u8>, RoutePolicyError> {
        let parts_of = match &self.key {
            Key::Function(key) => return Ok(key(parts, token).await),
            Key::Template(template) => template,
        };
        let refuse = |problem: String| RoutePolicyError::RateLimit {
            name: self.name(),
            problem,
        };
        let mut values = Vec::with_capacity(parts_of.len());
        for part in parts_of.iter() {
            let value = match part {
                Part::Literal(text) => text.clone(),
                Part::Path(name) => path_param(parts, name)
                    .ok_or_else(|| {
                        refuse(format!(
                            "uses {part}, but the route has no `{name}` path parameter"
                        ))
                    })?
                    .to_owned(),
                Part::Token(which) => {
                    let token = token.ok_or_else(|| {
                        refuse(format!(
                            "uses {part}, but no route policy verified a token for it; attach it with RoutePolicy::rate_limit"
                        ))
                    })?;
                    // Never share one key for a missing claim.
                    claim(token, *which).ok_or_else(|| {
                        refuse(format!("uses {part}, but the verified token has none"))
                    })?
                }
                Part::ClientAddress => konklav
                    .client_address(parts)
                    .ok_or(RoutePolicyError::NoClientAddress)?
                    .to_string(),
            };
            values.push(value);
        }
        Ok(encode(&values).into_bytes())
    }

    /// Adds one event for the request, or answers it.
    pub(crate) async fn add(
        &self,
        konklav: &Konklav,
        parts: &Parts,
        token: Option<&AccessClaims>,
    ) -> Result<(), Response> {
        let key = self
            .key(konklav, parts, token)
            .await
            .map_err(IntoResponse::into_response)?;
        self.limit
            .add(key)
            .await
            .map_err(|limited| konklav.respond(Denied::from(limited)))
    }
}

impl<S> Layer<S> for RouteRateLimit {
    type Service = RateLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimitService {
            limit: self.clone(),
            inner,
        }
    }
}

/// The service [`RouteRateLimit`] wraps a route in.
#[derive(Clone)]
pub struct RateLimitService<S> {
    limit: RouteRateLimit,
    inner: S,
}

impl<S> Service<Request> for RateLimitService<S>
where
    S: Service<Request, Error = Infallible> + Clone + Send + 'static,
    S::Response: IntoResponse,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = BoxFuture<'static, Result<Response, Infallible>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let ready = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, ready);
        let limit = self.limit.clone();
        Box::pin(async move {
            let (mut parts, body) = request.into_parts();
            let konklav = match Konklav::of(&parts) {
                Ok(konklav) => konklav,
                Err(error) => return Ok(error.into_response()),
            };
            read_path_params(&mut parts).await;
            let token = parts
                .extensions
                .get::<Evaluation>()
                .and_then(Evaluation::token)
                .cloned();
            if let Err(response) = limit.add(&konklav, &parts, token.as_ref()).await {
                return Ok(response);
            }
            let response = inner.call(Request::from_parts(parts, body)).await?;
            Ok(response.into_response())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn literal(text: &str) -> Part {
        Part::Literal(text.to_owned())
    }

    // r[verify item.axum.rate-limit-template]
    #[test]
    fn templates_parse_into_literals_and_fields() {
        assert_eq!(
            parse("{token:sub}/{path:project}").unwrap(),
            [
                Part::Token(Claim::Sub),
                literal("/"),
                Part::Path("project".into())
            ]
        );
        assert_eq!(
            parse("login {{{client:address}}}").unwrap(),
            [literal("login {"), Part::ClientAddress, literal("}")]
        );
        assert_eq!(parse("constant").unwrap(), [literal("constant")]);
        assert_eq!(parse("").unwrap(), []);
    }

    #[test]
    fn malformed_templates_are_refused() {
        for (template, why) in [
            ("{path}", "expected {source:name} at 0"),
            ("a{path:}", "expected {source:name} at 1"),
            ("{path:1x}", "expected {source:name} at 0"),
            (
                "{token:email}",
                "{token:email}: a token claim must be one of knd, sid, sub, tid",
            ),
            (
                "{client:port}",
                "{client:port}: the only client field is {client:address}",
            ),
            (
                "{query:q}",
                "{query:q}: the source must be path, token or client",
            ),
            ("a}b", "unmatched '}' at 1; write '}}' for a literal one"),
            ("{path:p", "expected {source:name} at 0"),
        ] {
            assert_eq!(
                parse(template),
                Err(TemplateError {
                    template: template.to_owned(),
                    why: why.to_owned()
                }),
                "{template}"
            );
        }
    }

    #[test]
    fn keys_are_json_arrays_whose_parts_cant_run_together() {
        let a = encode(&["a/b".into(), "/".into(), "c".into()]);
        let b = encode(&["a".into(), "/".into(), "b/c".into()]);
        assert_ne!(a, b);
        assert_eq!(a, r#"["a/b","/","c"]"#);
        // As Python's json.dumps(values, separators=(",", ":")) writes them.
        assert_eq!(
            encode(&["é \"q\" \\ \n\u{1}\u{7f}😀".into()]),
            r#"["\u00e9 \"q\" \\ \n\u0001\u007f\ud83d\ude00"]"#
        );
    }
}
