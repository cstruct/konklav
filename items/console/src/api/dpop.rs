//! DPoP proofs, signed in the browser by `dpop.js` with a non-extractable
//! WebCrypto key, and which authorization scheme a token needs.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use wasm_bindgen::prelude::*;

use super::error::ApiError;

#[wasm_bindgen(module = "/src/api/dpop.js")]
extern "C" {
    #[wasm_bindgen(catch, js_name = dpopProof)]
    async fn dpop_proof(
        method: &str,
        url: &str,
        access_token: Option<String>,
    ) -> Result<JsValue, JsValue>;
}

/// A proof for a request to `url` (relative to the console's origin).
// r[impl item.console.dpop]
pub async fn proof(
    method: &str,
    url: &str,
    access_token: Option<&str>,
) -> Result<String, ApiError> {
    dpop_proof(method, url, access_token.map(str::to_owned))
        .await
        .map_err(|error| ApiError::Network(format!("couldn't sign a DPoP proof: {error:?}")))?
        .as_string()
        .ok_or_else(|| ApiError::Network("couldn't sign a DPoP proof".into()))
}

/// The scheme to present `token` under: `DPoP` when it is bound to a key
/// (it carries `cnf`), `Bearer` otherwise, such as for a session started
/// before the console bound its sessions.
///
/// ```
/// use base64::Engine;
/// let part = |json: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
/// let bound = format!("{}.{}.sig", part("{}"), part(r#"{"cnf":{"jkt":"k"}}"#));
/// let plain = format!("{}.{}.sig", part("{}"), part(r#"{"sub":"s"}"#));
/// assert_eq!(konklav_console::api::scheme(&bound), "DPoP");
/// assert_eq!(konklav_console::api::scheme(&plain), "Bearer");
/// ```
#[must_use]
pub fn scheme(token: &str) -> &'static str {
    let bound = token
        .split('.')
        .nth(1)
        .and_then(|payload| URL_SAFE_NO_PAD.decode(payload).ok())
        .and_then(|payload| serde_json::from_slice::<serde_json::Value>(&payload).ok())
        .is_some_and(|claims| claims.get("cnf").is_some());
    if bound { "DPoP" } else { "Bearer" }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(claims: &str) -> String {
        format!(
            "{}.{}.signature",
            URL_SAFE_NO_PAD.encode("{}"),
            URL_SAFE_NO_PAD.encode(claims)
        )
    }

    // r[verify item.console.dpop]
    #[test]
    fn bound_tokens_go_under_dpop_and_others_under_bearer() {
        assert_eq!(scheme(&token(r#"{"cnf":{"jkt":"abc"}}"#)), "DPoP");
        assert_eq!(scheme(&token(r#"{"sub":"s"}"#)), "Bearer");
        assert_eq!(scheme("not a token"), "Bearer");
    }
}
