//! DPoP proofs (RFC 9449) signed in this process, for the admin page's
//! backend: its tokens are bound to a key no browser ever sees.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::{Value, json};

/// A P-256 key, held in memory only.
pub struct DpopKey {
    key: SigningKey,
}

impl Default for DpopKey {
    fn default() -> Self {
        Self::new()
    }
}

impl DpopKey {
    /// A new random key.
    ///
    /// # Panics
    ///
    /// If the system has no randomness.
    #[must_use]
    pub fn new() -> Self {
        loop {
            let mut scalar = [0; 32];
            getrandom::fill(&mut scalar).expect("system randomness");
            // Almost every 32-byte string is a valid scalar.
            if let Ok(key) = SigningKey::from_slice(&scalar) {
                return Self { key };
            }
        }
    }

    fn coordinates(&self) -> (Vec<u8>, Vec<u8>) {
        let point = self.key.verifying_key().to_sec1_point(false);
        let bytes = point.as_bytes();
        (bytes[1..33].to_vec(), bytes[33..65].to_vec())
    }

    fn jwk(&self) -> Value {
        let (x, y) = self.coordinates();
        json!({"kty": "EC", "crv": "P-256", "x": URL_SAFE_NO_PAD.encode(x), "y": URL_SAFE_NO_PAD.encode(y)})
    }

    /// The key's thumbprint (RFC 7638), for `dpop_jkt`.
    #[must_use]
    pub fn thumbprint(&self) -> String {
        let (x, y) = self.coordinates();
        konklav_token::ec_thumbprint(&x, &y)
    }

    /// A proof for one request to `url` (without query or fragment), with
    /// the access token's hash when one is presented.
    ///
    /// # Panics
    ///
    /// If the clock is before 1970.
    #[must_use]
    pub fn proof(&self, method: &str, url: &str, access_token: Option<&str>) -> String {
        let iat = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("a clock after 1970")
            .as_secs();
        let mut claims = json!({
            "jti": uuid::Uuid::new_v4().to_string(),
            "htm": method,
            "htu": url,
            "iat": iat,
        });
        if let Some(token) = access_token {
            claims["ath"] = json!(konklav_token::access_token_hash(token));
        }
        let header = json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": self.jwk()});
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        // ES256 in JWS is the raw r || s, which `to_bytes` gives.
        let signature: Signature = self.key.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }
}
