//! Making DPoP proofs (RFC 9449) with an ES256 key, for Rust clients of
//! Konklav. Verification stays in [`crate::verify_proof`].

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::{Value, json};

use crate::dpop::{access_token_hash, ec_thumbprint};

/// A P-256 key that signs DPoP proofs.
///
/// The crate reads no clock and draws no randomness: the caller supplies
/// the key's secret bytes, each proof's time and each proof's `jti`.
// r[impl item.token.dpop-signer]
#[derive(Clone)]
pub struct ProofSigner {
    key: SigningKey,
}

/// The secret bytes don't make a P-256 key: zero, or not below the curve
/// order. Draw new random bytes and try again.
#[derive(Debug, thiserror::Error)]
#[error("not a valid P-256 secret key")]
pub struct InvalidKey;

impl ProofSigner {
    /// A key from its 32-byte secret scalar, big-endian; any other length
    /// is refused.
    ///
    /// # Errors
    ///
    /// [`InvalidKey`] if the bytes aren't a valid scalar, which random
    /// bytes almost never are.
    pub fn from_secret_bytes(secret: &[u8]) -> Result<Self, InvalidKey> {
        if secret.len() != 32 {
            return Err(InvalidKey);
        }
        SigningKey::from_slice(secret)
            .map(|key| Self { key })
            .map_err(|_| InvalidKey)
    }

    /// The 32-byte secret scalar, to store the key and load it again with
    /// [`ProofSigner::from_secret_bytes`].
    #[must_use]
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.key.to_bytes().into()
    }

    fn coordinates(&self) -> ([u8; 32], [u8; 32]) {
        let point = self.key.verifying_key().to_sec1_point(false);
        let bytes = point.as_bytes();
        let mut x = [0; 32];
        let mut y = [0; 32];
        x.copy_from_slice(&bytes[1..33]);
        y.copy_from_slice(&bytes[33..65]);
        (x, y)
    }

    /// The public key as a JWK, as a proof's header carries it.
    #[must_use]
    pub fn jwk(&self) -> Value {
        let (x, y) = self.coordinates();
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(x),
            "y": URL_SAFE_NO_PAD.encode(y),
        })
    }

    /// The key thumbprint (`jkt`), as `dpop_jkt` and `cnf.jkt` carry it.
    #[must_use]
    pub fn thumbprint(&self) -> String {
        let (x, y) = self.coordinates();
        ec_thumbprint(&x, &y)
    }

    /// A proof for one request: `method` and `url` as sent, made at `iat`
    /// (Unix seconds) with `jti`, and with the hash of `access_token` when
    /// one goes with the request.
    ///
    /// `url` is sent as `htu` without its query and fragment, which a
    /// verifier ignores anyway.
    #[must_use]
    pub fn proof(
        &self,
        method: &str,
        url: &str,
        access_token: Option<&str>,
        iat: i64,
        jti: &str,
    ) -> String {
        let htu = url.split(['?', '#']).next().unwrap_or(url);
        let mut claims = json!({"jti": jti, "htm": method, "htu": htu, "iat": iat});
        if let Some(token) = access_token {
            claims["ath"] = json!(access_token_hash(token));
        }
        self.sign(&claims)
    }

    /// A proof with exactly these claims.
    #[must_use]
    pub fn sign(&self, claims: &Value) -> String {
        let header = json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": self.jwk()});
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let signature: Signature = self.key.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }
}

impl std::fmt::Debug for ProofSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProofSigner")
            .field("thumbprint", &self.thumbprint())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProofRequest, verify_proof};

    const NOW: i64 = 1_792_224_000;
    const URL: &str = "https://auth.example/v1/refresh";

    fn signer() -> ProofSigner {
        ProofSigner::from_secret_bytes(&[7; 32]).unwrap()
    }

    fn request<'a>(access_token: Option<&'a str>, bound_to: Option<&'a str>) -> ProofRequest<'a> {
        ProofRequest {
            method: "POST",
            url: URL,
            access_token,
            bound_to,
            now: NOW,
            max_age: 60,
            leeway: 5,
        }
    }

    // r[verify item.token.dpop-signer]
    #[test]
    fn proofs_verify_with_the_crates_verification() {
        let signer = signer();
        let proof = signer.proof("POST", URL, None, NOW, "one");
        let verified = verify_proof(&proof, &request(None, None)).unwrap();
        assert_eq!(verified.jkt, signer.thumbprint());
        assert_eq!(verified.jti, "one");
    }

    // r[verify item.token.dpop-signer]
    #[test]
    fn proofs_with_an_access_token_carry_its_hash() {
        let signer = signer();
        let jkt = signer.thumbprint();
        let proof = signer.proof("POST", URL, Some("token"), NOW, "two");
        verify_proof(&proof, &request(Some("token"), Some(&jkt))).unwrap();
        assert!(verify_proof(&proof, &request(Some("other"), Some(&jkt))).is_err());
    }

    #[test]
    fn htu_drops_the_query() {
        let signer = signer();
        let proof = signer.proof("POST", &format!("{URL}?a=b#c"), None, NOW, "three");
        verify_proof(&proof, &request(None, None)).unwrap();
    }

    #[test]
    fn the_key_round_trips_through_its_secret_bytes() {
        let signer = signer();
        let again = ProofSigner::from_secret_bytes(&signer.secret_bytes()).unwrap();
        assert_eq!(again.thumbprint(), signer.thumbprint());
        assert!(ProofSigner::from_secret_bytes(&[0; 32]).is_err());
        assert!(ProofSigner::from_secret_bytes(&[1; 31]).is_err());
    }

    #[test]
    fn debug_shows_no_secret() {
        let debug = format!("{:?}", signer());
        assert!(debug.contains("thumbprint"));
        assert!(!debug.contains("key:"));
    }
}
