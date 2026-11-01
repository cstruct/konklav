use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The key id of an Ed25519 public key: base64url (no padding) of the
/// SHA-256 of its 32 raw bytes.
// r[impl token.keys.kid]
#[must_use]
pub fn kid_for(key: &VerifyingKey) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(key.as_bytes()))
}

/// One public key in a JWKS document: an RFC 8037 OKP key (Ed25519, for
/// access tokens), or a P-256 EC or RSA key (for ID tokens). Relying
/// systems only use the Ed25519 keys and ignore the others.
// r[impl relying.verify.foreign-keys]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    /// The curve of an OKP or EC key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(default)]
    pub alg: String,
    #[serde(rename = "use", default)]
    pub use_: String,
    #[serde(default)]
    pub kid: String,
    /// The raw public key (OKP) or its x coordinate (EC), base64url without
    /// padding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// The y coordinate of an EC key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    /// The modulus of an RSA key, base64url without padding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    /// The public exponent of an RSA key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
}

impl Jwk {
    #[must_use]
    pub fn from_verifying_key(key: &VerifyingKey) -> Self {
        Self {
            kty: "OKP".into(),
            crv: Some("Ed25519".into()),
            alg: "EdDSA".into(),
            use_: "sig".into(),
            kid: kid_for(key),
            x: Some(URL_SAFE_NO_PAD.encode(key.as_bytes())),
            y: None,
            n: None,
            e: None,
        }
    }

    /// A P-256 key for `ES256`, from its raw coordinates. Its `kid` is the
    /// base64url SHA-256 of the coordinates.
    #[must_use]
    pub fn es256(x: &[u8], y: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(x);
        hasher.update(y);
        Self {
            kty: "EC".into(),
            crv: Some("P-256".into()),
            alg: "ES256".into(),
            use_: "sig".into(),
            kid: URL_SAFE_NO_PAD.encode(hasher.finalize()),
            x: Some(URL_SAFE_NO_PAD.encode(x)),
            y: Some(URL_SAFE_NO_PAD.encode(y)),
            n: None,
            e: None,
        }
    }

    /// An RSA key for `RS256`, from its big-endian modulus and exponent. Its
    /// `kid` is its RFC 7638 thumbprint.
    #[must_use]
    pub fn rs256(n: &[u8], e: &[u8]) -> Self {
        let n = URL_SAFE_NO_PAD.encode(n);
        let e = URL_SAFE_NO_PAD.encode(e);
        let thumbprint = format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#);
        Self {
            kty: "RSA".into(),
            crv: None,
            alg: "RS256".into(),
            use_: "sig".into(),
            kid: URL_SAFE_NO_PAD.encode(Sha256::digest(thumbprint.as_bytes())),
            x: None,
            y: None,
            n: Some(n),
            e: Some(e),
        }
    }

    /// The Ed25519 key, if this is a well-formed Ed25519 signing JWK.
    #[must_use]
    pub fn verifying_key(&self) -> Option<VerifyingKey> {
        if self.kty != "OKP" || self.crv.as_deref() != Some("Ed25519") {
            return None;
        }
        let bytes: [u8; 32] = URL_SAFE_NO_PAD
            .decode(self.x.as_deref()?)
            .ok()?
            .try_into()
            .ok()?;
        VerifyingKey::from_bytes(&bytes).ok()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    #[must_use]
    pub fn find(&self, kid: &str) -> Option<VerifyingKey> {
        self.keys
            .iter()
            .find(|key| key.kid == kid)
            .and_then(Jwk::verifying_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // r[verify relying.verify.foreign-keys]
    #[test]
    fn sets_with_other_key_types_parse_and_only_ed25519_keys_verify() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key();
        let ours = Jwk::from_verifying_key(&key);
        let set: JwkSet = serde_json::from_value(serde_json::json!({"keys": [
            {"kty": "RSA", "kid": "r", "alg": "RS256", "use": "sig", "n": "AQAB", "e": "AQAB"},
            {"kty": "EC", "crv": "P-256", "kid": "e", "alg": "ES256", "x": "AA", "y": "AA"},
            {"kty": "oct", "kid": "s"},
            serde_json::to_value(&ours).unwrap(),
        ]}))
        .unwrap();
        assert_eq!(set.find(&ours.kid), Some(key));
        for other in ["r", "e", "s"] {
            assert_eq!(set.find(other), None, "{other}");
        }
    }

    #[test]
    fn rsa_kids_are_rfc_7638_thumbprints() {
        // The example key of RFC 7638 section 3.1.
        let n = URL_SAFE_NO_PAD
            .decode(concat!(
                "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_",
                "BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_",
                "FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4",
                "vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
            ))
            .unwrap();
        let jwk = Jwk::rs256(&n, &[1, 0, 1]);
        assert_eq!(jwk.kid, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    }
}
