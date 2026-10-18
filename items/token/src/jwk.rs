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
/// access tokens), or a P-256 EC key (for ID tokens). Relying systems only
/// use the Ed25519 keys.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub kid: String,
    /// The raw public key (OKP) or its x coordinate (EC), base64url without
    /// padding.
    pub x: String,
    /// The y coordinate of an EC key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

impl Jwk {
    #[must_use]
    pub fn from_verifying_key(key: &VerifyingKey) -> Self {
        Self {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            alg: "EdDSA".into(),
            use_: "sig".into(),
            kid: kid_for(key),
            x: URL_SAFE_NO_PAD.encode(key.as_bytes()),
            y: None,
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
            crv: "P-256".into(),
            alg: "ES256".into(),
            use_: "sig".into(),
            kid: URL_SAFE_NO_PAD.encode(hasher.finalize()),
            x: URL_SAFE_NO_PAD.encode(x),
            y: Some(URL_SAFE_NO_PAD.encode(y)),
        }
    }

    /// The Ed25519 key, if this is a well-formed Ed25519 signing JWK.
    #[must_use]
    pub fn verifying_key(&self) -> Option<VerifyingKey> {
        if self.kty != "OKP" || self.crv != "Ed25519" {
            return None;
        }
        let bytes: [u8; 32] = URL_SAFE_NO_PAD.decode(&self.x).ok()?.try_into().ok()?;
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
