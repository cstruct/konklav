use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{AccessClaims, kid_for};

#[derive(Serialize, Deserialize)]
struct Header {
    alg: String,
    typ: String,
    kid: String,
}

/// Signs access tokens with one Ed25519 key.
// r[impl token.access.jwt]
pub struct Signer {
    key: SigningKey,
    kid: String,
}

impl Signer {
    #[must_use]
    pub fn new(key: SigningKey) -> Self {
        let kid = kid_for(&key.verifying_key());
        Self { key, kid }
    }

    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// Encodes and signs `claims` as a compact JWS.
    ///
    /// # Panics
    ///
    /// Never in practice: the header and claims always serialize.
    #[must_use]
    pub fn sign(&self, claims: &AccessClaims) -> String {
        let header = Header {
            alg: "EdDSA".into(),
            typ: "JWT".into(),
            kid: self.kid.clone(),
        };
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header"));
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("claims"));
        let signing_input = format!("{header}.{payload}");
        let signature = self.key.sign(signing_input.as_bytes());
        format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        )
    }
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signer")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

/// What a verifier expects of a token.
#[derive(Clone, Debug)]
pub struct VerifyOptions<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    /// The current time, in Unix seconds.
    pub now: i64,
    /// Tolerated clock skew, in seconds.
    pub leeway: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    #[error("token is malformed")]
    Malformed,
    #[error("token uses an unsupported algorithm")]
    UnsupportedAlgorithm,
    #[error("token was signed by an unknown key")]
    UnknownKey,
    #[error("token signature is invalid")]
    BadSignature,
    #[error("token has expired")]
    Expired,
    #[error("token was issued in the future")]
    IssuedInFuture,
    #[error("token has the wrong issuer")]
    WrongIssuer,
    #[error("token has the wrong audience")]
    WrongAudience,
}

fn split(token: &str) -> Result<(&str, &str, &str), VerifyError> {
    let mut parts = token.split('.');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) => Ok((h, p, s)),
        _ => Err(VerifyError::Malformed),
    }
}

fn decode_header(header: &str) -> Result<Header, VerifyError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(header)
        .map_err(|_| VerifyError::Malformed)?;
    serde_json::from_slice(&bytes).map_err(|_| VerifyError::Malformed)
}

/// Reads the `kid` from a token's header without verifying anything, so the
/// caller can look up the verification key.
pub fn decode_unverified_kid(token: &str) -> Result<String, VerifyError> {
    let (header, _, _) = split(token)?;
    Ok(decode_header(header)?.kid)
}

/// Verifies a compact JWS access token: algorithm, signature, issuer,
/// audience, expiry and issue time.
///
/// `key_for` maps a `kid` to its verification key.
pub fn verify(
    token: &str,
    key_for: impl FnOnce(&str) -> Option<VerifyingKey>,
    options: &VerifyOptions<'_>,
) -> Result<AccessClaims, VerifyError> {
    let (header_b64, payload_b64, signature_b64) = split(token)?;
    let header = decode_header(header_b64)?;
    if header.alg != "EdDSA" {
        return Err(VerifyError::UnsupportedAlgorithm);
    }
    let key = key_for(&header.kid).ok_or(VerifyError::UnknownKey)?;
    let signature: [u8; 64] = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| VerifyError::Malformed)?
        .try_into()
        .map_err(|_| VerifyError::Malformed)?;
    let signing_input = &token[..header_b64.len() + 1 + payload_b64.len()];
    key.verify_strict(signing_input.as_bytes(), &Signature::from_bytes(&signature))
        .map_err(|_| VerifyError::BadSignature)?;

    let payload = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| VerifyError::Malformed)?;
    let claims: AccessClaims =
        serde_json::from_slice(&payload).map_err(|_| VerifyError::Malformed)?;
    if claims.iss != options.issuer {
        return Err(VerifyError::WrongIssuer);
    }
    if claims.aud != options.audience {
        return Err(VerifyError::WrongAudience);
    }
    if claims.exp + options.leeway <= options.now {
        return Err(VerifyError::Expired);
    }
    if claims.iat - options.leeway > options.now {
        return Err(VerifyError::IssuedInFuture);
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use conclave_core::{SessionId, SubjectId};

    use super::*;
    use crate::{Jwk, JwkSet, TokenKind};

    fn signer(seed: u8) -> Signer {
        Signer::new(SigningKey::from_bytes(&[seed; 32]))
    }

    fn claims(now: i64) -> AccessClaims {
        AccessClaims {
            iss: "https://auth.example".into(),
            aud: "api".into(),
            sub: SubjectId::new_v7(),
            jti: "j1".into(),
            iat: now,
            exp: now + 900,
            knd: TokenKind::Identity,
            sid: SessionId::new_v7(),
            sv: 1,
            amr: vec!["pwd".into()],
            auth_time: now,
            tid: None,
            mid: None,
            sfl: vec![],
            fct: BTreeMap::new(),
            act: None,
        }
    }

    fn options(now: i64) -> VerifyOptions<'static> {
        VerifyOptions {
            issuer: "https://auth.example",
            audience: "api",
            now,
            leeway: 5,
        }
    }

    fn jwks(signer: &Signer) -> JwkSet {
        JwkSet {
            keys: vec![Jwk::from_verifying_key(&signer.verifying_key())],
        }
    }

    #[test]
    fn verifies_what_it_signs() {
        let signer = signer(1);
        let claims = claims(1000);
        let token = signer.sign(&claims);
        let jwks = jwks(&signer);
        let verified = verify(&token, |kid| jwks.find(kid), &options(1000)).unwrap();
        assert_eq!(verified, claims);
        assert_eq!(decode_unverified_kid(&token).unwrap(), signer.kid());
    }

    #[test]
    fn rejects_unknown_keys_and_forged_signatures() {
        let token = signer(1).sign(&claims(1000));
        let other = jwks(&signer(2));
        assert_eq!(
            verify(&token, |kid| other.find(kid), &options(1000)),
            Err(VerifyError::UnknownKey)
        );
        let impostor = signer(2).verifying_key();
        assert_eq!(
            verify(&token, |_| Some(impostor), &options(1000)),
            Err(VerifyError::BadSignature)
        );
    }

    #[test]
    fn rejects_tampered_payloads() {
        let signer = signer(1);
        let token = signer.sign(&claims(1000));
        let (h, _, s) = split(&token).unwrap();
        let mut forged = claims(1000);
        forged.sv = 99;
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&forged).unwrap());
        let tampered = format!("{h}.{payload}.{s}");
        let key = signer.verifying_key();
        assert_eq!(
            verify(&tampered, |_| Some(key), &options(1000)),
            Err(VerifyError::BadSignature)
        );
    }

    #[test]
    fn enforces_time_issuer_and_audience() {
        let signer = signer(1);
        let key = signer.verifying_key();
        let token = signer.sign(&claims(1000));
        assert_eq!(
            verify(&token, |_| Some(key), &options(1905)),
            Err(VerifyError::Expired)
        );
        assert!(
            verify(&token, |_| Some(key), &options(1904)).is_ok(),
            "within leeway"
        );
        assert_eq!(
            verify(&token, |_| Some(key), &options(900)),
            Err(VerifyError::IssuedInFuture)
        );
        let wrong_audience = VerifyOptions {
            audience: "other",
            ..options(1000)
        };
        assert_eq!(
            verify(&token, |_| Some(key), &wrong_audience),
            Err(VerifyError::WrongAudience)
        );
        let wrong_issuer = VerifyOptions {
            issuer: "https://evil",
            ..options(1000)
        };
        assert_eq!(
            verify(&token, |_| Some(key), &wrong_issuer),
            Err(VerifyError::WrongIssuer)
        );
    }

    #[test]
    fn rejects_other_algorithms() {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT","kid":"x"}"#);
        let token = format!("{header}.e30.");
        assert_eq!(
            verify(&token, |_| None, &options(0)),
            Err(VerifyError::UnsupportedAlgorithm)
        );
    }

    // r[verify token.keys.kid]
    #[test]
    fn kid_is_derived_from_the_public_key() {
        let a = signer(1);
        assert_eq!(a.kid(), kid_for(&a.verifying_key()));
        assert_ne!(a.kid(), signer(2).kid());
        assert_eq!(a.kid().len(), 43, "base64url of 32 bytes");
    }
}
