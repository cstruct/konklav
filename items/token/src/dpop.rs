//! DPoP (RFC 9449) proofs: verification, key thumbprints and access-token
//! hashes. Stateless: callers supply the time and the request, and keep the
//! replay state themselves (`r[token.dpop.replay]`).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Proofs larger than this are refused before they are parsed.
pub const MAX_PROOF_LEN: usize = 4096;

/// The proof algorithms Konklav accepts, as discovery lists them.
pub const PROOF_ALGORITHMS: [&str; 2] = ["ES256", "EdDSA"];

/// What a proof must match.
#[derive(Clone, Debug)]
pub struct ProofRequest<'a> {
    /// The HTTP method of the request the proof came with.
    pub method: &'a str,
    /// The URL the client addressed, with or without query and fragment.
    pub url: &'a str,
    /// The access token presented with the proof, if any; the proof must
    /// then carry its hash (`ath`).
    pub access_token: Option<&'a str>,
    /// The key thumbprint the proof must be made with: the access token's
    /// `cnf.jkt`, or a bound session's key. `None` accepts any key.
    pub bound_to: Option<&'a str>,
    /// The current time, in Unix seconds.
    pub now: i64,
    /// How old a proof may be, in seconds.
    pub max_age: i64,
    /// Tolerated clock skew for proofs from the future, in seconds.
    pub leeway: i64,
}

/// A proof that verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// The thumbprint of the key that made the proof.
    pub jkt: String,
    /// The proof's unique id, for replay detection.
    pub jti: String,
    /// When the proof was made, in Unix seconds.
    pub iat: i64,
}

impl Proof {
    /// Until when the proof could still pass the freshness check, so the
    /// caller knows how long to remember its `jti`.
    #[must_use]
    pub fn replayable_until(&self, max_age: i64) -> i64 {
        self.iat.saturating_add(max_age)
    }
}

/// Why a proof was refused. Every variant is `invalid_dpop_proof` on the
/// wire; the variants exist for logs and tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProofError {
    #[error("DPoP proof is malformed")]
    Malformed,
    #[error("DPoP proof is too large")]
    TooLarge,
    #[error("DPoP proof has the wrong typ")]
    WrongType,
    #[error("DPoP proof uses an unsupported algorithm")]
    UnsupportedAlgorithm,
    #[error("DPoP proof key is invalid or doesn't match its algorithm")]
    BadKey,
    #[error("DPoP proof key carries private key material")]
    PrivateKey,
    #[error("DPoP proof signature is invalid")]
    BadSignature,
    #[error("DPoP proof lacks a required claim")]
    MissingClaim,
    #[error("DPoP proof is for another method")]
    WrongMethod,
    #[error("DPoP proof is for another URL")]
    WrongUrl,
    #[error("DPoP proof is too old")]
    TooOld,
    #[error("DPoP proof was made in the future")]
    IssuedInFuture,
    #[error("DPoP proof lacks the access token hash")]
    MissingAccessTokenHash,
    #[error("DPoP proof is for another access token")]
    WrongAccessToken,
    #[error("DPoP proof was made with another key")]
    WrongKey,
}

#[derive(Deserialize)]
struct Header {
    typ: Option<String>,
    alg: String,
    jwk: Map<String, Value>,
}

#[derive(Deserialize)]
struct Claims {
    jti: Option<String>,
    htm: Option<String>,
    htu: Option<String>,
    iat: Option<i64>,
    ath: Option<String>,
}

/// Members that only private (or symmetric) JWKs have.
const PRIVATE_MEMBERS: [&str; 7] = ["d", "p", "q", "dp", "dq", "qi", "k"];

/// A proof's public key.
enum ProofKey {
    Es256(p256::ecdsa::VerifyingKey),
    EdDsa(ed25519_dalek::VerifyingKey),
}

/// Verifies a DPoP proof against the request it came with.
// r[impl token.dpop.proof]
// r[impl token.dpop.request-match]
// r[impl token.dpop.freshness]
// r[impl token.dpop.access-token]
// r[impl item.token.dpop-proof]
pub fn verify_proof(proof: &str, request: &ProofRequest<'_>) -> Result<Proof, ProofError> {
    if proof.len() > MAX_PROOF_LEN {
        return Err(ProofError::TooLarge);
    }
    let mut parts = proof.split('.');
    let (Some(header_b64), Some(payload_b64), Some(signature_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(ProofError::Malformed);
    };
    let header: Header = decode_json(header_b64)?;
    if !header
        .typ
        .as_deref()
        .is_some_and(|typ| typ.eq_ignore_ascii_case("dpop+jwt"))
    {
        return Err(ProofError::WrongType);
    }
    if PRIVATE_MEMBERS
        .iter()
        .any(|member| header.jwk.contains_key(*member))
    {
        return Err(ProofError::PrivateKey);
    }
    let (key, jkt) = proof_key(&header.alg, &header.jwk)?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| ProofError::Malformed)?;
    let signing_input = &proof[..header_b64.len() + 1 + payload_b64.len()];
    key.verify(signing_input.as_bytes(), &signature)?;

    let claims: Claims = decode_json(payload_b64)?;
    let (Some(jti), Some(htm), Some(htu), Some(iat)) =
        (claims.jti, claims.htm, claims.htu, claims.iat)
    else {
        return Err(ProofError::MissingClaim);
    };
    if jti.is_empty() {
        return Err(ProofError::MissingClaim);
    }
    if htm != request.method {
        return Err(ProofError::WrongMethod);
    }
    match (normalize_htu(&htu), normalize_htu(request.url)) {
        (Some(proof_url), Some(request_url)) if proof_url == request_url => {}
        _ => return Err(ProofError::WrongUrl),
    }
    if iat < request.now.saturating_sub(request.max_age) {
        return Err(ProofError::TooOld);
    }
    if iat > request.now.saturating_add(request.leeway) {
        return Err(ProofError::IssuedInFuture);
    }
    if let Some(token) = request.access_token {
        let ath = claims.ath.ok_or(ProofError::MissingAccessTokenHash)?;
        if ath != access_token_hash(token) {
            return Err(ProofError::WrongAccessToken);
        }
    }
    if request.bound_to.is_some_and(|bound| bound != jkt) {
        return Err(ProofError::WrongKey);
    }
    Ok(Proof { jkt, jti, iat })
}

fn decode_json<T: serde::de::DeserializeOwned>(part: &str) -> Result<T, ProofError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| ProofError::Malformed)?;
    serde_json::from_slice(&bytes).map_err(|_| ProofError::Malformed)
}

/// The key a proof's `jwk` header names, checked against its `alg`, and
/// its thumbprint.
fn proof_key(alg: &str, jwk: &Map<String, Value>) -> Result<(ProofKey, String), ProofError> {
    let member = |name: &str| jwk.get(name).and_then(Value::as_str);
    let coordinate = |name: &str| -> Result<Vec<u8>, ProofError> {
        URL_SAFE_NO_PAD
            .decode(member(name).ok_or(ProofError::BadKey)?)
            .map_err(|_| ProofError::BadKey)
    };
    match alg {
        "ES256" => {
            if member("kty") != Some("EC") || member("crv") != Some("P-256") {
                return Err(ProofError::BadKey);
            }
            let (x, y) = (coordinate("x")?, coordinate("y")?);
            if x.len() != 32 || y.len() != 32 {
                return Err(ProofError::BadKey);
            }
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04);
            sec1.extend_from_slice(&x);
            sec1.extend_from_slice(&y);
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                .map_err(|_| ProofError::BadKey)?;
            Ok((ProofKey::Es256(key), ec_thumbprint(&x, &y)))
        }
        "EdDSA" => {
            if member("kty") != Some("OKP") || member("crv") != Some("Ed25519") {
                return Err(ProofError::BadKey);
            }
            let x: [u8; 32] = coordinate("x")?
                .try_into()
                .map_err(|_| ProofError::BadKey)?;
            let key =
                ed25519_dalek::VerifyingKey::from_bytes(&x).map_err(|_| ProofError::BadKey)?;
            Ok((ProofKey::EdDsa(key), ed25519_thumbprint(&x)))
        }
        _ => Err(ProofError::UnsupportedAlgorithm),
    }
}

impl ProofKey {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), ProofError> {
        match self {
            ProofKey::Es256(key) => {
                use p256::ecdsa::signature::Verifier as _;
                let signature = p256::ecdsa::Signature::from_slice(signature)
                    .map_err(|_| ProofError::BadSignature)?;
                key.verify(message, &signature)
                    .map_err(|_| ProofError::BadSignature)
            }
            ProofKey::EdDsa(key) => {
                let signature: [u8; 64] =
                    signature.try_into().map_err(|_| ProofError::BadSignature)?;
                key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(&signature))
                    .map_err(|_| ProofError::BadSignature)
            }
        }
    }
}

/// The RFC 7638 thumbprint of a P-256 public key, from its coordinates.
#[must_use]
pub fn ec_thumbprint(x: &[u8], y: &[u8]) -> String {
    let (x, y) = (URL_SAFE_NO_PAD.encode(x), URL_SAFE_NO_PAD.encode(y));
    thumbprint_of(&format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#
    ))
}

/// The RFC 7638 thumbprint of an Ed25519 public key.
#[must_use]
pub fn ed25519_thumbprint(x: &[u8]) -> String {
    let x = URL_SAFE_NO_PAD.encode(x);
    thumbprint_of(&format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#))
}

fn thumbprint_of(canonical: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

/// The `ath` of an access token: base64url of its SHA-256.
#[must_use]
pub fn access_token_hash(access_token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()))
}

/// An `htu` or request URL reduced to what proofs compare: scheme and host
/// lowercased, a default port dropped, an empty path made `/`, and query
/// and fragment removed. `None` if it isn't an absolute `http(s)` URL.
#[must_use]
pub fn normalize_htu(url: &str) -> Option<String> {
    let url = url.split(['?', '#']).next().unwrap_or_default();
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "https" => "443",
        "http" => "80",
        _ => return None,
    };
    let (authority, path) = match rest.find('/') {
        Some(index) => rest.split_at(index),
        None => (rest, "/"),
    };
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    // A port follows the last `:`, unless that is inside an IPv6 literal.
    let (host, port) = match authority.rfind(':') {
        Some(index) if !authority[index..].contains(']') => {
            (&authority[..index], Some(&authority[index + 1..]))
        }
        _ => (authority, None),
    };
    if host.is_empty() {
        return None;
    }
    let host = host.to_ascii_lowercase();
    Some(match port {
        Some(port) if !port.is_empty() && port != default_port => {
            if !port.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            format!("{scheme}://{host}:{port}{path}")
        }
        _ => format!("{scheme}://{host}{path}"),
    })
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::signature::Signer as _;
    use serde_json::json;

    use super::*;

    const NOW: i64 = 1_792_224_000;
    const URL: &str = "https://auth.example/v1/oauth2/token";

    struct Key(p256::ecdsa::SigningKey);

    impl Key {
        fn new(seed: u8) -> Self {
            Self(p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap())
        }

        fn jwk(&self) -> Value {
            let point = self.0.verifying_key().to_sec1_point(false);
            let bytes = point.as_bytes();
            json!({
                "kty": "EC",
                "crv": "P-256",
                "x": URL_SAFE_NO_PAD.encode(&bytes[1..33]),
                "y": URL_SAFE_NO_PAD.encode(&bytes[33..65]),
            })
        }

        fn jkt(&self) -> String {
            let point = self.0.verifying_key().to_sec1_point(false);
            let bytes = point.as_bytes();
            ec_thumbprint(&bytes[1..33], &bytes[33..65])
        }

        fn sign(&self, header: &Value, claims: &Value) -> String {
            let input = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(header.to_string()),
                URL_SAFE_NO_PAD.encode(claims.to_string())
            );
            let signature: p256::ecdsa::Signature = self.0.sign(input.as_bytes());
            format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
        }

        fn proof(&self, claims: &Value) -> String {
            self.sign(
                &json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": self.jwk()}),
                claims,
            )
        }
    }

    fn claims() -> Value {
        json!({"jti": "a", "htm": "POST", "htu": URL, "iat": NOW})
    }

    fn request() -> ProofRequest<'static> {
        ProofRequest {
            method: "POST",
            url: URL,
            access_token: None,
            bound_to: None,
            now: NOW,
            max_age: 60,
            leeway: 5,
        }
    }

    fn with(mut base: Value, key: &str, value: Value) -> Value {
        base[key] = value;
        base
    }

    // r[verify token.dpop.proof]
    // r[verify item.token.dpop-proof]
    #[test]
    fn a_well_formed_proof_verifies_and_names_its_key() {
        let key = Key::new(1);
        let proof = verify_proof(&key.proof(&claims()), &request()).unwrap();
        assert_eq!(proof.jkt, key.jkt());
        assert_eq!(proof.jti, "a");
        assert_eq!(proof.replayable_until(60), NOW + 60);
    }

    // r[verify token.dpop.proof]
    #[test]
    fn proofs_with_a_bad_header_or_signature_are_refused() {
        let key = Key::new(1);
        let jwk = key.jwk();
        let refused = |header: Value| verify_proof(&key.sign(&header, &claims()), &request());
        assert_eq!(
            refused(json!({"typ": "JWT", "alg": "ES256", "jwk": jwk})),
            Err(ProofError::WrongType)
        );
        assert_eq!(
            refused(json!({"alg": "ES256", "jwk": jwk})),
            Err(ProofError::WrongType)
        );
        assert_eq!(
            refused(json!({"typ": "dpop+jwt", "alg": "none", "jwk": jwk})),
            Err(ProofError::UnsupportedAlgorithm)
        );
        assert_eq!(
            refused(json!({"typ": "dpop+jwt", "alg": "HS256", "jwk": jwk})),
            Err(ProofError::UnsupportedAlgorithm)
        );
        assert_eq!(
            refused(json!({"typ": "dpop+jwt", "alg": "EdDSA", "jwk": jwk})),
            Err(ProofError::BadKey)
        );
        assert_eq!(
            refused(json!({"typ": "dpop+jwt", "alg": "ES256",
                "jwk": with(jwk.clone(), "d", json!("AAAA"))})),
            Err(ProofError::PrivateKey)
        );
        assert_eq!(
            refused(json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": Key::new(2).jwk()})),
            Err(ProofError::BadSignature)
        );
        assert_eq!(verify_proof("a.b", &request()), Err(ProofError::Malformed));
        assert_eq!(
            verify_proof(&"a".repeat(MAX_PROOF_LEN + 1), &request()),
            Err(ProofError::TooLarge)
        );
        for missing in ["jti", "htm", "htu", "iat"] {
            let mut partial = claims();
            partial.as_object_mut().unwrap().remove(missing);
            assert_eq!(
                verify_proof(&key.proof(&partial), &request()),
                Err(ProofError::MissingClaim),
                "{missing}"
            );
        }
    }

    // r[verify token.dpop.proof]
    #[test]
    fn ed25519_proofs_verify() {
        use ed25519_dalek::Signer as _;
        let key = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let x = key.verifying_key().to_bytes();
        let header = json!({"typ": "dpop+jwt", "alg": "EdDSA",
            "jwk": {"kty": "OKP", "crv": "Ed25519", "x": URL_SAFE_NO_PAD.encode(x)}});
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims().to_string())
        );
        let signature = key.sign(input.as_bytes());
        let proof = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()));
        assert_eq!(
            verify_proof(&proof, &request()).unwrap().jkt,
            ed25519_thumbprint(&x)
        );
    }

    // r[verify token.dpop.request-match]
    #[test]
    fn proofs_match_method_and_normalized_url() {
        let key = Key::new(1);
        let proof = |htu: &str| key.proof(&with(claims(), "htu", json!(htu)));
        for equivalent in [
            "HTTPS://Auth.Example/v1/oauth2/token",
            "https://auth.example:443/v1/oauth2/token",
            "https://auth.example/v1/oauth2/token?x=1#y",
        ] {
            assert!(
                verify_proof(&proof(equivalent), &request()).is_ok(),
                "{equivalent}"
            );
        }
        for other in [
            "https://auth.example/v1/oauth2/userinfo",
            "http://auth.example/v1/oauth2/token",
            "https://auth.example:8443/v1/oauth2/token",
            "https://evil.example/v1/oauth2/token",
            "/v1/oauth2/token",
        ] {
            assert_eq!(
                verify_proof(&proof(other), &request()),
                Err(ProofError::WrongUrl),
                "{other}"
            );
        }
        let get = ProofRequest {
            method: "GET",
            ..request()
        };
        assert_eq!(
            verify_proof(&key.proof(&claims()), &get),
            Err(ProofError::WrongMethod)
        );
    }

    #[test]
    fn urls_normalize() {
        assert_eq!(
            normalize_htu("HTTP://[::1]:80").as_deref(),
            Some("http://[::1]/")
        );
        assert_eq!(
            normalize_htu("http://[::1]:8080/a").as_deref(),
            Some("http://[::1]:8080/a")
        );
        assert_eq!(normalize_htu("https://u@host/"), None);
        assert_eq!(normalize_htu("ftp://host/"), None);
        assert_eq!(normalize_htu("https://host:x/"), None);
    }

    // r[verify token.dpop.freshness]
    #[test]
    fn stale_and_future_proofs_are_refused() {
        let key = Key::new(1);
        let at =
            |iat: i64| verify_proof(&key.proof(&with(claims(), "iat", json!(iat))), &request());
        assert!(at(NOW - 60).is_ok());
        assert_eq!(at(NOW - 61), Err(ProofError::TooOld));
        assert!(at(NOW + 5).is_ok());
        assert_eq!(at(NOW + 6), Err(ProofError::IssuedInFuture));
    }

    // r[verify token.dpop.access-token]
    #[test]
    fn proofs_with_an_access_token_carry_its_hash_and_the_bound_key() {
        let key = Key::new(1);
        let jkt = key.jkt();
        let with_token = ProofRequest {
            access_token: Some("token"),
            bound_to: Some(&jkt),
            ..request()
        };
        let ath = access_token_hash("token");
        assert!(verify_proof(&key.proof(&with(claims(), "ath", json!(ath))), &with_token).is_ok());
        assert_eq!(
            verify_proof(&key.proof(&claims()), &with_token),
            Err(ProofError::MissingAccessTokenHash)
        );
        assert_eq!(
            verify_proof(
                &key.proof(&with(claims(), "ath", json!(access_token_hash("other")))),
                &with_token
            ),
            Err(ProofError::WrongAccessToken)
        );
        let other = Key::new(2);
        assert_eq!(
            verify_proof(
                &other.proof(&with(claims(), "ath", json!(ath))),
                &with_token
            ),
            Err(ProofError::WrongKey)
        );
    }

    /// RFC 7638 §3.1 uses an RSA key; this checks the EC member order and
    /// encoding against RFC 9449's example key (§4.1, thumbprint from §6.1).
    #[test]
    fn thumbprints_match_rfc_9449() {
        let x = URL_SAFE_NO_PAD
            .decode("l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs")
            .unwrap();
        let y = URL_SAFE_NO_PAD
            .decode("9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA")
            .unwrap();
        assert_eq!(
            ec_thumbprint(&x, &y),
            "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
        );
    }
}
