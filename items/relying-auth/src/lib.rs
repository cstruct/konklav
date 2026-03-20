use std::collections::BTreeMap;
use std::fmt;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use conclave_core::{
    ActionName, CatalogRevision, PolicyRevision, ScopeId, ScopeKind, SubjectId, TenantId,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub type DynError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorChainClaim {
    pub sub: SubjectId,
    pub tid: TenantId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopedBitsClaim {
    pub kind: ScopeKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<ScopeId>,
    pub bits: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationSnapshotClaim {
    pub catalog_rev: CatalogRevision,
    pub policy_rev: PolicyRevision,
    pub tenant_bits: String,
    pub scopes: Vec<ScopedBitsClaim>,
    pub facts: Map<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub iss: String,
    pub sub: SubjectId,
    pub aud: String,
    pub jti: String,
    pub iat: u64,
    pub exp: u64,
    pub tid: TenantId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act: Option<ActorChainClaim>,
    pub az: AuthorizationSnapshotClaim,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionCatalogEntry {
    pub name: ActionName,
    pub bit: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessDecision {
    pub action: ActionName,
    pub allowed: bool,
    pub matched_scope: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ValidatedToken {
    pub claims: AccessTokenClaims,
    pub decision: Option<AccessDecision>,
}

#[derive(Clone, Debug, Default)]
pub struct ValidationOptions<'a> {
    pub issuer: Option<&'a str>,
    pub audience: Option<&'a str>,
    pub expected_tenant: Option<&'a str>,
    pub current_catalog_revision: Option<CatalogRevision>,
    pub current_policy_revision: Option<PolicyRevision>,
    pub action: Option<&'a str>,
    pub scope_kind: Option<&'a str>,
    pub scope_id: Option<&'a str>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub kid: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub x: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

#[derive(Clone)]
pub struct JwtSigner {
    kid: String,
    signing_key: SigningKey,
}

#[derive(Clone)]
pub struct JwtVerifier {
    keys: BTreeMap<String, VerifyingKey>,
}

#[derive(Debug)]
struct JwtError {
    message: String,
}

impl JwtError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for JwtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(f)
    }
}

impl std::error::Error for JwtError {}

impl JwtSigner {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let kid = derive_kid(&signing_key.verifying_key());

        Self { kid, signing_key }
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    // r[impl item.relying-auth.ed25519-jwt-boundary]
    pub fn jwk(&self) -> Jwk {
        let public = self.signing_key.verifying_key();

        Jwk {
            kty: "OKP".to_owned(),
            crv: "Ed25519".to_owned(),
            kid: self.kid.clone(),
            alg: "EdDSA".to_owned(),
            use_: "sig".to_owned(),
            x: URL_SAFE_NO_PAD.encode(public.as_bytes()),
        }
    }

    pub fn verifier(&self) -> JwtVerifier {
        JwtVerifier::from_jwks(&JwkSet {
            keys: vec![self.jwk()],
        })
        .expect("signer should produce a valid verifier")
    }

    // r[impl item.relying-auth.ed25519-jwt-boundary]
    pub fn sign(&self, claims: &AccessTokenClaims) -> Result<String, DynError> {
        let header = JwtHeader {
            alg: "EdDSA",
            typ: "JWT",
            kid: &self.kid,
        };
        let header = serde_json::to_vec(&header)?;
        let payload = serde_json::to_vec(claims)?;
        let header = URL_SAFE_NO_PAD.encode(header);
        let payload = URL_SAFE_NO_PAD.encode(payload);
        let signing_input = format!("{header}.{payload}");
        let signature = self.signing_key.sign(signing_input.as_bytes());

        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ))
    }
}

fn derive_kid(public: &VerifyingKey) -> String {
    let digest = Sha256::digest(public.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

impl JwtVerifier {
    // r[impl item.relying-auth.ed25519-jwt-boundary]
    pub fn from_jwks(jwks: &JwkSet) -> Result<Self, DynError> {
        let mut keys = BTreeMap::new();

        for key in &jwks.keys {
            if key.kty != "OKP" || key.crv != "Ed25519" || key.alg != "EdDSA" {
                return Err(Box::new(JwtError::new(format!(
                    "unsupported jwk {} {} {}",
                    key.kty, key.crv, key.alg
                ))));
            }

            let bytes = URL_SAFE_NO_PAD.decode(key.x.as_bytes()).map_err(|err| {
                Box::new(JwtError::new(format!("invalid jwk x: {err}"))) as DynError
            })?;
            let array: [u8; 32] = bytes.try_into().map_err(|_| {
                Box::new(JwtError::new("ed25519 public key must be 32 bytes")) as DynError
            })?;
            keys.insert(key.kid.clone(), VerifyingKey::from_bytes(&array)?);
        }

        Ok(Self { keys })
    }

    // r[impl item.relying-auth.validation-options]
    // r[impl item.relying-auth.offline-decision-evaluation]
    pub fn verify(
        &self,
        token: &str,
        catalog: &[ActionCatalogEntry],
        options: ValidationOptions<'_>,
    ) -> Result<ValidatedToken, DynError> {
        let (header, claims, signing_input, signature) = split_token(token)?;
        let key = self.keys.get(&header.kid).ok_or_else(|| {
            Box::new(JwtError::new(format!("unknown kid {}", header.kid))) as DynError
        })?;
        let signature = Signature::from_slice(&signature)?;
        key.verify(signing_input.as_bytes(), &signature)?;

        if let Some(expected) = options.issuer {
            if claims.iss != expected {
                return Err(Box::new(JwtError::new(format!(
                    "token issuer {} does not match {}",
                    claims.iss, expected
                ))));
            }
        }

        if let Some(expected) = options.audience {
            if claims.aud != expected {
                return Err(Box::new(JwtError::new(format!(
                    "token audience {} does not match {}",
                    claims.aud, expected
                ))));
            }
        }

        if let Some(expected) = options.expected_tenant {
            if claims.tid != expected {
                return Err(Box::new(JwtError::new(format!(
                    "token tenant {} does not match {}",
                    claims.tid, expected
                ))));
            }
        }

        if let Some(expected) = options.current_catalog_revision {
            if claims.az.catalog_rev != expected {
                return Err(Box::new(JwtError::new("token catalog revision is stale")));
            }
        }

        if let Some(expected) = options.current_policy_revision {
            if claims.az.policy_rev != expected {
                return Err(Box::new(JwtError::new("token policy revision is stale")));
            }
        }

        let decision = if let Some(action) = options.action {
            let entry = catalog
                .iter()
                .find(|entry| entry.name == action)
                .ok_or_else(|| {
                    Box::new(JwtError::new(format!("unknown action {action}"))) as DynError
                })?;
            let (allowed, matched_scope) =
                evaluate_action(&claims.az, entry.bit, options.scope_kind, options.scope_id)?;

            Some(AccessDecision {
                action: action.to_owned(),
                allowed,
                matched_scope,
            })
        } else {
            None
        };

        Ok(ValidatedToken { claims, decision })
    }
}

#[derive(Deserialize)]
struct JwtHeaderOwned {
    alg: String,
    typ: Option<String>,
    kid: String,
}

#[derive(Serialize)]
struct JwtHeader<'a> {
    alg: &'a str,
    typ: &'a str,
    kid: &'a str,
}

fn split_token(
    token: &str,
) -> Result<(JwtHeaderOwned, AccessTokenClaims, String, Vec<u8>), DynError> {
    let mut parts = token.split('.');
    let header_part = parts
        .next()
        .ok_or_else(|| Box::new(JwtError::new("missing header")) as DynError)?;
    let payload_part = parts
        .next()
        .ok_or_else(|| Box::new(JwtError::new("missing payload")) as DynError)?;
    let signature_part = parts
        .next()
        .ok_or_else(|| Box::new(JwtError::new("missing signature")) as DynError)?;

    if parts.next().is_some() {
        return Err(Box::new(JwtError::new(
            "token must have exactly three parts",
        )));
    }

    let header: JwtHeaderOwned =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header_part.as_bytes()).map_err(
            |err| Box::new(JwtError::new(format!("invalid jwt header: {err}"))) as DynError,
        )?)?;
    if header.alg != "EdDSA" {
        return Err(Box::new(JwtError::new(format!(
            "unsupported jwt alg {}",
            header.alg
        ))));
    }
    if header.typ.as_deref().unwrap_or("JWT") != "JWT" {
        return Err(Box::new(JwtError::new("jwt typ must be JWT")));
    }

    let claims: AccessTokenClaims =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload_part.as_bytes()).map_err(
            |err| Box::new(JwtError::new(format!("invalid jwt payload: {err}"))) as DynError,
        )?)?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature_part.as_bytes())
        .map_err(|err| {
            Box::new(JwtError::new(format!("invalid jwt signature: {err}"))) as DynError
        })?;

    Ok((
        header,
        claims,
        format!("{header_part}.{payload_part}"),
        signature,
    ))
}

fn evaluate_action(
    snapshot: &AuthorizationSnapshotClaim,
    bit: usize,
    scope_kind: Option<&str>,
    scope_id: Option<&str>,
) -> Result<(bool, Option<String>), DynError> {
    if has_bit(&snapshot.tenant_bits, bit)? {
        return Ok((true, None));
    }

    for scope in &snapshot.scopes {
        if scope_kind.is_some_and(|expected| scope.kind != expected) {
            continue;
        }

        match (scope.id.as_deref(), scope_id) {
            (None, _) => {}
            (Some(left), Some(right)) if left == right => {}
            (Some(_), Some(_)) | (Some(_), None) => continue,
        }

        if has_bit(&scope.bits, bit)? {
            return Ok((
                true,
                Some(match &scope.id {
                    Some(id) => format!("{}:{id}", scope.kind),
                    None => format!("{}:*", scope.kind),
                }),
            ));
        }
    }

    Ok((false, None))
}

fn has_bit(encoded: &str, bit: usize) -> Result<bool, DynError> {
    if encoded.is_empty() || encoded == "0" {
        return Ok(false);
    }

    let bytes = hex_to_bytes(encoded)?;
    let byte = bit / 8;
    let offset = bit % 8;

    Ok(bytes
        .get(byte)
        .is_some_and(|value| (value & (1 << offset)) != 0))
}

fn hex_to_bytes(encoded: &str) -> Result<Vec<u8>, DynError> {
    let encoded = if encoded.len() % 2 == 0 {
        encoded.to_owned()
    } else {
        format!("0{encoded}")
    };

    let mut bytes = Vec::with_capacity(encoded.len() / 2);
    for chunk in encoded.as_bytes().chunks(2) {
        let pair = std::str::from_utf8(chunk)?;
        bytes.push(u8::from_str_radix(pair, 16)?);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    // r[verify item.relying-auth.ed25519-jwt-boundary]
    // r[verify item.relying-auth.validation-options]
    // r[verify item.relying-auth.offline-decision-evaluation]
    #[test]
    fn signs_and_verifies_ed25519_tokens() {
        let signer = JwtSigner::from_seed([7; 32]);
        let verifier = signer.verifier();
        let claims = AccessTokenClaims {
            iss: "https://conclave.test".to_owned(),
            sub: "subject-1".to_owned(),
            aud: "clinic-api".to_owned(),
            jti: "token-1".to_owned(),
            iat: 10,
            exp: 20,
            tid: "tenant-a".to_owned(),
            act: None,
            az: AuthorizationSnapshotClaim {
                catalog_rev: 4,
                policy_rev: 9,
                tenant_bits: "01".to_owned(),
                scopes: vec![ScopedBitsClaim {
                    kind: "clinic".to_owned(),
                    id: Some("clinic-1".to_owned()),
                    bits: "02".to_owned(),
                }],
                facts: Map::from_iter([("authn_level".to_owned(), json!(2))]),
            },
        };

        let token = signer.sign(&claims).expect("token should sign");
        let validated = verifier
            .verify(
                &token,
                &[
                    ActionCatalogEntry {
                        name: "tenant:user:read".to_owned(),
                        bit: 0,
                    },
                    ActionCatalogEntry {
                        name: "tenant:user:write".to_owned(),
                        bit: 1,
                    },
                ],
                ValidationOptions {
                    issuer: Some("https://conclave.test"),
                    audience: Some("clinic-api"),
                    expected_tenant: Some("tenant-a"),
                    current_catalog_revision: Some(4),
                    current_policy_revision: Some(9),
                    action: Some("tenant:user:write"),
                    scope_kind: Some("clinic"),
                    scope_id: Some("clinic-1"),
                },
            )
            .expect("token should verify");

        assert_eq!(validated.claims, claims);
        assert_eq!(
            validated.decision,
            Some(AccessDecision {
                action: "tenant:user:write".to_owned(),
                allowed: true,
                matched_scope: Some("clinic:clinic-1".to_owned()),
            })
        );
    }

    #[test]
    fn derives_stable_kids_from_public_key_material() {
        let first = JwtSigner::from_seed([7; 32]);
        let same = JwtSigner::from_seed([7; 32]);
        let different = JwtSigner::from_seed([8; 32]);

        assert_eq!(first.kid(), same.kid());
        assert_ne!(first.kid(), different.kid());
    }
}
