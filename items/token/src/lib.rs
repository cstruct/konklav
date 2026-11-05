//! Konklav access tokens: claims, compact EdDSA (Ed25519) JWS signing and
//! verification, key ids, and JWKS documents.
//!
//! This crate is shared by the issuer (`konklav-authn` via the server) and by
//! verifiers (the relying core), so it performs no I/O and reads no clock:
//! callers pass the current time in.

// r[impl item.token.sans-io]
mod claims;
mod dpop;
mod jwk;
mod jws;

pub use claims::{AccessClaims, Actor, Confirmation, TokenKind};
pub use dpop::{
    MAX_PROOF_LEN, PROOF_ALGORITHMS, Proof, ProofError, ProofRequest, access_token_hash,
    ec_thumbprint, ed25519_thumbprint, normalize_htu, verify_proof,
};
pub use jwk::{Jwk, JwkSet, kid_for};
pub use jws::{
    Signer, VerifyError, VerifyOptions, decode_claims_unverified, decode_unverified_kid, verify,
};
