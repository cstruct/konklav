//! Conclave access tokens: claims, compact EdDSA (Ed25519) JWS signing and
//! verification, key ids, and JWKS documents.
//!
//! This crate is shared by the issuer (`conclave-authn` via the server) and by
//! verifiers (the relying core), so it performs no I/O and reads no clock:
//! callers pass the current time in.

mod claims;
mod jwk;
mod jws;

pub use claims::{AccessClaims, Actor, TokenKind};
pub use jwk::{Jwk, JwkSet, kid_for};
pub use jws::{
    Signer, VerifyError, VerifyOptions, decode_claims_unverified, decode_unverified_kid, verify,
};
