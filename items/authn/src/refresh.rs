use conclave_core::SessionId;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// An opaque refresh token: `<session id>.<secret>`.
///
/// Only the SHA-256 of the whole token is stored. Embedding the session id
/// lets Conclave find the session without an index over hashes, and tell a
/// replayed (rotated-away) token of a known session from a random guess.
// r[impl token.refresh.opaque]
#[derive(Clone, PartialEq, Eq)]
pub struct RefreshToken {
    session: SessionId,
    token: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("malformed refresh token")]
pub struct RefreshTokenError;

impl RefreshToken {
    #[must_use]
    pub fn generate(session: SessionId) -> Self {
        Self {
            session,
            token: format!("{session}.{}", crate::generate_secret()),
        }
    }

    pub fn parse(token: &str) -> Result<Self, RefreshTokenError> {
        let (session, secret) = token.split_once('.').ok_or(RefreshTokenError)?;
        if secret.len() < 32 {
            return Err(RefreshTokenError);
        }
        Ok(Self {
            session: session.parse().map_err(|_| RefreshTokenError)?,
            token: token.to_owned(),
        })
    }

    #[must_use]
    pub fn session(&self) -> SessionId {
        self.session
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.token
    }

    #[must_use]
    pub fn hash(&self) -> Vec<u8> {
        Sha256::digest(self.token.as_bytes()).to_vec()
    }

    /// Compares this token's hash with a stored one in constant time.
    #[must_use]
    pub fn matches(&self, stored_hash: &[u8]) -> bool {
        self.hash().ct_eq(stored_hash).into()
    }
}

impl std::fmt::Debug for RefreshToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshToken")
            .field("session", &self.session)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // r[verify token.refresh.opaque]
    #[test]
    fn round_trips_and_matches_its_hash() {
        let session = SessionId::new_v7();
        let token = RefreshToken::generate(session);
        let parsed = RefreshToken::parse(token.as_str()).unwrap();
        assert_eq!(parsed.session(), session);
        assert!(parsed.matches(&token.hash()));
        assert!(!RefreshToken::generate(session).matches(&token.hash()));
    }

    #[test]
    fn rejects_malformed_tokens() {
        assert!(RefreshToken::parse("nope").is_err());
        assert!(
            RefreshToken::parse("not-a-uuid.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").is_err()
        );
        assert!(RefreshToken::parse(&format!("{}.short", SessionId::new_v7())).is_err());
    }
}
