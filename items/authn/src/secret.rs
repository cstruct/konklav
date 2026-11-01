use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Generates a high-entropy secret (32 random bytes, base64url).
///
/// # Panics
///
/// Panics if the operating system cannot provide randomness.
#[must_use]
pub fn generate_secret() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("system randomness");
    URL_SAFE_NO_PAD.encode(bytes)
}

/// A secret key as presented by a service principal: the credential id (its
/// login identifier) and the secret of one of its slots.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretKey {
    pub key_id: String,
    pub secret: String,
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretKey")
            .field("key_id", &self.key_id)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Splits a combined `<key id>.<secret>` string, the form handed out when a
/// secret is created.
#[must_use]
pub fn parse_presented_secret_key(presented: &str) -> Option<SecretKey> {
    let (key_id, secret) = presented.split_once('.')?;
    (!key_id.is_empty() && !secret.is_empty()).then(|| SecretKey {
        key_id: key_id.to_owned(),
        secret: secret.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_are_long_and_unique() {
        let a = generate_secret();
        assert_eq!(a.len(), 43);
        assert_ne!(a, generate_secret());
    }

    #[test]
    fn splits_presented_keys() {
        let key = parse_presented_secret_key("0193.abc.def").unwrap();
        assert_eq!(key.key_id, "0193");
        assert_eq!(key.secret, "abc.def");
        assert!(parse_presented_secret_key("nodot").is_none());
        assert!(parse_presented_secret_key(".secret").is_none());
    }
}
