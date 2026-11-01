use std::collections::BTreeMap;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

/// A secret encrypted with one of the configured keys.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedSecret {
    pub key_id: String,
    /// Base64 of the 96-bit nonce.
    pub nonce: String,
    /// Base64 of the AES-256-GCM ciphertext and tag.
    pub ciphertext: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EncryptionError {
    #[error("no encryption key is configured")]
    NoKey,
    #[error("encryption key `{0}` is not configured")]
    UnknownKey(String),
    #[error("encryption key `{0}` must be 32 bytes of base64")]
    InvalidKey(String),
    #[error("the secret could not be decrypted")]
    Decrypt,
}

/// Encrypts small secrets (such as TOTP seeds) with AES-256-GCM. The first
/// key encrypts; every key decrypts, so keys can be rotated by adding a new
/// first key and re-encrypting.
// r[impl authn.mfa.secrets-encrypted]
pub struct SecretBox {
    current: Option<String>,
    keys: BTreeMap<String, Aes256Gcm>,
}

impl SecretBox {
    /// Builds a box from `(key id, base64 key)` pairs, the first encrypting.
    pub fn new<'a>(
        keys: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, EncryptionError> {
        let mut current = None;
        let mut map = BTreeMap::new();
        for (id, key) in keys {
            let bytes = STANDARD
                .decode(key)
                .ok()
                .filter(|b| b.len() == 32)
                .ok_or_else(|| EncryptionError::InvalidKey(id.to_owned()))?;
            let cipher = Aes256Gcm::new_from_slice(&bytes)
                .map_err(|_| EncryptionError::InvalidKey(id.to_owned()))?;
            current.get_or_insert_with(|| id.to_owned());
            map.insert(id.to_owned(), cipher);
        }
        Ok(Self { current, keys: map })
    }

    /// Encrypts `plaintext` with the current key.
    ///
    /// # Panics
    ///
    /// Panics if the operating system cannot provide randomness.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedSecret, EncryptionError> {
        let id = self.current.as_ref().ok_or(EncryptionError::NoKey)?;
        let cipher = &self.keys[id];
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce).expect("system randomness");
        let ciphertext = cipher
            .encrypt(&Nonce::from(nonce), plaintext)
            .map_err(|_| EncryptionError::Decrypt)?;
        Ok(EncryptedSecret {
            key_id: id.clone(),
            nonce: STANDARD.encode(nonce),
            ciphertext: STANDARD.encode(ciphertext),
        })
    }

    pub fn decrypt(&self, secret: &EncryptedSecret) -> Result<Vec<u8>, EncryptionError> {
        let cipher = self
            .keys
            .get(&secret.key_id)
            .ok_or_else(|| EncryptionError::UnknownKey(secret.key_id.clone()))?;
        let nonce: [u8; 12] = STANDARD
            .decode(&secret.nonce)
            .ok()
            .and_then(|n| n.try_into().ok())
            .ok_or(EncryptionError::Decrypt)?;
        let ciphertext = STANDARD
            .decode(&secret.ciphertext)
            .map_err(|_| EncryptionError::Decrypt)?;
        cipher
            .decrypt(&Nonce::from(nonce), ciphertext.as_slice())
            .map_err(|_| EncryptionError::Decrypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const K1: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const K2: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";

    #[test]
    fn round_trips_and_rotates() {
        let old = SecretBox::new([("k1", K1)]).unwrap();
        let sealed = old.encrypt(b"seed").unwrap();
        assert_eq!(sealed.key_id, "k1");
        let rotated = SecretBox::new([("k2", K2), ("k1", K1)]).unwrap();
        assert_eq!(rotated.decrypt(&sealed).unwrap(), b"seed");
        assert_eq!(rotated.encrypt(b"x").unwrap().key_id, "k2");
    }

    #[test]
    fn rejects_tampering_and_unknown_keys() {
        let sealed = SecretBox::new([("k1", K1)])
            .unwrap()
            .encrypt(b"seed")
            .unwrap();
        let other = SecretBox::new([("k2", K2)]).unwrap();
        assert_eq!(
            other.decrypt(&sealed),
            Err(EncryptionError::UnknownKey("k1".into()))
        );
        let mut tampered = sealed.clone();
        tampered.ciphertext = STANDARD.encode(b"garbagegarbagegarbage");
        assert_eq!(
            SecretBox::new([("k1", K1)]).unwrap().decrypt(&tampered),
            Err(EncryptionError::Decrypt)
        );
        assert!(matches!(
            SecretBox::new([("bad", "short")]),
            Err(EncryptionError::InvalidKey(_))
        ));
        assert_eq!(
            SecretBox::new([]).unwrap().encrypt(b"x"),
            Err(EncryptionError::NoKey)
        );
    }
}
