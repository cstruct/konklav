use std::collections::BTreeMap;

use aes_gcm::aead::{Aead, KeyInit, Payload};
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
    /// Base64 of the AES-256-GCM ciphertext and tag. After
    /// [`BOUND_PREFIX`], the secret is bound: it was encrypted with
    /// associated data naming its owner.
    pub ciphertext: String,
}

/// What the `ciphertext` of a bound secret starts with. No base64 text
/// holds a colon, so an unbound ciphertext never starts with it.
const BOUND_PREFIX: &str = "b1:";

impl EncryptedSecret {
    /// Whether the secret was encrypted for one owner, with
    /// [`SecretBox::encrypt_bound`].
    #[must_use]
    pub fn is_bound(&self) -> bool {
        self.ciphertext.starts_with(BOUND_PREFIX)
    }
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

    /// Encrypts `plaintext` with the current key, bound to nothing: anyone
    /// who can move the result to another record moves the secret with it.
    /// Prefer [`Self::encrypt_bound`] for a secret that belongs to a record.
    ///
    /// # Panics
    ///
    /// Panics if the operating system cannot provide randomness.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedSecret, EncryptionError> {
        self.seal(plaintext, None)
    }

    /// Encrypts `plaintext` with the current key for the owner `binding`
    /// names, such as the record it is stored on, which must not be empty.
    /// It decrypts only with [`Self::decrypt_bound`] and the same binding.
    ///
    /// # Panics
    ///
    /// Panics if the operating system cannot provide randomness.
    // r[impl credential.mfa-seed.bound]
    pub fn encrypt_bound(
        &self,
        binding: &[u8],
        plaintext: &[u8],
    ) -> Result<EncryptedSecret, EncryptionError> {
        self.seal(plaintext, Some(binding))
    }

    fn seal(
        &self,
        plaintext: &[u8],
        binding: Option<&[u8]>,
    ) -> Result<EncryptedSecret, EncryptionError> {
        let id = self.current.as_ref().ok_or(EncryptionError::NoKey)?;
        let cipher = &self.keys[id];
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce).expect("system randomness");
        let payload = Payload {
            msg: plaintext,
            aad: binding.unwrap_or_default(),
        };
        let ciphertext = cipher
            .encrypt(&Nonce::from(nonce), payload)
            .map_err(|_| EncryptionError::Decrypt)?;
        let prefix = if binding.is_some() { BOUND_PREFIX } else { "" };
        Ok(EncryptedSecret {
            key_id: id.clone(),
            nonce: STANDARD.encode(nonce),
            ciphertext: format!("{prefix}{}", STANDARD.encode(ciphertext)),
        })
    }

    /// Decrypts a secret that isn't bound. A bound one is refused: it needs
    /// [`Self::decrypt_bound`].
    pub fn decrypt(&self, secret: &EncryptedSecret) -> Result<Vec<u8>, EncryptionError> {
        if secret.is_bound() {
            return Err(EncryptionError::Decrypt);
        }
        self.open(secret, &secret.ciphertext, &[])
    }

    /// Decrypts a secret stored for the owner `binding` names. A bound
    /// secret decrypts only for the owner it was encrypted for, and is
    /// never tried without its binding. A secret that isn't bound, from
    /// before secrets were, decrypts for any owner.
    // r[impl credential.mfa-seed.bound]
    pub fn decrypt_bound(
        &self,
        binding: &[u8],
        secret: &EncryptedSecret,
    ) -> Result<Vec<u8>, EncryptionError> {
        match secret.ciphertext.strip_prefix(BOUND_PREFIX) {
            Some(ciphertext) => self.open(secret, ciphertext, binding),
            None => self.open(secret, &secret.ciphertext, &[]),
        }
    }

    fn open(
        &self,
        secret: &EncryptedSecret,
        ciphertext: &str,
        aad: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
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
            .decode(ciphertext)
            .map_err(|_| EncryptionError::Decrypt)?;
        let payload = Payload {
            msg: ciphertext.as_slice(),
            aad,
        };
        cipher
            .decrypt(&Nonce::from(nonce), payload)
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

    // r[verify credential.mfa-seed.bound]
    #[test]
    fn a_bound_secret_decrypts_only_for_its_owner() {
        let secrets = SecretBox::new([("k1", K1)]).unwrap();
        let sealed = secrets.encrypt_bound(b"factor-1", b"seed").unwrap();
        assert!(sealed.is_bound());
        assert_eq!(
            secrets.decrypt_bound(b"factor-1", &sealed).unwrap(),
            b"seed"
        );
        // Moved to another owner, it stays shut.
        assert_eq!(
            secrets.decrypt_bound(b"factor-2", &sealed),
            Err(EncryptionError::Decrypt)
        );
        assert_eq!(secrets.decrypt(&sealed), Err(EncryptionError::Decrypt));

        // Stripping the mark doesn't open it as an unbound secret.
        let mut stripped = sealed.clone();
        stripped.ciphertext = sealed.ciphertext[BOUND_PREFIX.len()..].to_owned();
        assert!(!stripped.is_bound());
        for binding in [&b"factor-1"[..], b"factor-2", b""] {
            assert_eq!(
                secrets.decrypt_bound(binding, &stripped),
                Err(EncryptionError::Decrypt)
            );
        }
        assert_eq!(secrets.decrypt(&stripped), Err(EncryptionError::Decrypt));

        // Nor does marking an unbound secret bind it to anyone.
        let unbound = secrets.encrypt(b"seed").unwrap();
        let mut marked = unbound.clone();
        marked.ciphertext = format!("{BOUND_PREFIX}{}", unbound.ciphertext);
        assert_eq!(
            secrets.decrypt_bound(b"factor-1", &marked),
            Err(EncryptionError::Decrypt)
        );
    }

    #[test]
    fn secrets_from_before_binding_still_decrypt() {
        let secrets = SecretBox::new([("k1", K1)]).unwrap();
        let old = secrets.encrypt(b"seed").unwrap();
        assert!(!old.is_bound());
        assert_eq!(secrets.decrypt(&old).unwrap(), b"seed");
        assert_eq!(secrets.decrypt_bound(b"factor-1", &old).unwrap(), b"seed");
    }
}
