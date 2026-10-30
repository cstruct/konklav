//! Signing keys: loading private keys from PEM files, syncing published
//! public keys to the database, and serving JWKS.

use std::path::Path;

use axum::Json;
use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{SigningKey, VerifyingKey};
use konklav_store::signing_keys::{self, SigningKey as StoredKey};
use konklav_token::{Jwk, JwkSet, Signer};

use crate::AppState;
use crate::error::ApiError;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("cannot read signing key {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("{path} is not an unencrypted PKCS#8 PEM Ed25519 private key")]
    Decode { path: String },
}

/// Reads an unencrypted PKCS#8 PEM Ed25519 private key.
// r[impl token.keys.private-material]
pub fn read_signing_key(path: &Path) -> Result<SigningKey, KeyError> {
    let pem = std::fs::read_to_string(path).map_err(|source| KeyError::Read {
        path: path.display().to_string(),
        source,
    })?;
    SigningKey::from_pkcs8_pem(&pem).map_err(|_| KeyError::Decode {
        path: path.display().to_string(),
    })
}

/// The keys from configuration: the signer and every key to publish
/// (including the signer's).
pub struct ConfiguredKeys {
    pub signer: Signer,
    pub published: Vec<VerifyingKey>,
}

impl ConfiguredKeys {
    pub fn load(
        signing_key_file: &Path,
        published_key_files: &[impl AsRef<Path>],
    ) -> Result<Self, KeyError> {
        let signer = Signer::new(read_signing_key(signing_key_file)?);
        let mut published = vec![signer.verifying_key()];
        for file in published_key_files {
            published.push(read_signing_key(file.as_ref())?.verifying_key());
        }
        Ok(Self { signer, published })
    }

    /// Records the configured keys in the database: publishes them,
    /// activates the signer and retires previously active keys.
    pub async fn sync(
        &self,
        conn: &mut konklav_store::Connection,
    ) -> Result<(), konklav_store::StoreError> {
        let published = self
            .published
            .iter()
            .map(|key| (konklav_token::kid_for(key), key.as_bytes().to_vec()))
            .collect::<Vec<_>>();
        let keys = signing_keys::sync_configured(conn, &published, self.signer.kid()).await?;
        if !keys
            .iter()
            .any(|key| key.kid == self.signer.kid() && key.is_active())
        {
            tracing::error!(
                kid = self.signer.kid(),
                "the configured signing key is revoked; token issuance is blocked"
            );
        }
        Ok(())
    }
}

/// Whether a stored key should still be published: not revoked, and either
/// unretired or retired so recently that tokens it signed may be unexpired.
#[must_use]
pub fn is_publishable(key: &StoredKey, now: DateTime<Utc>, max_token_ttl: Duration) -> bool {
    key.revoked_at.is_none()
        && key
            .retired_at
            .is_none_or(|retired| retired + max_token_ttl > now)
}

pub(crate) fn to_verifying_key(key: &StoredKey) -> Option<VerifyingKey> {
    let bytes: [u8; 32] = key.public_key.as_slice().try_into().ok()?;
    VerifyingKey::from_bytes(&bytes).ok()
}

/// The verification key for `kid`, if it is currently publishable.
pub async fn verifying_key(
    conn: &mut konklav_store::Connection,
    kid: &str,
    max_token_ttl: Duration,
) -> Result<Option<VerifyingKey>, ApiError> {
    let now = Utc::now();
    Ok(signing_keys::list(conn)
        .await?
        .iter()
        .find(|key| key.kid == kid && is_publishable(key, now, max_token_ttl))
        .and_then(to_verifying_key))
}

/// `GET /.well-known/jwks.json`
// r[impl token.keys.jwks]
pub async fn jwks(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    let mut conn = state.pool.get().await?;
    let now = Utc::now();
    let keys = signing_keys::list(&mut conn)
        .await?
        .iter()
        .filter(|key| is_publishable(key, now, state.auth.access_ttl))
        .filter_map(to_verifying_key)
        .map(|key| Jwk::from_verifying_key(&key))
        .chain(
            state
                .auth
                .oidc
                .iter()
                .flat_map(crate::oidc::OpenIdProvider::jwks),
        )
        .collect();
    Ok((
        [(header::CACHE_CONTROL, "public, max-age=60")],
        Json(JwkSet { keys }),
    ))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::pkcs8::EncodePrivateKey;

    use super::*;

    // r[verify token.keys.private-material]
    #[test]
    fn reads_pkcs8_pem_keys_and_rejects_anything_else() {
        let dir = std::env::temp_dir().join(format!("konklav-keys-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = SigningKey::from_bytes(&[7; 32]);
        let pem = key
            .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::default())
            .unwrap();
        let good = dir.join("good.pem");
        std::fs::write(&good, pem.as_bytes()).unwrap();
        assert_eq!(read_signing_key(&good).unwrap().to_bytes(), key.to_bytes());

        let bad = dir.join("bad.pem");
        std::fs::write(&bad, "not a key").unwrap();
        assert!(matches!(
            read_signing_key(&bad),
            Err(KeyError::Decode { .. })
        ));
        assert!(matches!(
            read_signing_key(&dir.join("missing.pem")),
            Err(KeyError::Read { .. })
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn retired_keys_stay_published_while_their_tokens_can_be_valid() {
        let now = Utc::now();
        let key = |retired: Option<DateTime<Utc>>, revoked: Option<DateTime<Utc>>| StoredKey {
            kid: "k".into(),
            algorithm: "EdDSA".into(),
            public_key: vec![0; 32],
            published_at: now,
            activated_at: Some(now),
            retired_at: retired,
            revoked_at: revoked,
        };
        let ttl = Duration::minutes(15);
        assert!(is_publishable(&key(None, None), now, ttl));
        assert!(is_publishable(
            &key(Some(now - Duration::minutes(10)), None),
            now,
            ttl
        ));
        assert!(!is_publishable(
            &key(Some(now - Duration::minutes(20)), None),
            now,
            ttl
        ));
        assert!(!is_publishable(&key(None, Some(now)), now, ttl));
    }
}
