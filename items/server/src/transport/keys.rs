//! Signing keys, without their key material.

use konklav_api as api;
use konklav_store::signing_keys::SigningKey;

pub(crate) fn signing_key(key: SigningKey) -> api::SigningKey {
    api::SigningKey {
        kid: key.kid,
        algorithm: key.algorithm,
        published_at: key.published_at,
        activated_at: key.activated_at,
        retired_at: key.retired_at,
        revoked_at: key.revoked_at,
    }
}
