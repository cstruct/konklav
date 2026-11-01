//! Authentication primitives: password and secret-key hashing, and refresh
//! tokens. No I/O; persistence and orchestration live in the server and store.

mod challenge;
mod encryption;
mod password;
mod refresh;
mod secret;
mod totp;

pub use challenge::{generate_code, hash_challenge_secret};
pub use encryption::{EncryptedSecret, EncryptionError, SecretBox};
pub use password::{PasswordCheck, PasswordHasher};
pub use refresh::{RefreshToken, RefreshTokenError};
pub use secret::{SecretKey, generate_secret, parse_presented_secret_key};
pub use totp::{TotpSecret, verify_totp};
