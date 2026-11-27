//! The Konklav operator CLI (`konklav`): sign-in to DPoP-bound sessions and
//! control-plane commands.
//!
//! The library holds what the binary is built from, so that tests drive the
//! same code against a real server.

// r[impl item.cli.independent]
pub mod error;
pub mod profile;
pub mod session;
pub mod store;

pub use error::{Error, Result};
pub use session::{Context, PasswordLogin, PendingMfa, Session, Surface};
