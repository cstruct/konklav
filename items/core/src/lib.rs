//! Identifiers and small value types shared across Konklav software items.
//!
//! Keep this crate tiny: only types that several software items need to agree
//! on belong here.

mod cursor;
pub mod feed;
mod id;

pub use cursor::Cursor;
pub use id::{CredentialId, MembershipId, SessionId, ShareId, SubjectId, TenantId};
