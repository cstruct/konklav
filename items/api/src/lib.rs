//! Transport types of Konklav's HTTP surfaces: the request and response
//! bodies the server and its clients share, each with an `OpenAPI` schema.
//!
//! Only the control-plane surface's tenant, membership, subject, credential,
//! session and signing-key routes are here so far. The server converts its
//! storage models to these types at the boundary, so a storage change can't
//! change the API by accident.

// r[impl item.api.transport-only]
// r[impl item.api.both-directions]
// r[impl item.api.schemas]
mod authz;
mod credentials;
mod error;
mod keys;
mod sessions;
mod subjects;
mod tenancy;
mod written;

pub use authz::{AssignmentTarget, RoleAssignment, Scope};
pub use credentials::{
    BreakGlass, CreateCredential, CreatedCredential, Credential, CredentialKind, Passkey,
    ReplacePassword, RevokeCredential, RotateSlot, RotatedSlot, SecretKeySlot, SecretKeySlots,
    SecretKeys, SecretSlot, SessionFlags,
};
pub use error::{ErrorBody, ErrorCode, ErrorResponse};
pub use keys::{RevokedKey, SigningKey};
pub use sessions::{
    ClientKind, RequestedClaims, RevokeSessions, RevokedSessions, Session, SessionFilter,
    SessionPage, SessionQuery, SessionStage,
};
pub use subjects::{
    CreateSubject, Subject, SubjectDetail, SubjectKind, SubjectPage, SubjectQuery, SubjectState,
};
pub use tenancy::{
    CreateMembership, CreateTenant, Membership, MembershipDetail, MembershipQuery, MembershipState,
    SetTenantState, Tenant, TenantPage, TenantQuery, TenantState,
};
pub use written::Written;
