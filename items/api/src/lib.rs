//! Transport types of Konklav's HTTP surfaces: the request and response
//! bodies the server and its clients share, each with an `OpenAPI` schema.
//!
//! Only the control-plane surface is here so far. The server converts its
//! storage models to these types at the boundary, so a storage change can't
//! change the API by accident. Authorization's wire types, which relying
//! systems read too, are `konklav-authz`'s own and are re-exported here.

// r[impl item.api.transport-only]
// r[impl item.api.both-directions]
// r[impl item.api.schemas]
mod authz;
mod batch;
mod catalog;
mod credentials;
mod error;
mod explain;
mod import;
mod invites;
mod keys;
mod oidc_clients;
mod registered_scopes;
mod roles;
mod sessions;
mod shares;
mod subjects;
mod templates;
mod tenancy;
mod written;

pub use authz::{AssignRole, AssignmentTarget, EntitlementQuery, RoleAssignment};
pub use batch::{Batch, BatchMethod, BatchOperation, BatchResult, BatchResults};
pub use catalog::{
    ActionEntry, CatalogDocument, FactEntry, FactTarget, FactType, FlagKind, GroupEntry,
    ScopeKindEntry, SessionFlagEntry,
};
pub use credentials::{
    BreakGlass, CreateCredential, CreatedCredential, Credential, CredentialKind, Passkey,
    ReplacePassword, RevokeCredential, RotateSlot, RotatedSlot, SecretKeySlot, SecretKeySlots,
    SecretKeys, SecretSlot, SessionFlags, SlotExpiry,
};
pub use error::{ErrorBody, ErrorCode, ErrorResponse};
pub use explain::{ExplainDecision, ExplainQuery};
pub use import::{
    ImportCredentials, ImportFactors, ImportSessions, ImportSubjects, Imported, ImportedCredential,
    ImportedCredentialMaterial, ImportedFactor, ImportedFactorMaterial, ImportedSecretSlot,
    ImportedSession, ImportedSubject,
};
pub use invites::{CreateInvite, CreatedInvite, Invite, InviteState};
pub use keys::{RevokedKey, SigningKey};
pub use konklav_authz::{
    ActionExplanation, Check, Contribution, Decision, DecisionExplanation, DenyReason, Effect,
    Entitlements, Explanation, Group, Obligation, Policy, Reason, Requirements, Scope,
    ScopeRequirement, Shared, StepUp,
};
pub use oidc_clients::{
    IdTokenAlgorithm, OidcClient, OidcClientDefinition, OidcClientKind, OidcClientSecret,
};
pub use registered_scopes::{
    RecordRegisteredScope, RegisteredScope, RegisteredScopeBatch, RegisteredScopeChange,
    RegisteredScopeChanges, RegisteredScopeState,
};
pub use roles::{Deleted, PutRole, Role};
pub use sessions::{
    ClientKind, RequestedClaims, RevokeSessions, RevokedSessions, Session, SessionFilter,
    SessionPage, SessionQuery, SessionStage,
};
pub use shares::{RevokeShare, Share, ShareList, ShareQuery, ShareSide, ShareState, ShareTerms};
pub use subjects::{
    CreateSubject, MfaFactor, MfaFactorKind, Subject, SubjectDetail, SubjectKind, SubjectPage,
    SubjectQuery, SubjectState,
};
pub use templates::{PutTemplate, Template};
pub use tenancy::{
    CreateMembership, CreateTenant, Membership, MembershipDetail, MembershipQuery, MembershipState,
    SetTenantState, Tenant, TenantPage, TenantQuery, TenantState,
};
pub use written::Written;
