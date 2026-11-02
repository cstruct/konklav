//! Writing imported records, shared by the import API, the control-plane
//! endpoints that create the same records, and the `bootstrap` command, so
//! every path applies the same checks.
//!
//! Functions take a connection and leave authorization and transactions to
//! their callers.

mod records;
mod tenancy;

pub(crate) use records::{
    CredentialMaterial, CredentialRecord, FactorMaterial, FactorRecord, SessionRecord, SlotRecord,
    SubjectRecord, credential, decode_base32, factor, seal_factor, session, subject,
};
pub(crate) use tenancy::{
    assign_global_role, assign_membership_role, create_membership, create_tenant, not_found_as,
    put_template, replace_catalog, validate_facts,
};

/// What writing one record did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Created,
    /// It existed already and was left alone.
    Skipped,
    /// It existed and was brought up to date (secret-key slots only).
    Updated,
}

impl Outcome {
    fn created_if(created: bool) -> Self {
        if created {
            Self::Created
        } else {
            Self::Skipped
        }
    }
}
