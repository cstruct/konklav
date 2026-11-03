//! Applying each kind of record: resolving how it names others, comparing
//! it with what is stored, and writing it through the shared import
//! functions when it is new.

use chrono::{DateTime, Utc};
use konklav_authn::PasswordCheck;
use konklav_bootstrap::{
    AssignmentTarget, CredentialMaterial, FactorMaterial, Id, Kind, Located, MembershipRef,
    SubjectRef, TenantRef,
};
use konklav_core::{CredentialId, MembershipId, SubjectId, TenantId};
use konklav_store::Connection;
use konklav_store::catalog::{CatalogDocument, FactTarget};
use konklav_store::credentials::{
    self, CredentialData, CredentialKind, FederatedData, NewCredential, PasswordData,
    SecretKeyData, SecretSlotData,
};
use konklav_store::mfa::{self, FactorData};
use konklav_store::roles::{self, RoleDefinition};
use konklav_store::subjects::{self, SubjectKind, SubjectState};
use konklav_store::{StoreError, memberships, templates, tenants};

use diesel_async::AsyncConnection;

use super::{Context, catalog as catalogs};
use crate::error::{ApiError, ErrorCode};
use crate::import::{self, Outcome};
use crate::subject_api;

fn conflict(message: impl Into<String>) -> ApiError {
    ApiError::new(ErrorCode::Conflict, message)
}

fn invalid(message: impl Into<String>) -> ApiError {
    ApiError::invalid_request(message)
}

impl Context<'_> {
    fn uuid(&self, id: &Id, kind: Kind) -> Result<uuid::Uuid, ApiError> {
        id.resolve(self.namespace, kind).ok_or_else(|| {
            invalid(format!(
                "`{id}` is an external id, but no id_namespace is declared"
            ))
        })
    }

    fn tenant(&self, tenant: &TenantRef) -> Result<TenantId, ApiError> {
        match tenant {
            TenantRef::Root => Ok(tenants::ROOT),
            TenantRef::Id(id) => Ok(self.uuid(id, Kind::Tenant)?.into()),
        }
    }

    /// The subject a record names. A login identifier finds the subject
    /// with an active credential for it, or else a new subject, which the
    /// set must give a credential for so the next run finds it again.
    // r[impl bootstrap.ids]
    async fn subject(
        &mut self,
        conn: &mut Connection,
        subject: &SubjectRef,
    ) -> Result<SubjectId, ApiError> {
        let identifier = match subject {
            SubjectRef::Id(id) => return Ok(self.uuid(id, Kind::Subject)?.into()),
            SubjectRef::Identifier(identifier) => credentials::normalize_identifier(identifier),
        };
        if let Some(found) = self.subjects.get(&identifier) {
            return Ok(*found);
        }
        for kind in [
            CredentialKind::Password,
            CredentialKind::EmailLink,
            CredentialKind::PhoneOtp,
            CredentialKind::SecretKey,
        ] {
            if let Some(credential) = credentials::find_active(conn, kind, &identifier).await? {
                self.subjects.insert(identifier, credential.subject_id);
                return Ok(credential.subject_id);
            }
        }
        if !self.identifiers.contains(&identifier) {
            return Err(invalid(format!(
                "no subject has the login identifier `{identifier}`, and the set gives none a \
                 credential for it"
            )));
        }
        let created = SubjectId::new_v7();
        self.subjects.insert(identifier, created);
        Ok(created)
    }

    async fn membership(
        &mut self,
        conn: &mut Connection,
        membership: &MembershipRef,
    ) -> Result<MembershipId, ApiError> {
        match membership {
            MembershipRef::Id(id) => Ok(self.uuid(id, Kind::Membership)?.into()),
            MembershipRef::Of { subject, tenant } => {
                let subject = self.subject(conn, subject).await?;
                let tenant = self.tenant(tenant)?;
                memberships::find_active(conn, subject, tenant)
                    .await?
                    .map(|m| m.id)
                    .ok_or_else(|| invalid("the subject has no active membership in the tenant"))
            }
        }
    }
}

fn policies(policies: &[konklav_bootstrap::Policy]) -> Vec<konklav_authz::Policy> {
    policies
        .iter()
        .map(|p| konklav_authz::Policy {
            action: p.action.clone(),
            effect: match p.effect {
                konklav_bootstrap::Effect::Allow => konklav_authz::Effect::Allow,
                konklav_bootstrap::Effect::Deny => konklav_authz::Effect::Deny,
            },
            scope_bound: p.scope_bound,
        })
        .collect()
}

pub(super) async fn catalog(
    conn: &mut Connection,
    catalog: &Located<serde_json::Value>,
) -> Result<Outcome, ApiError> {
    let set: CatalogDocument = serde_json::from_value(catalog.value.clone())
        .map_err(|error| invalid(format!("the catalog is not a catalog document: {error}")))?;
    let stored = konklav_store::catalog::load(conn).await?;
    let merged = catalogs::merge(&stored, &set).map_err(conflict)?;
    if merged == stored {
        return Ok(Outcome::Skipped);
    }
    import::replace_catalog(conn, &merged).await?;
    Ok(if stored == CatalogDocument::default() {
        Outcome::Created
    } else {
        Outcome::Updated
    })
}

// r[impl bootstrap.metadata]
pub(super) async fn template(
    conn: &mut Connection,
    template: &Located<konklav_bootstrap::Template>,
) -> Result<Outcome, ApiError> {
    let wanted = &template.value;
    let policies = policies(&wanted.policies);
    match templates::get(conn, &wanted.key).await {
        Ok(existing)
            if existing.description == wanted.description
                && existing.metadata == wanted.metadata
                && existing.policies == policies =>
        {
            Ok(Outcome::Skipped)
        }
        Ok(_) => Err(conflict(format!(
            "template `{}` exists with another description, metadata or policies",
            wanted.key
        ))),
        Err(StoreError::NotFound) => {
            import::put_template(
                conn,
                &wanted.key,
                &wanted.description,
                &wanted.metadata,
                &policies,
            )
            .await?;
            Ok(Outcome::Created)
        }
        Err(error) => Err(error.into()),
    }
}

pub(super) async fn tenant(
    conn: &mut Connection,
    context: &Context<'_>,
    catalog: &CatalogDocument,
    tenant: &Located<konklav_bootstrap::Tenant>,
) -> Result<Outcome, ApiError> {
    let id: TenantId = context.uuid(&tenant.value.id, Kind::Tenant)?.into();
    let parent = context.tenant(&tenant.value.parent)?;
    let facts =
        catalogs::typed_facts(catalog, FactTarget::Tenant, &tenant.value.facts).map_err(invalid)?;
    let (existing, created) =
        import::create_tenant(conn, id, parent, &facts, &tenant.value.templates).await?;
    if created {
        Ok(Outcome::Created)
    } else if existing.parent_id == Some(parent) && existing.facts == facts {
        Ok(Outcome::Skipped)
    } else {
        Err(conflict(format!(
            "tenant {id} exists with another parent or other facts"
        )))
    }
}

// r[impl bootstrap.metadata]
pub(super) async fn role(
    conn: &mut Connection,
    context: &Context<'_>,
    role: &Located<konklav_bootstrap::Role>,
) -> Result<Outcome, ApiError> {
    let wanted = &role.value;
    let tenant = context.tenant(&wanted.tenant)?;
    let policies = policies(&wanted.policies);
    match roles::get(conn, tenant, &wanted.key).await {
        Ok(existing)
            if existing.template == wanted.template
                && existing.priority == wanted.priority
                && existing.metadata == wanted.metadata
                && existing.policies == policies =>
        {
            Ok(Outcome::Skipped)
        }
        Ok(_) => Err(conflict(format!(
            "role `{}` exists with another definition",
            wanted.key
        ))),
        Err(StoreError::NotFound) => {
            tenants::get(conn, tenant)
                .await
                .map_err(import::not_found_as("tenant"))?;
            let definition = RoleDefinition {
                template: wanted.template.clone(),
                priority: wanted.priority,
                metadata: wanted.metadata.clone(),
                policies,
            };
            roles::put(conn, tenant, &wanted.key, &definition).await?;
            Ok(Outcome::Created)
        }
        Err(error) => Err(error.into()),
    }
}

pub(super) async fn subject(
    conn: &mut Connection,
    context: &mut Context<'_>,
    subject: &Located<konklav_bootstrap::Subject>,
) -> Result<Outcome, ApiError> {
    let id = context.subject(conn, &subject.value.key).await?;
    let kind = match subject.value.kind {
        konklav_bootstrap::SubjectKind::Human => SubjectKind::Human,
        konklav_bootstrap::SubjectKind::Service => SubjectKind::Service,
    };
    let state = match subject.value.state {
        konklav_bootstrap::SubjectState::Active => SubjectState::Active,
        konklav_bootstrap::SubjectState::Disabled => SubjectState::Disabled,
    };
    conn.transaction::<_, ApiError, _>(async |conn| {
        let (existing, created) = subjects::create(conn, id, kind).await?;
        if created {
            if state != SubjectState::Active {
                subjects::set_state(conn, id, state).await?;
            }
            Ok(Outcome::Created)
        } else if existing.state == state {
            Ok(Outcome::Skipped)
        } else {
            Err(conflict(format!(
                "subject {id} exists as {}",
                existing.state.as_str()
            )))
        }
    })
    .await
}

fn slot(slot: &konklav_bootstrap::SecretSlot) -> Result<SecretSlotData, ApiError> {
    let time = |text: &str| {
        DateTime::parse_from_rfc3339(text)
            .map(|t| t.with_timezone(&Utc))
            .map_err(|_| invalid(format!("`{text}` is not an RFC 3339 time")))
    };
    Ok(SecretSlotData {
        hash: slot.hash.clone(),
        created_at: time(&slot.created_at)?,
        expires_at: slot.expires_at.as_deref().map(time).transpose()?,
    })
}

/// The stored identifier and data for a credential, hashing a plaintext
/// password when the run allows it.
// r[impl bootstrap.secrets]
fn material(
    context: &Context<'_>,
    credential: &konklav_bootstrap::Credential,
) -> Result<(String, CredentialData), ApiError> {
    let identifier = || {
        credential
            .identifier
            .clone()
            .ok_or_else(|| invalid("the credential has no identifier"))
    };
    Ok(match &credential.material {
        CredentialMaterial::PasswordHash(hash) => {
            if !hash.starts_with("$argon2") {
                return Err(invalid("password hashes must be Argon2 PHC strings"));
            }
            (
                identifier()?,
                CredentialData::Password(PasswordData { hash: hash.clone() }),
            )
        }
        CredentialMaterial::Password(password) => {
            if !context.options.allow_plaintext_passwords {
                return Err(invalid(
                    "plaintext passwords need --allow-plaintext-passwords; give password_hash",
                ));
            }
            (
                identifier()?,
                CredentialData::Password(PasswordData {
                    hash: context.hasher.hash(password),
                }),
            )
        }
        CredentialMaterial::SecretKey { a, b } => (
            identifier()?,
            CredentialData::SecretKey(SecretKeyData {
                a: slot(a)?,
                b: slot(b)?,
            }),
        ),
        CredentialMaterial::EmailLink => (identifier()?, CredentialData::EmailLink),
        CredentialMaterial::PhoneOtp => (identifier()?, CredentialData::PhoneOtp),
        CredentialMaterial::Federated { provider, subject } => (
            credentials::federated_identifier(provider, subject),
            CredentialData::Federated(FederatedData {
                provider: provider.clone(),
                subject: subject.clone(),
                email: None,
                email_verified: None,
            }),
        ),
    })
}

/// Whether a stored credential is the one the set describes. A plaintext
/// password matches a stored hash it verifies against.
fn same_credential(
    context: &Context<'_>,
    existing: &credentials::Credential,
    wanted: &konklav_bootstrap::Credential,
    subject: SubjectId,
    identifier: &str,
    data: &CredentialData,
) -> bool {
    let same_data = match (&wanted.material, &existing.data) {
        (CredentialMaterial::Password(password), CredentialData::Password(stored)) => matches!(
            context.hasher.verify(password, &stored.hash),
            PasswordCheck::Match { .. }
        ),
        _ => existing.data == *data,
    };
    existing.subject_id == subject
        && existing.identifier == credentials::normalize_identifier(identifier)
        && existing.mfa_factors_required == wanted.mfa_factors_required
        && existing.session_flags == wanted.session_flags
        && same_data
}

pub(super) async fn credential(
    conn: &mut Connection,
    context: &mut Context<'_>,
    credential: &Located<konklav_bootstrap::Credential>,
) -> Result<Outcome, ApiError> {
    let wanted = &credential.value;
    let subject = context.subject(conn, &wanted.subject).await?;
    let (identifier, data) = material(context, wanted)?;
    let context = &*context;
    conn.transaction::<_, ApiError, _>(async |conn| {
        subjects::get(conn, subject)
            .await
            .map_err(import::not_found_as("subject"))?;
        let existing = match &wanted.id {
            Some(id) => {
                let id: CredentialId = context.uuid(id, Kind::Credential)?.into();
                match credentials::get(conn, id).await {
                    Ok(existing) => Some(existing),
                    Err(StoreError::NotFound) => None,
                    Err(error) => return Err(error.into()),
                }
            }
            // Without an id, the credential is the active one of its kind
            // for its login identifier.
            None => credentials::find_active(conn, data.kind(), &identifier).await?,
        };
        if let Some(existing) = existing {
            if same_credential(context, &existing, wanted, subject, &identifier, &data) {
                return Ok(Outcome::Skipped);
            }
            // r[impl import.credentials.secret-key-rotation]
            if existing.subject_id == subject
                && existing.is_active()
                && matches!(
                    (&existing.data, &data),
                    (CredentialData::SecretKey(_), CredentialData::SecretKey(_))
                )
            {
                credentials::set_data(conn, existing.id, &data).await?;
                return Ok(Outcome::Updated);
            }
            return Err(conflict(format!(
                "credential {} exists with another subject, identifier or secret",
                existing.id
            )));
        }
        let id = match &wanted.id {
            Some(id) => context.uuid(id, Kind::Credential)?.into(),
            None => CredentialId::new_v7(),
        };
        credentials::insert(
            conn,
            NewCredential {
                id,
                subject_id: subject,
                identifier: identifier.clone(),
                data: data.clone(),
                mfa_factors_required: wanted.mfa_factors_required,
                replaces: None,
            },
        )
        .await?;
        if !wanted.session_flags.is_empty() {
            subject_api::check_credential_flags(conn, &wanted.session_flags).await?;
            credentials::set_session_flags(conn, id, &wanted.session_flags).await?;
        }
        Ok(Outcome::Created)
    })
    .await
}

pub(super) async fn factor(
    conn: &mut Connection,
    context: &mut Context<'_>,
    factor: &Located<konklav_bootstrap::Factor>,
) -> Result<Outcome, ApiError> {
    let wanted = &factor.value;
    let subject = context.subject(conn, &wanted.subject).await?;
    let id = match &wanted.id {
        Some(id) => context.uuid(id, Kind::MfaFactor)?,
        // Without an id, a factor is identified by its subject and position.
        None => uuid::Uuid::new_v5(
            &subject.into(),
            format!("{}:{}", Kind::MfaFactor.as_str(), wanted.position).as_bytes(),
        ),
    };
    let material = match &wanted.material {
        FactorMaterial::Totp { seed_base32 } => import::FactorMaterial::Totp {
            seed_base32: seed_base32.clone(),
        },
        FactorMaterial::EmailCode { email } => import::FactorMaterial::EmailCode {
            email: email.clone(),
        },
    };
    let context = &*context;
    conn.transaction::<_, ApiError, _>(async |conn| {
        subjects::get(conn, subject)
            .await
            .map_err(import::not_found_as("subject"))?;
        match mfa::get(conn, subject, id).await {
            Ok(existing) => {
                let same = match (&existing.data, &wanted.material) {
                    (FactorData::Totp(stored), FactorMaterial::Totp { seed_base32 }) => {
                        let stored = context
                            .secrets
                            .decrypt(&konklav_authn::EncryptedSecret {
                                key_id: stored.key_id.clone(),
                                nonce: stored.nonce.clone(),
                                ciphertext: stored.ciphertext.clone(),
                            })
                            .map_err(|e| invalid(e.to_string()))?;
                        import::decode_base32(seed_base32).as_deref() == Some(stored.as_slice())
                    }
                    (FactorData::EmailCode(stored), FactorMaterial::EmailCode { email }) => {
                        stored.email == *email
                    }
                    _ => false,
                };
                if same && existing.active == wanted.active {
                    Ok(Outcome::Skipped)
                } else {
                    Err(conflict(format!(
                        "MFA factor {id} exists with another secret"
                    )))
                }
            }
            Err(StoreError::NotFound) => {
                let data = import::seal_factor(context.secrets, id, material)?;
                match import::factor(conn, id, subject, &data, wanted.active).await? {
                    Outcome::Created => Ok(Outcome::Created),
                    _ => Err(conflict(format!(
                        "MFA factor {id} belongs to another subject"
                    ))),
                }
            }
            Err(error) => Err(error.into()),
        }
    })
    .await
}

pub(super) async fn membership(
    conn: &mut Connection,
    context: &mut Context<'_>,
    catalog: &CatalogDocument,
    membership: &Located<konklav_bootstrap::Membership>,
) -> Result<Outcome, ApiError> {
    let wanted = &membership.value;
    let subject = context.subject(conn, &wanted.subject).await?;
    let tenant = context.tenant(&wanted.tenant)?;
    let facts =
        catalogs::typed_facts(catalog, FactTarget::Membership, &wanted.facts).map_err(invalid)?;
    let context = &*context;
    conn.transaction::<_, ApiError, _>(async |conn| {
        let id = match &wanted.id {
            Some(id) => context.uuid(id, Kind::Membership)?.into(),
            None => match memberships::find_active(conn, subject, tenant).await? {
                Some(existing) if existing.facts == facts => return Ok(Outcome::Skipped),
                Some(existing) => {
                    return Err(conflict(format!(
                        "membership {} exists with other facts",
                        existing.id
                    )));
                }
                None => MembershipId::new_v7(),
            },
        };
        let (existing, created) =
            import::create_membership(conn, id, subject, tenant, &facts).await?;
        if created {
            Ok(Outcome::Created)
        } else if existing.facts == facts {
            Ok(Outcome::Skipped)
        } else {
            Err(conflict(format!("membership {id} exists with other facts")))
        }
    })
    .await
}

pub(super) async fn assignment(
    conn: &mut Connection,
    context: &mut Context<'_>,
    assignment: &Located<konklav_bootstrap::Assignment>,
) -> Result<Outcome, ApiError> {
    let wanted = &assignment.value;
    let scope = wanted
        .scope
        .as_ref()
        .map(|(kind, id)| konklav_authz::Scope {
            kind: kind.clone(),
            id: id.clone(),
        });
    match &wanted.target {
        AssignmentTarget::Membership(membership) => {
            let membership = context.membership(conn, membership).await?;
            conn.transaction::<_, ApiError, _>(async |conn| {
                let found = memberships::get(conn, membership)
                    .await
                    .map_err(import::not_found_as("membership"))?;
                let role = roles::get(conn, found.tenant_id, &wanted.role)
                    .await
                    .map_err(import::not_found_as("role"))?;
                let held = roles::assignments_of_membership(conn, membership).await?;
                if held
                    .iter()
                    .any(|a| a.role_id == role.id && a.scope == scope)
                {
                    return Ok(Outcome::Skipped);
                }
                import::assign_membership_role(
                    conn,
                    None,
                    membership,
                    &wanted.role,
                    scope.as_ref(),
                )
                .await?;
                Ok(Outcome::Created)
            })
            .await
        }
        AssignmentTarget::Global(subject) => {
            let subject = context.subject(conn, subject).await?;
            conn.transaction::<_, ApiError, _>(async |conn| {
                let role = roles::get(conn, tenants::ROOT, &wanted.role)
                    .await
                    .map_err(import::not_found_as("global role"))?;
                let held = roles::global_assignments_of(conn, subject).await?;
                if held.iter().any(|a| a.role_id == role.id) {
                    return Ok(Outcome::Skipped);
                }
                import::assign_global_role(conn, None, subject, &role).await?;
                Ok(Outcome::Created)
            })
            .await
        }
    }
}

/// Sessions change as they are used, so one that exists is skipped
/// whatever it looks like now.
pub(super) async fn session(
    conn: &mut Connection,
    context: &mut Context<'_>,
    session: &Located<konklav_bootstrap::Session>,
) -> Result<Outcome, ApiError> {
    let s = &session.value;
    let optional = |id: &Option<Id>, kind| id.as_ref().map(|id| context.uuid(id, kind)).transpose();
    let record = serde_json::json!({
        "id": context.uuid(&s.id, Kind::Session)?,
        "subject": context.uuid(&s.subject, Kind::Subject)?,
        "credential": context.uuid(&s.credential, Kind::Credential)?,
        "tenant": optional(&s.tenant, Kind::Tenant)?,
        "membership": optional(&s.membership, Kind::Membership)?,
        "stage": s.stage,
        "client_kind": s.client_kind.as_deref().unwrap_or("native"),
        "amr": s.amr,
        "flags": s.flags,
        "impersonator": optional(&s.impersonator, Kind::Subject)?,
        "auth_time": s.auth_time,
        "version": s.version,
        "refresh_hash": s.refresh_hash,
        "expires_at": s.expires_at,
        "revoked_at": s.revoked_at,
    });
    let record: import::SessionRecord =
        serde_json::from_value(record).map_err(|error| invalid(error.to_string()))?;
    conn.transaction::<_, ApiError, _>(async |conn| import::session(conn, record).await)
        .await
}
