use chrono::{DateTime, Utc};
use konklav_core::{CredentialId, SubjectId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    Password,
    SecretKey,
    /// Log in through a magic link sent to the identifier (an email address).
    EmailLink,
    /// Log in with a code sent to the identifier (an E.164 phone number).
    PhoneOtp,
    /// Log in through an identity provider.
    Federated,
    /// An OIDC client acting as a service principal (client credentials);
    /// the identifier is the client id.
    Client,
    /// A passkey; the identifier is its WebAuthn credential ID in unpadded
    /// base64url.
    PublicKey,
}

/// One of the two independently rotatable slots of a secret key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum SecretSlot {
    A,
    B,
}

/// One slot of a secret key, without its secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SecretKeySlot {
    pub created_at: DateTime<Utc>,
    #[schema(required)]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Both slots of a secret key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SecretKeySlots {
    pub a: SecretKeySlot,
    pub b: SecretKeySlot,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Passkey {
    pub label: String,
    #[schema(required)]
    pub last_used_at: Option<DateTime<Utc>>,
}

/// The account a federated credential stands for, as the identity provider
/// reported it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct FederatedIdentity {
    /// The configured provider id.
    pub provider: String,
    /// The provider's `sub`.
    pub subject: String,
    #[schema(required)]
    pub email: Option<String>,
    #[schema(required)]
    pub email_verified: Option<bool>,
}

/// A credential without any secret material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Credential {
    pub id: CredentialId,
    pub subject_id: SubjectId,
    pub kind: CredentialKind,
    pub identifier: String,
    pub mfa_factors_required: i16,
    /// For secret keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slots: Option<SecretKeySlots>,
    /// For passkeys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passkey: Option<Passkey>,
    /// For federated credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federated: Option<FederatedIdentity>,
    #[schema(required)]
    pub replaces: Option<CredentialId>,
    pub created_at: DateTime<Utc>,
    #[schema(required)]
    pub revoked_at: Option<DateTime<Utc>>,
    #[schema(required)]
    pub revoked_reason: Option<String>,
    pub break_glass: bool,
    pub session_flags: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CreateCredential {
    /// With either `password` or an Argon2id `password_hash`.
    #[schema(title = "CreateCredentialPassword")]
    Password {
        id: Option<CredentialId>,
        identifier: String,
        password: Option<String>,
        password_hash: Option<String>,
        #[serde(default)]
        mfa_factors_required: i16,
    },
    #[schema(title = "CreateCredentialSecretKey")]
    SecretKey {
        id: Option<CredentialId>,
        expires_at: Option<DateTime<Utc>>,
    },
    /// Log in with a magic link sent to `identifier`, an email address.
    #[schema(title = "CreateCredentialEmailLink")]
    EmailLink {
        id: Option<CredentialId>,
        identifier: String,
    },
    /// Log in with a code sent to `identifier`, an E.164 phone number.
    #[schema(title = "CreateCredentialPhoneOtp")]
    PhoneOtp {
        id: Option<CredentialId>,
        identifier: String,
    },
    /// A workload identity at an identity provider: tokens it issues for
    /// `subject` sign the service principal in with the JWT bearer grant.
    #[schema(title = "CreateCredentialFederated")]
    Federated {
        id: Option<CredentialId>,
        provider: String,
        subject: String,
    },
}

/// A new credential, with a secret key's secrets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreatedCredential {
    pub credential: Credential,
    /// For secret keys: both slots' `<key id>.<secret>`, shown only once.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_keys: Option<SecretKeys>,
}

/// Both slots' `<key id>.<secret>`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SecretKeys {
    pub a: String,
    pub b: String,
}

/// A secret key after one slot's rotation, with that slot's new secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RotatedSlot {
    pub credential: Credential,
    pub slot: SecretSlot,
    /// The slot's new `<key id>.<secret>`, shown only once.
    pub secret_key: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RevokeCredential {
    /// Recorded as the revocation reason; `revoked` when absent.
    pub reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ReplacePassword {
    pub password: String,
    /// The new credential's id; generated when absent.
    pub id: Option<CredentialId>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RotateSlot {
    pub expires_at: Option<DateTime<Utc>>,
}

/// A slot's new expiry, keeping its secret.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SlotExpiry {
    /// When the slot's secret stops working; `null` for never.
    #[schema(required)]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SessionFlags {
    pub session_flags: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct BreakGlass {
    pub break_glass: bool,
}
