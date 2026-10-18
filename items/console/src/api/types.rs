//! What Conclave returns, as far as the console reads it.
//!
//! These are transport DTOs owned by the console, not the server's models:
//! they keep only the fields the console shows, and documents the operator
//! edits as a whole (facts, policies, the catalog) stay JSON.

use serde::Deserialize;
use serde_json::Value;

/// An access token from login, MFA or refresh.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    /// `partial`, `identity` or `tenant`.
    pub token_kind: String,
    pub expires_in: i64,
    pub session_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Factor {
    pub id: String,
    /// `totp` or `email_code`.
    pub kind: String,
    pub active: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct OwnCapabilities {
    pub subject: String,
    pub capabilities: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Subject {
    pub id: String,
    /// `human` or `service`.
    pub kind: String,
    /// `active` or `disabled`.
    pub state: String,
    pub created_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct SubjectPage {
    pub subjects: Vec<Subject>,
    pub next: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct SubjectDetail {
    #[serde(flatten)]
    pub subject: Subject,
    pub credentials: Vec<Credential>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Slot {
    pub created_at: String,
    pub expires_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Slots {
    pub a: Slot,
    pub b: Slot,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Credential {
    pub id: String,
    pub subject_id: String,
    pub kind: String,
    pub identifier: String,
    pub mfa_factors_required: i16,
    #[serde(default)]
    pub slots: Option<Slots>,
    pub replaces: Option<String>,
    pub created_at: String,
    pub revoked_at: Option<String>,
    pub revoked_reason: Option<String>,
    pub break_glass: bool,
}

impl Credential {
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }

    /// Only active local passwords and secret keys can be break-glass
    /// credentials.
    #[must_use]
    pub fn can_be_break_glass(&self) -> bool {
        self.is_active() && matches!(self.kind.as_str(), "password" | "secret_key")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct SecretKeys {
    pub a: String,
    pub b: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct CreatedCredential {
    pub credential: Credential,
    #[serde(default)]
    pub secret_keys: Option<SecretKeys>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct RotatedSlot {
    pub slot: String,
    pub secret_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Session {
    pub id: String,
    pub subject_id: String,
    pub credential_id: String,
    pub tenant_id: Option<String>,
    pub membership_id: Option<String>,
    pub stage: String,
    pub client_kind: String,
    pub amr: Vec<String>,
    pub flags: Vec<String>,
    pub impersonator_subject_id: Option<String>,
    pub oidc_client_id: Option<String>,
    pub created_at: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
    pub revoked_reason: Option<String>,
}

impl Session {
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct SessionPage {
    pub sessions: Vec<Session>,
    pub next: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct RevokedSessions {
    pub revoked: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct Tenant {
    pub id: String,
    pub parent_id: Option<String>,
    /// `active`, `suspended` or `deleted`.
    pub state: String,
    pub facts: Value,
    pub created_at: String,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct TenantPage {
    pub tenants: Vec<Tenant>,
    pub next: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct Membership {
    pub id: String,
    pub subject_id: String,
    pub tenant_id: String,
    /// `active` or `ended`.
    pub state: String,
    pub facts: Value,
    pub managed_by: Option<String>,
    pub created_at: String,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct MembershipDetail {
    #[serde(flatten)]
    pub membership: Membership,
    pub assignments: Vec<Assignment>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct AssignmentTarget {
    /// `membership` or `subject`.
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Scope {
    pub kind: String,
    pub id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Assignment {
    pub id: String,
    pub role_id: String,
    pub target: AssignmentTarget,
    pub scope: Option<Scope>,
    pub managed_by: Option<String>,
    pub created_at: String,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct Role {
    pub id: String,
    pub tenant_id: String,
    pub key: String,
    pub template: Option<String>,
    pub priority: i32,
    pub metadata: Value,
    pub policies: Value,
    pub updated_at: String,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct Template {
    pub key: String,
    pub description: String,
    pub metadata: Value,
    pub policies: Value,
    pub updated_at: String,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct Entitlements {
    pub global: Vec<String>,
    pub tenant: Vec<String>,
    pub scoped: Vec<ScopedActions>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct ScopedActions {
    pub kind: String,
    pub id: String,
    pub actions: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Explanation {
    pub action: String,
    pub contributions: Vec<Contribution>,
    pub granted_at: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Contribution {
    pub assignment: String,
    pub level: String,
    pub policy: String,
    pub effect: String,
    pub priority: i32,
    pub from_template: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct SigningKey {
    pub kid: String,
    pub algorithm: String,
    pub published_at: String,
    pub activated_at: Option<String>,
    pub retired_at: Option<String>,
    pub revoked_at: Option<String>,
}

impl SigningKey {
    /// `active`, `published` (not yet signing), `retired` or `revoked`.
    #[must_use]
    pub fn status(&self) -> &'static str {
        if self.revoked_at.is_some() {
            "revoked"
        } else if self.retired_at.is_some() {
            "retired"
        } else if self.activated_at.is_some() {
            "active"
        } else {
            "published"
        }
    }
}

/// An OIDC client registration. `raw` keeps the whole registration so the
/// operator can edit its definition.
#[derive(Clone, Debug, PartialEq)]
pub struct OidcClient {
    pub id: String,
    pub kind: String,
    pub audience: String,
    pub redirect_uris: Vec<String>,
    pub has_secret: bool,
    pub disabled_at: Option<String>,
    pub raw: Value,
}

impl<'de> Deserialize<'de> for OidcClient {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Fields {
            id: String,
            kind: String,
            audience: String,
            #[serde(default)]
            redirect_uris: Vec<String>,
            #[serde(default)]
            has_secret: bool,
            disabled_at: Option<String>,
        }
        let raw = Value::deserialize(deserializer)?;
        let fields = Fields::deserialize(&raw).map_err(serde::de::Error::custom)?;
        Ok(Self {
            id: fields.id,
            kind: fields.kind,
            audience: fields.audience,
            redirect_uris: fields.redirect_uris,
            has_secret: fields.has_secret,
            disabled_at: fields.disabled_at,
            raw,
        })
    }
}

impl OidcClient {
    /// The registration as `PUT /v1/oidc/clients/{id}` takes it: without
    /// the fields Conclave keeps itself.
    #[must_use]
    pub fn definition(&self) -> Value {
        let mut definition = self.raw.clone();
        if let Some(fields) = definition.as_object_mut() {
            for key in [
                "id",
                "has_secret",
                "disabled_at",
                "created_at",
                "updated_at",
            ] {
                fields.remove(key);
            }
        }
        definition
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct NewClientSecret {
    pub client_secret: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct CreatedInvite {
    pub invite_id: String,
    pub expires_at: String,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn client_definitions_drop_what_conclave_keeps() {
        let client: OidcClient = serde_json::from_value(json!({
            "id": "tool",
            "kind": "confidential",
            "redirect_uris": ["https://tool.example/cb"],
            "scopes": ["openid"],
            "audience": "tool",
            "has_secret": true,
            "disabled_at": null,
            "created_at": "2026-10-01T00:00:00Z",
            "updated_at": "2026-10-01T00:00:00Z",
        }))
        .unwrap();
        assert!(client.has_secret);
        assert_eq!(
            client.definition(),
            json!({
                "kind": "confidential",
                "redirect_uris": ["https://tool.example/cb"],
                "scopes": ["openid"],
                "audience": "tool",
            })
        );
    }

    #[test]
    fn subject_details_flatten_the_subject() {
        let detail: SubjectDetail = serde_json::from_value(json!({
            "id": "s1", "kind": "human", "state": "active",
            "created_at": "2026-10-01T00:00:00Z",
            "credentials": [{
                "id": "c1", "subject_id": "s1", "kind": "password",
                "identifier": "ada@example.com", "mfa_factors_required": 0,
                "replaces": null, "created_at": "2026-10-01T00:00:00Z",
                "revoked_at": null, "revoked_reason": null, "break_glass": false,
            }],
        }))
        .unwrap();
        assert_eq!(detail.subject.kind, "human");
        assert!(detail.credentials[0].can_be_break_glass());
    }

    #[test]
    fn only_active_local_credentials_can_be_break_glass() {
        let mut credential = Credential {
            id: "c1".into(),
            subject_id: "s1".into(),
            kind: "email_link".into(),
            identifier: "ada@example.com".into(),
            mfa_factors_required: 0,
            slots: None,
            replaces: None,
            created_at: String::new(),
            revoked_at: None,
            revoked_reason: None,
            break_glass: false,
        };
        assert!(!credential.can_be_break_glass());
        credential.kind = "secret_key".into();
        assert!(credential.can_be_break_glass());
        credential.revoked_at = Some("2026-10-02T00:00:00Z".into());
        assert!(!credential.can_be_break_glass());
    }

    #[test]
    fn signing_key_status_follows_its_lifecycle() {
        let mut key = SigningKey {
            kid: "k".into(),
            algorithm: "EdDSA".into(),
            published_at: String::new(),
            activated_at: None,
            retired_at: None,
            revoked_at: None,
        };
        assert_eq!(key.status(), "published");
        key.activated_at = Some(String::new());
        assert_eq!(key.status(), "active");
        key.retired_at = Some(String::new());
        assert_eq!(key.status(), "retired");
        key.revoked_at = Some(String::new());
        assert_eq!(key.status(), "revoked");
    }
}
