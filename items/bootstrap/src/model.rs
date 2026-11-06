//! The bootstrap set: every record a run read, where it was read from, and
//! how it names other records. Identifiers stay as written; the server
//! turns them into UUIDs ([`Id::resolve`]) and finds natural keys.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

use uuid::Uuid;

/// Where a record was written.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Location {
    pub file: PathBuf,
    /// 1-based.
    pub line: usize,
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.file.display(), self.line)
    }
}

/// A record and where it was written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Located<T> {
    pub value: T,
    pub at: Location,
}

/// The kinds of record whose ids an import may choose, as they appear in
/// external-id derivation (`<kind>:<external id>`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Tenant,
    Subject,
    Credential,
    MfaFactor,
    Membership,
    Session,
}

impl Kind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tenant => "tenant",
            Self::Subject => "subject",
            Self::Credential => "credential",
            Self::MfaFactor => "mfa_factor",
            Self::Membership => "membership",
            Self::Session => "session",
        }
    }
}

/// An identifier as written: a UUID, or anything else as an external id.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Id {
    Uuid(Uuid),
    External(String),
}

impl Id {
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let text = text.trim();
        match Uuid::parse_str(text) {
            Ok(uuid) => Self::Uuid(uuid),
            Err(_) => Self::External(text.to_owned()),
        }
    }

    /// The record's UUID: a UUID as given, or an external id derived under
    /// `namespace`. `None` when an external id has no namespace.
    // r[impl bootstrap.ids]
    #[must_use]
    pub fn resolve(&self, namespace: Option<Uuid>, kind: Kind) -> Option<Uuid> {
        match self {
            Self::Uuid(uuid) => Some(*uuid),
            Self::External(external) => {
                namespace.map(|namespace| derive(namespace, kind, external))
            }
        }
    }

    #[must_use]
    pub fn is_external(&self) -> bool {
        matches!(self, Self::External(_))
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uuid(uuid) => uuid.fmt(f),
            Self::External(external) => f.write_str(external),
        }
    }
}

/// UUID version 5 of `namespace` and `<kind>:<external>`.
#[must_use]
pub fn derive(namespace: Uuid, kind: Kind, external: &str) -> Uuid {
    Uuid::new_v5(
        &namespace,
        format!("{}:{external}", kind.as_str()).as_bytes(),
    )
}

/// How a record names a subject.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SubjectRef {
    Id(Id),
    /// Its natural key: a login identifier, such as an email address.
    Identifier(String),
}

/// How a record names a tenant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TenantRef {
    Root,
    Id(Id),
}

impl TenantRef {
    #[must_use]
    pub fn parse(text: &str) -> Self {
        if text.trim() == "root" {
            Self::Root
        } else {
            Self::Id(Id::parse(text))
        }
    }
}

/// How a record names a membership.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MembershipRef {
    Id(Id),
    /// Its natural key: the subject's active membership in the tenant.
    Of {
        subject: SubjectRef,
        tenant: TenantRef,
    },
}

/// A fact as written. Both formats write scalars as text; the catalog's
/// declared type decides how it is read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FactValue {
    Text(String),
    List(Vec<String>),
}

pub type Facts = BTreeMap<String, FactValue>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub action: String,
    pub effect: Effect,
    pub scope_bound: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Template {
    pub key: String,
    pub description: String,
    /// A JSON object stored with the template, as the control plane's
    /// `metadata`.
    pub metadata: serde_json::Value,
    pub policies: Vec<Policy>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Role {
    pub tenant: TenantRef,
    pub key: String,
    pub template: Option<String>,
    pub priority: i32,
    /// A JSON object stored with the role, as the control plane's
    /// `metadata`.
    pub metadata: serde_json::Value,
    pub policies: Vec<Policy>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tenant {
    pub id: Id,
    pub parent: TenantRef,
    pub facts: Facts,
    /// Templates to derive roles from when the tenant is created.
    pub templates: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubjectKind {
    Human,
    Service,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubjectState {
    Active,
    Disabled,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subject {
    pub key: SubjectRef,
    pub kind: SubjectKind,
    pub state: SubjectState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretSlot {
    pub hash: String,
    /// RFC 3339.
    pub created_at: String,
    pub expires_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialMaterial {
    /// An Argon2 PHC string.
    PasswordHash(String),
    /// Plaintext, accepted only when the run allows it.
    Password(String),
    SecretKey {
        a: SecretSlot,
        b: SecretSlot,
    },
    EmailLink,
    PhoneOtp,
    Federated {
        provider: String,
        subject: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credential {
    pub id: Option<Id>,
    pub subject: SubjectRef,
    /// The login identifier; federated credentials derive theirs.
    pub identifier: Option<String>,
    pub mfa_factors_required: i16,
    /// Restrictive session flags every session started with it carries.
    pub session_flags: Vec<String>,
    pub material: CredentialMaterial,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FactorMaterial {
    Totp { seed_base32: String },
    EmailCode { email: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Factor {
    /// Without one, the factor is identified by its subject and its
    /// position among that subject's factors in the set.
    pub id: Option<Id>,
    pub subject: SubjectRef,
    pub position: usize,
    pub active: bool,
    pub material: FactorMaterial,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Membership {
    pub id: Option<Id>,
    pub subject: SubjectRef,
    pub tenant: TenantRef,
    pub facts: Facts,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssignmentTarget {
    Membership(MembershipRef),
    /// A global role, assigned directly to the subject.
    Global(SubjectRef),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assignment {
    pub target: AssignmentTarget,
    pub role: String,
    /// `(scope kind, scope id)`.
    pub scope: Option<(String, String)>,
}

/// A scope of a registered kind, with its owner tenant and the scopes it
/// sits in. Its kind and ids are opaque and used as written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredScope {
    pub kind: String,
    pub id: String,
    pub tenant: TenantRef,
    /// `(scope kind, scope id)` of each containing scope.
    pub containers: Vec<(String, String)>,
}

/// A live session carried over; flat tables only, with ids.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub id: Id,
    pub subject: Id,
    pub credential: Id,
    pub tenant: Option<Id>,
    pub membership: Option<Id>,
    pub stage: String,
    pub client_kind: Option<String>,
    pub amr: Vec<String>,
    pub flags: Vec<String>,
    pub impersonator: Option<Id>,
    pub auth_time: String,
    pub version: i64,
    pub refresh_hash: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
}

/// Everything one run read, in the order it was read.
// r[impl bootstrap.contents]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BootstrapSet {
    pub id_namespace: Option<Located<Uuid>>,
    /// A catalog document in the control plane's JSON shape.
    pub catalog: Option<Located<serde_json::Value>>,
    pub templates: Vec<Located<Template>>,
    pub roles: Vec<Located<Role>>,
    pub tenants: Vec<Located<Tenant>>,
    pub subjects: Vec<Located<Subject>>,
    pub credentials: Vec<Located<Credential>>,
    pub factors: Vec<Located<Factor>>,
    pub memberships: Vec<Located<Membership>>,
    pub assignments: Vec<Located<Assignment>>,
    pub registered_scopes: Vec<Located<RegisteredScope>>,
    pub sessions: Vec<Located<Session>>,
}

impl BootstrapSet {
    /// Adds `other`'s records after this set's.
    pub(crate) fn extend(&mut self, other: Self, problems: &mut Vec<crate::Problem>) {
        match (&self.id_namespace, other.id_namespace) {
            (Some(ours), Some(theirs)) if ours.value != theirs.value => {
                problems.push(crate::Problem::at(
                    &theirs.at,
                    format!(
                        "id_namespace {} differs from {} declared at {}",
                        theirs.value, ours.value, ours.at
                    ),
                ));
            }
            (None, Some(theirs)) => self.id_namespace = Some(theirs),
            _ => {}
        }
        match (&self.catalog, other.catalog) {
            (Some(ours), Some(theirs)) => problems.push(crate::Problem::at(
                &theirs.at,
                format!("a catalog was already read from {}", ours.at),
            )),
            (None, Some(theirs)) => self.catalog = Some(theirs),
            _ => {}
        }
        self.templates.extend(other.templates);
        self.roles.extend(other.roles);
        self.tenants.extend(other.tenants);
        self.subjects.extend(other.subjects);
        self.credentials.extend(other.credentials);
        self.factors.extend(other.factors);
        self.memberships.extend(other.memberships);
        self.assignments.extend(other.assignments);
        self.registered_scopes.extend(other.registered_scopes);
        self.sessions.extend(other.sessions);
    }

    /// Whether any record uses an external id, which needs a namespace.
    #[must_use]
    pub fn uses_external_ids(&self) -> bool {
        let subject = |key: &SubjectRef| matches!(key, SubjectRef::Id(id) if id.is_external());
        let tenant = |key: &TenantRef| matches!(key, TenantRef::Id(id) if id.is_external());
        let id = |id: &Option<Id>| id.as_ref().is_some_and(Id::is_external);
        self.tenants
            .iter()
            .any(|t| t.value.id.is_external() || tenant(&t.value.parent))
            || self.roles.iter().any(|r| tenant(&r.value.tenant))
            || self.subjects.iter().any(|s| subject(&s.value.key))
            || self
                .credentials
                .iter()
                .any(|c| id(&c.value.id) || subject(&c.value.subject))
            || self
                .factors
                .iter()
                .any(|f| id(&f.value.id) || subject(&f.value.subject))
            || self
                .memberships
                .iter()
                .any(|m| id(&m.value.id) || subject(&m.value.subject) || tenant(&m.value.tenant))
            || self.assignments.iter().any(|a| match &a.value.target {
                AssignmentTarget::Global(key) => subject(key),
                AssignmentTarget::Membership(MembershipRef::Id(id)) => id.is_external(),
                AssignmentTarget::Membership(MembershipRef::Of {
                    subject: s,
                    tenant: t,
                }) => subject(s) || tenant(t),
            })
            || self
                .registered_scopes
                .iter()
                .any(|r| tenant(&r.value.tenant))
            || self.sessions.iter().any(|s| {
                let s = &s.value;
                s.id.is_external()
                    || s.subject.is_external()
                    || s.credential.is_external()
                    || id(&s.tenant)
                    || id(&s.membership)
                    || id(&s.impersonator)
            })
    }
}
