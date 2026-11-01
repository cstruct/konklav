//! Nested documents (Styx): records inside the ones they belong to, with
//! optional ids. Tenants hold child tenants, roles and members; a member is
//! a subject with a membership in the enclosing tenant. A subject without
//! an id is named by its login identifier, so the same person in two
//! tenants is one subject.

use std::collections::BTreeMap;
use std::path::Path;

use facet::Facet;
use facet_reflect::Span;
use facet_styx::RenderError;
use uuid::Uuid;

use crate::model::{
    Assignment, AssignmentTarget, BootstrapSet, Credential, CredentialMaterial, Effect, FactValue,
    Factor, FactorMaterial, Facts, Id, Located, Location, Membership, MembershipRef, Policy, Role,
    SecretSlot, Subject, SubjectKind, SubjectRef, SubjectState, Template, Tenant, TenantRef,
};
use crate::{Problem, line_of};

#[derive(Debug, Clone, Facet)]
#[facet(metadata_container)]
struct Spanned<T> {
    value: T,
    #[facet(metadata = "span")]
    span: Option<Span>,
}

#[derive(Debug, Facet)]
#[facet(deny_unknown_fields)]
struct Document {
    id_namespace: Option<Spanned<String>>,
    /// A catalog document in the control plane's JSON shape, relative to
    /// this file.
    catalog_file: Option<Spanned<String>>,
    templates: Option<Vec<Spanned<TemplateDoc>>>,
    /// Global roles: roles of the root tenant.
    global_roles: Option<Vec<Spanned<RoleDoc>>>,
    tenants: Option<Vec<Spanned<TenantDoc>>>,
    subjects: Option<Vec<Spanned<SubjectDoc>>>,
}

#[derive(Debug, Facet)]
#[facet(deny_unknown_fields)]
struct PolicyDoc {
    action: String,
    /// `allow` (the default) or `deny`.
    effect: Option<String>,
    scope_bound: Option<bool>,
}

#[derive(Debug, Facet)]
#[facet(deny_unknown_fields)]
struct TemplateDoc {
    key: String,
    description: Option<String>,
    metadata: Option<BTreeMap<String, facet_value::Value>>,
    policies: Option<Vec<PolicyDoc>>,
}

#[derive(Debug, Facet)]
#[facet(deny_unknown_fields)]
struct RoleDoc {
    key: String,
    template: Option<String>,
    priority: Option<i32>,
    metadata: Option<BTreeMap<String, facet_value::Value>>,
    policies: Option<Vec<PolicyDoc>>,
}

#[derive(Debug, Facet)]
#[facet(deny_unknown_fields)]
struct TenantDoc {
    id: Option<String>,
    /// A name for the tenant, used as its external id.
    key: Option<String>,
    /// For top-level tenants only: a tenant id or `root` (the default).
    parent: Option<String>,
    facts: Option<BTreeMap<String, facet_value::Value>>,
    templates: Option<Vec<String>>,
    roles: Option<Vec<Spanned<RoleDoc>>>,
    children: Option<Vec<Spanned<TenantDoc>>>,
    members: Option<Vec<Spanned<MemberDoc>>>,
}

#[derive(Debug, Facet)]
#[facet(deny_unknown_fields)]
struct SlotDoc {
    hash: String,
    created_at: String,
    expires_at: Option<String>,
}

#[derive(Debug, Facet)]
#[facet(deny_unknown_fields)]
struct CredentialDoc {
    id: Option<String>,
    /// `password`, `secret_key`, `email_link`, `phone_otp` or `federated`.
    kind: String,
    identifier: Option<String>,
    password_hash: Option<String>,
    password: Option<String>,
    mfa_factors_required: Option<i16>,
    provider: Option<String>,
    provider_subject: Option<String>,
    a: Option<SlotDoc>,
    b: Option<SlotDoc>,
}

#[derive(Debug, Facet)]
#[facet(deny_unknown_fields)]
struct FactorDoc {
    id: Option<String>,
    /// `totp` or `email_code`.
    kind: String,
    seed_base32: Option<String>,
    email: Option<String>,
    active: Option<bool>,
}

#[derive(Debug, Facet)]
#[facet(deny_unknown_fields)]
struct ScopedRoleDoc {
    role: String,
    scope_kind: String,
    scope_id: String,
}

/// What a subject and a member share. Shorthands: `email` with
/// `password_hash` or `password` makes a password credential, with
/// `email_link true` an email-link one; `phone` makes a phone credential.
#[derive(Debug, Facet)]
#[facet(deny_unknown_fields)]
struct SubjectDoc {
    id: Option<String>,
    /// `human` (the default) or `service`.
    kind: Option<String>,
    /// `active` (the default) or `disabled`.
    state: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    password_hash: Option<String>,
    password: Option<String>,
    email_link: Option<bool>,
    mfa_factors_required: Option<i16>,
    credentials: Option<Vec<Spanned<CredentialDoc>>>,
    factors: Option<Vec<Spanned<FactorDoc>>>,
    global_roles: Option<Vec<String>>,
}

#[derive(Debug, Facet)]
#[facet(deny_unknown_fields)]
struct MemberDoc {
    id: Option<String>,
    kind: Option<String>,
    state: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    password_hash: Option<String>,
    password: Option<String>,
    email_link: Option<bool>,
    mfa_factors_required: Option<i16>,
    credentials: Option<Vec<Spanned<CredentialDoc>>>,
    factors: Option<Vec<Spanned<FactorDoc>>>,
    global_roles: Option<Vec<String>>,
    /// The membership's id; without one, the membership is the subject's
    /// active one in the tenant.
    membership: Option<String>,
    facts: Option<BTreeMap<String, facet_value::Value>>,
    /// Role keys of the tenant, assigned tenant-wide.
    roles: Option<Vec<String>>,
    scoped_roles: Option<Vec<ScopedRoleDoc>>,
}

impl MemberDoc {
    fn into_parts(self) -> (SubjectDoc, MembershipParts) {
        (
            SubjectDoc {
                id: self.id,
                kind: self.kind,
                state: self.state,
                email: self.email,
                phone: self.phone,
                password_hash: self.password_hash,
                password: self.password,
                email_link: self.email_link,
                mfa_factors_required: self.mfa_factors_required,
                credentials: self.credentials,
                factors: self.factors,
                global_roles: self.global_roles,
            },
            MembershipParts {
                id: self.membership,
                facts: self.facts,
                roles: self.roles.unwrap_or_default(),
                scoped_roles: self.scoped_roles.unwrap_or_default(),
            },
        )
    }
}

struct MembershipParts {
    id: Option<String>,
    facts: Option<BTreeMap<String, facet_value::Value>>,
    roles: Vec<String>,
    scoped_roles: Vec<ScopedRoleDoc>,
}

struct Reader<'a> {
    file: &'a Path,
    text: &'a str,
    set: BootstrapSet,
    problems: Vec<Problem>,
    /// Factors read per subject, for their positions.
    positions: BTreeMap<SubjectRef, usize>,
}

pub(crate) fn read(file: &Path, text: &str) -> Result<BootstrapSet, Vec<Problem>> {
    let document: Document = facet_styx::from_str(text).map_err(|error| {
        // The rendered report names the file, line and column itself.
        let rendered = strip_ansi(&error.render(&file.display().to_string(), text));
        vec![Problem {
            at: None,
            message: rendered.trim_end().to_owned(),
        }]
    })?;
    let mut reader = Reader {
        file,
        text,
        set: BootstrapSet::default(),
        problems: Vec::new(),
        positions: BTreeMap::new(),
    };
    reader.document(document);
    if reader.problems.is_empty() {
        Ok(reader.set)
    } else {
        Err(reader.problems)
    }
}

/// Error reports are coloured for terminals; problems are plain text.
fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

impl Reader<'_> {
    fn at<T>(&self, spanned: &Spanned<T>) -> Location {
        Location {
            file: self.file.to_owned(),
            line: spanned
                .span
                .map_or(1, |span| line_of(self.text, span.offset as usize)),
        }
    }

    fn problem(&mut self, at: &Location, message: impl Into<String>) {
        self.problems.push(Problem::at(at, message));
    }

    fn document(&mut self, document: Document) {
        if let Some(namespace) = &document.id_namespace {
            let at = self.at(namespace);
            match Uuid::parse_str(namespace.value.trim()) {
                Ok(value) => self.set.id_namespace = Some(Located { value, at }),
                Err(_) => self.problem(&at, "id_namespace must be a UUID"),
            }
        }
        if let Some(catalog) = &document.catalog_file {
            let at = self.at(catalog);
            let path = self
                .file
                .parent()
                .unwrap_or(Path::new("."))
                .join(&catalog.value);
            match std::fs::read_to_string(&path)
                .map_err(|e| e.to_string())
                .and_then(|text| serde_json::from_str(&text).map_err(|e| e.to_string()))
            {
                Ok(value) => self.set.catalog = Some(Located { value, at }),
                Err(error) => self.problem(&at, format!("{}: {error}", path.display())),
            }
        }
        for template in document.templates.unwrap_or_default() {
            let at = self.at(&template);
            let doc = template.value;
            let policies = self.policies(&at, doc.policies);
            let metadata = self.metadata(&at, doc.metadata);
            self.set.templates.push(Located {
                value: Template {
                    key: doc.key,
                    description: doc.description.unwrap_or_default(),
                    metadata,
                    policies,
                },
                at,
            });
        }
        for role in document.global_roles.unwrap_or_default() {
            self.role(TenantRef::Root, role);
        }
        for tenant in document.tenants.unwrap_or_default() {
            self.tenant(None, tenant);
        }
        for subject in document.subjects.unwrap_or_default() {
            let at = self.at(&subject);
            self.subject(&at, subject.value);
        }
    }

    fn policies(&mut self, at: &Location, policies: Option<Vec<PolicyDoc>>) -> Vec<Policy> {
        policies
            .unwrap_or_default()
            .into_iter()
            .filter_map(|policy| {
                let effect = match policy.effect.as_deref() {
                    None | Some("allow") => Effect::Allow,
                    Some("deny") => Effect::Deny,
                    Some(other) => {
                        self.problem(at, format!("effect must be allow or deny, not `{other}`"));
                        return None;
                    }
                };
                Some(Policy {
                    action: policy.action,
                    effect,
                    scope_bound: policy.scope_bound.unwrap_or(false),
                })
            })
            .collect()
    }

    fn role(&mut self, tenant: TenantRef, role: Spanned<RoleDoc>) {
        let at = self.at(&role);
        let doc = role.value;
        let policies = self.policies(&at, doc.policies);
        let metadata = self.metadata(&at, doc.metadata);
        self.set.roles.push(Located {
            value: Role {
                tenant,
                key: doc.key,
                template: doc.template,
                priority: doc.priority.unwrap_or(0),
                metadata,
                policies,
            },
            at,
        });
    }

    // r[impl bootstrap.metadata]
    /// Metadata as the JSON object the control plane stores. Styx scalars
    /// are text, so they become strings.
    fn metadata(
        &mut self,
        at: &Location,
        metadata: Option<BTreeMap<String, facet_value::Value>>,
    ) -> serde_json::Value {
        let mut out = serde_json::Map::new();
        for (key, value) in metadata.unwrap_or_default() {
            match json(&value) {
                Some(value) => {
                    out.insert(key, value);
                }
                None => self.problem(at, format!("metadata `{key}` has a value JSON can't hold")),
            }
        }
        serde_json::Value::Object(out)
    }

    fn facts(
        &mut self,
        at: &Location,
        facts: Option<BTreeMap<String, facet_value::Value>>,
    ) -> Facts {
        let mut out = Facts::new();
        for (key, value) in facts.unwrap_or_default() {
            if let Some(text) = value.as_string() {
                out.insert(key, FactValue::Text(text.as_str().to_owned()));
            } else if let Some(items) = value.as_array() {
                let texts: Option<Vec<String>> = items
                    .iter()
                    .map(|item| item.as_string().map(|s| s.as_str().to_owned()))
                    .collect();
                match texts {
                    Some(texts) => {
                        out.insert(key, FactValue::List(texts));
                    }
                    None => self.problem(at, format!("fact `{key}` must be a value or a list")),
                }
            } else {
                self.problem(at, format!("fact `{key}` must be a value or a list"));
            }
        }
        out
    }

    fn tenant(&mut self, parent: Option<TenantRef>, tenant: Spanned<TenantDoc>) {
        let at = self.at(&tenant);
        let doc = tenant.value;
        let id = match (doc.id, doc.key) {
            (Some(id), None) => Id::parse(&id),
            (None, Some(key)) => Id::External(key),
            _ => {
                self.problem(&at, "a tenant needs exactly one of `id` and `key`");
                return;
            }
        };
        let parent = match (parent, doc.parent) {
            (Some(enclosing), None) => enclosing,
            (None, Some(parent)) => TenantRef::parse(&parent),
            (None, None) => TenantRef::Root,
            (Some(_), Some(_)) => {
                self.problem(&at, "a child tenant's parent is the tenant it is in");
                return;
            }
        };
        let facts = self.facts(&at, doc.facts);
        let here = TenantRef::Id(id.clone());
        self.set.tenants.push(Located {
            value: Tenant {
                id,
                parent,
                facts,
                templates: doc.templates.unwrap_or_default(),
            },
            at,
        });
        for role in doc.roles.unwrap_or_default() {
            self.role(here.clone(), role);
        }
        for child in doc.children.unwrap_or_default() {
            self.tenant(Some(here.clone()), child);
        }
        for member in doc.members.unwrap_or_default() {
            let at = self.at(&member);
            let (subject, membership) = member.value.into_parts();
            let Some(key) = self.subject(&at, subject) else {
                continue;
            };
            self.membership(&at, key, here.clone(), membership);
        }
    }

    fn membership(
        &mut self,
        at: &Location,
        subject: SubjectRef,
        tenant: TenantRef,
        parts: MembershipParts,
    ) {
        let facts = self.facts(at, parts.facts);
        let id = parts.id.as_deref().map(Id::parse);
        let target = match &id {
            Some(id) => MembershipRef::Id(id.clone()),
            None => MembershipRef::Of {
                subject: subject.clone(),
                tenant: tenant.clone(),
            },
        };
        self.set.memberships.push(Located {
            value: Membership {
                id,
                subject,
                tenant,
                facts,
            },
            at: at.clone(),
        });
        for role in parts.roles {
            self.set.assignments.push(Located {
                value: Assignment {
                    target: AssignmentTarget::Membership(target.clone()),
                    role,
                    scope: None,
                },
                at: at.clone(),
            });
        }
        for scoped in parts.scoped_roles {
            self.set.assignments.push(Located {
                value: Assignment {
                    target: AssignmentTarget::Membership(target.clone()),
                    role: scoped.role,
                    scope: Some((scoped.scope_kind, scoped.scope_id)),
                },
                at: at.clone(),
            });
        }
    }

    /// Reads a subject with its credentials, factors and global roles, and
    /// returns how other records name it.
    fn subject(&mut self, at: &Location, doc: SubjectDoc) -> Option<SubjectRef> {
        let kind = match doc.kind.as_deref() {
            None | Some("human") => SubjectKind::Human,
            Some("service") => SubjectKind::Service,
            Some(other) => {
                self.problem(at, format!("kind must be human or service, not `{other}`"));
                return None;
            }
        };
        let state = match doc.state.as_deref() {
            None | Some("active") => SubjectState::Active,
            Some("disabled") => SubjectState::Disabled,
            Some(other) => {
                self.problem(
                    at,
                    format!("state must be active or disabled, not `{other}`"),
                );
                return None;
            }
        };
        let mfa = doc.mfa_factors_required.unwrap_or(0);
        let mut credentials = self.shorthand_credentials(at, &doc, mfa)?;
        for credential in doc.credentials.unwrap_or_default() {
            let at = self.at(&credential);
            if let Some(read) = self.credential(&at, credential.value) {
                credentials.push(read);
            }
        }
        let key = match doc.id.as_deref() {
            Some(id) => SubjectRef::Id(Id::parse(id)),
            None => {
                let identifier = doc
                    .email
                    .clone()
                    .or(doc.phone.clone())
                    .or_else(|| credentials.iter().find_map(|c| c.2.clone()));
                let Some(identifier) = identifier else {
                    self.problem(
                        at,
                        "a subject without `id` needs an email, a phone or a credential \
                         identifier to be found by",
                    );
                    return None;
                };
                SubjectRef::Identifier(identifier)
            }
        };
        self.set.subjects.push(Located {
            value: Subject {
                key: key.clone(),
                kind,
                state,
            },
            at: at.clone(),
        });
        for (at, id, identifier, material, mfa_factors_required) in credentials {
            self.set.credentials.push(Located {
                value: Credential {
                    id,
                    subject: key.clone(),
                    identifier,
                    mfa_factors_required,
                    material,
                },
                at,
            });
        }
        for factor in doc.factors.unwrap_or_default() {
            self.factor(&key, factor);
        }
        for role in doc.global_roles.unwrap_or_default() {
            self.set.assignments.push(Located {
                value: Assignment {
                    target: AssignmentTarget::Global(key.clone()),
                    role,
                    scope: None,
                },
                at: at.clone(),
            });
        }
        Some(key)
    }

    /// The credentials `email` and `phone` stand for.
    #[allow(clippy::type_complexity)]
    fn shorthand_credentials(
        &mut self,
        at: &Location,
        doc: &SubjectDoc,
        mfa: i16,
    ) -> Option<
        Vec<(
            Location,
            Option<Id>,
            Option<String>,
            CredentialMaterial,
            i16,
        )>,
    > {
        let mut credentials = Vec::new();
        if let Some(email) = &doc.email {
            let material = match (&doc.password_hash, &doc.password, doc.email_link) {
                (Some(hash), None, None | Some(false)) => {
                    Some(CredentialMaterial::PasswordHash(hash.clone()))
                }
                (None, Some(password), None | Some(false)) => {
                    Some(CredentialMaterial::Password(password.clone()))
                }
                (None, None, Some(true)) => Some(CredentialMaterial::EmailLink),
                (None, None, None | Some(false)) => None,
                _ => {
                    self.problem(
                        at,
                        "give `email` one of `password_hash`, `password` and `email_link true`",
                    );
                    return None;
                }
            };
            if let Some(material) = material {
                credentials.push((at.clone(), None, Some(email.clone()), material, mfa));
            }
        } else if doc.password_hash.is_some() || doc.password.is_some() || doc.email_link.is_some()
        {
            self.problem(at, "a password or email link needs `email`");
            return None;
        }
        if let Some(phone) = &doc.phone {
            credentials.push((
                at.clone(),
                None,
                Some(phone.clone()),
                CredentialMaterial::PhoneOtp,
                mfa,
            ));
        }
        Some(credentials)
    }

    fn factor(&mut self, key: &SubjectRef, factor: Spanned<FactorDoc>) {
        let at = self.at(&factor);
        let doc = factor.value;
        let material = match (doc.kind.as_str(), doc.seed_base32, doc.email) {
            ("totp", Some(seed_base32), None) => FactorMaterial::Totp { seed_base32 },
            ("email_code", None, Some(email)) => FactorMaterial::EmailCode { email },
            _ => {
                self.problem(
                    &at,
                    "a factor is `kind totp` with `seed_base32`, or `kind email_code` \
                     with `email`",
                );
                return;
            }
        };
        let position = self.positions.entry(key.clone()).or_default();
        *position += 1;
        let position = *position;
        self.set.factors.push(Located {
            value: Factor {
                id: doc.id.as_deref().map(Id::parse),
                subject: key.clone(),
                position,
                active: doc.active.unwrap_or(true),
                material,
            },
            at,
        });
    }

    #[allow(clippy::type_complexity)]
    fn credential(
        &mut self,
        at: &Location,
        doc: CredentialDoc,
    ) -> Option<(
        Location,
        Option<Id>,
        Option<String>,
        CredentialMaterial,
        i16,
    )> {
        let material = match doc.kind.as_str() {
            "password" => match (doc.password_hash, doc.password) {
                (Some(hash), None) => CredentialMaterial::PasswordHash(hash),
                (None, Some(password)) => CredentialMaterial::Password(password),
                _ => {
                    self.problem(
                        at,
                        "a password needs exactly one of `password_hash` and `password`",
                    );
                    return None;
                }
            },
            "secret_key" => match (doc.a, doc.b) {
                (Some(a), Some(b)) => CredentialMaterial::SecretKey {
                    a: SecretSlot {
                        hash: a.hash,
                        created_at: a.created_at,
                        expires_at: a.expires_at,
                    },
                    b: SecretSlot {
                        hash: b.hash,
                        created_at: b.created_at,
                        expires_at: b.expires_at,
                    },
                },
                _ => {
                    self.problem(at, "a secret key needs slots `a` and `b`");
                    return None;
                }
            },
            "email_link" => CredentialMaterial::EmailLink,
            "phone_otp" => CredentialMaterial::PhoneOtp,
            "federated" => match (doc.provider, doc.provider_subject) {
                (Some(provider), Some(subject)) => {
                    CredentialMaterial::Federated { provider, subject }
                }
                _ => {
                    self.problem(
                        at,
                        "a federated credential needs `provider` and `provider_subject`",
                    );
                    return None;
                }
            },
            other => {
                self.problem(
                    at,
                    format!(
                        "kind must be password, secret_key, email_link, phone_otp or federated, \
                         not `{other}`"
                    ),
                );
                return None;
            }
        };
        let federated = matches!(material, CredentialMaterial::Federated { .. });
        if !federated && doc.identifier.is_none() {
            self.problem(at, "a credential needs an `identifier`");
            return None;
        }
        Some((
            at.clone(),
            doc.id.as_deref().map(Id::parse),
            if federated { None } else { doc.identifier },
            material,
            doc.mfa_factors_required.unwrap_or(0),
        ))
    }
}

/// `value` as JSON, or `None` for what JSON can't hold, such as bytes.
fn json(value: &facet_value::Value) -> Option<serde_json::Value> {
    if value.is_null() {
        return Some(serde_json::Value::Null);
    }
    if let Some(flag) = value.as_bool() {
        return Some(flag.into());
    }
    if let Some(text) = value.as_string() {
        return Some(text.as_str().into());
    }
    if let Some(number) = value.as_number() {
        return match number.to_i64() {
            Some(whole) => Some(whole.into()),
            None => serde_json::Number::from_f64(number.to_f64()?).map(serde_json::Value::Number),
        };
    }
    if let Some(items) = value.as_array() {
        return items
            .iter()
            .map(json)
            .collect::<Option<Vec<_>>>()
            .map(serde_json::Value::Array);
    }
    if let Some(object) = value.as_object() {
        return object
            .iter()
            .map(|(key, item)| Some((key.as_str().to_owned(), json(item)?)))
            .collect::<Option<serde_json::Map<_, _>>>()
            .map(serde_json::Value::Object);
    }
    None
}
