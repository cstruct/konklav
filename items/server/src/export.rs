//! The `export` command: writes the database's identity data as a
//! bootstrap set that `bootstrap` loads into an empty database unchanged.
//!
//! It reads the database directly, in one read-only transaction, rather
//! than through the control plane, which never shows hashes or MFA seeds.
//! The set holds both, so it is as sensitive as the database.
//!
//! What it writes:
//!
//! - `catalog.json`
//! - `set.styx`: templates, global roles, and tenants with their roles
//! - `subjects.csv`, `credentials.csv`, `mfa_factors.csv`,
//!   `memberships.csv` and `assignments.csv`
//!
//! What it leaves out, and reports: sessions, signing keys, OIDC clients and
//! the `client` credentials they bind, passkeys (a bootstrap set can't hold
//! them), revoked credentials, ended memberships, tenant states, and records
//! an identity provider's claim mapping manages, which it makes again.

use std::collections::{BTreeMap, HashMap};
use std::fmt::{self, Write as _};
use std::path::Path;

use chrono::{DateTime, SecondsFormat, Utc};
use konklav_authn::{EncryptedSecret, SecretBox, TotpSecret};
use konklav_authz::{Effect, Policy};
use konklav_core::TenantId;
use konklav_store::credentials::{self, Credential, CredentialData, SecretSlotData};
use konklav_store::memberships::{self, MembershipState};
use konklav_store::mfa::{self, Factor, FactorData};
use konklav_store::roles::{self, AssignmentTarget, Role, RoleAssignment};
use konklav_store::subjects::{self, Subject, SubjectKind, SubjectState};
use konklav_store::tenants::{self, ROOT, Tenant};
use konklav_store::{Connection, Pool, catalog, templates};

use crate::transport;

const PAGE: i64 = 500;

/// Why an export failed.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error("{0} exists and isn't an empty directory")]
    NotEmpty(String),
    #[error("writing {path}: {source}")]
    Write {
        path: String,
        source: std::io::Error,
    },
    #[error("reading the database: {0}")]
    Store(#[from] konklav_store::StoreError),
    #[error("reading the database: {0}")]
    Database(#[from] diesel::result::Error),
    #[error("connecting to the database: {0}")]
    Pool(String),
    #[error("decrypting the TOTP seed of factor {factor}: {message}")]
    Seed { factor: uuid::Uuid, message: String },
    #[error("{0}")]
    Unsupported(String),
}

/// What an export wrote, and what it left out.
#[derive(Debug, Default)]
pub struct Report {
    /// Records written, by kind.
    pub written: BTreeMap<&'static str, usize>,
    /// Records left out, by why.
    pub left_out: BTreeMap<&'static str, usize>,
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (kind, n) in &self.written {
            writeln!(f, "{kind}: {n}")?;
        }
        for (why, n) in &self.left_out {
            writeln!(f, "left out, {why}: {n}")?;
        }
        Ok(())
    }
}

impl Report {
    fn wrote(&mut self, kind: &'static str, n: usize) {
        *self.written.entry(kind).or_default() += n;
    }

    fn leave_out(&mut self, why: &'static str) {
        *self.left_out.entry(why).or_default() += 1;
    }
}

/// Writes the database's identity data into `directory`, which must be
/// empty or not exist yet. `secrets` decrypts TOTP seeds.
// r[impl bootstrap.export]
pub async fn run(
    pool: &Pool,
    secrets: &SecretBox,
    directory: &Path,
) -> Result<Report, ExportError> {
    let mut conn = pool
        .get()
        .await
        .map_err(|error| ExportError::Pool(error.to_string()))?;
    let set = conn
        .build_transaction()
        .read_only()
        .repeatable_read()
        .run::<_, ExportError, _>(async |conn| read(conn, secrets).await)
        .await?;
    write(directory, &set)?;
    Ok(set.report)
}

/// Everything an export writes, as file contents.
struct Set {
    catalog: serde_json::Value,
    document: String,
    tables: Vec<(&'static str, String)>,
    report: Report,
}

async fn read(conn: &mut Connection, secrets: &SecretBox) -> Result<Set, ExportError> {
    let mut report = Report::default();
    let catalog = serde_json::to_value(transport::catalog(catalog::load(conn).await?))
        .map_err(|error| ExportError::Unsupported(error.to_string()))?;
    let (document, tenants, role_keys) = document(conn, &mut report).await?;
    let mut people = people(conn, secrets, &role_keys, &mut report).await?;
    let (membership_columns, membership_rows) = memberships(
        conn,
        &tenants,
        &role_keys,
        &mut people.assignments,
        &mut report,
    )
    .await?;
    report.wrote("role assignments", people.assignments.len());

    let slot_columns = ["a", "b"]
        .into_iter()
        .flat_map(|slot| ["hash", "created_at", "expires_at"].map(|part| format!("{slot}_{part}")));
    let credential_columns: Vec<String> = [
        "id",
        "subject",
        "kind",
        "identifier",
        "password_hash",
        "mfa_factors_required",
        "session_flags",
        "provider",
        "provider_subject",
    ]
    .into_iter()
    .map(str::to_owned)
    .chain(slot_columns)
    .collect();
    let tables = vec![
        (
            "subjects.csv",
            table(&["id", "kind", "state"], &people.subjects),
        ),
        (
            "credentials.csv",
            table(&credential_columns, &people.credentials),
        ),
        (
            "mfa_factors.csv",
            table(
                &["id", "subject", "kind", "seed_base32", "email", "active"],
                &people.factors,
            ),
        ),
        (
            "memberships.csv",
            table(&membership_columns, &membership_rows),
        ),
        (
            "assignments.csv",
            table(
                &["membership", "subject", "role", "scope_kind", "scope_id"],
                &people.assignments,
            ),
        ),
    ];
    Ok(Set {
        catalog,
        document,
        tables,
        report,
    })
}

/// `set.styx`, with the tenants it lists and every role's key by id.
async fn document(
    conn: &mut Connection,
    report: &mut Report,
) -> Result<(String, Vec<Tenant>, HashMap<uuid::Uuid, String>), ExportError> {
    let tenants = in_tree_order(all_tenants(conn).await?);
    let global_roles = roles::list(conn, ROOT).await?;
    let mut role_keys: HashMap<uuid::Uuid, String> =
        global_roles.iter().map(|r| (r.id, r.key.clone())).collect();
    let mut tenant_docs = Vec::new();
    for tenant in &tenants {
        let tenant_roles = roles::list(conn, tenant.id).await?;
        role_keys.extend(tenant_roles.iter().map(|r| (r.id, r.key.clone())));
        if tenant.state != tenants::TenantState::Active {
            report.leave_out("tenant states (written as active)");
        }
        tenant_docs.push(Value::map([
            ("id", Value::text(tenant.id.to_string())),
            ("parent", Value::text(tenant_reference(tenant.parent_id))),
            ("facts", facts_value(&tenant.facts)?),
            ("roles", roles_value(&tenant_roles)),
        ]));
    }
    report.wrote("tenants", tenants.len());
    let template_docs: Vec<Value> = templates::list(conn)
        .await?
        .into_iter()
        .map(|t| {
            Value::map([
                ("key", Value::text(t.key)),
                ("description", Value::text(t.description)),
                ("metadata", metadata_value(&t.metadata)),
                ("policies", policies_value(&t.policies)),
            ])
        })
        .collect();
    report.wrote("templates", template_docs.len());
    report.wrote(
        "global roles",
        global_roles.iter().filter(|r| !r.builtin).count(),
    );
    let mut document = String::new();
    for (key, value) in [
        ("templates", Value::List(template_docs)),
        ("global_roles", roles_value(&global_roles)),
        ("tenants", Value::List(tenant_docs)),
    ] {
        let _ = writeln!(document, "{key} {}", value.styx(0));
    }
    Ok((document, tenants, role_keys))
}

/// Rows of the tables about subjects.
#[derive(Default)]
struct People {
    subjects: Vec<Vec<String>>,
    credentials: Vec<Vec<String>>,
    factors: Vec<Vec<String>>,
    assignments: Vec<Vec<String>>,
}

/// Every subject with its credentials, MFA factors and global role
/// assignments.
async fn people(
    conn: &mut Connection,
    secrets: &SecretBox,
    role_keys: &HashMap<uuid::Uuid, String>,
    report: &mut Report,
) -> Result<People, ExportError> {
    let mut people = People::default();
    for subject in all_subjects(conn).await? {
        people.subjects.push(vec![
            subject.id.to_string(),
            match subject.kind {
                SubjectKind::Human => "human",
                SubjectKind::Service => "service",
            }
            .to_owned(),
            match subject.state {
                SubjectState::Active => "active",
                SubjectState::Disabled => "disabled",
            }
            .to_owned(),
        ]);
        for credential in credentials::list_for_subject(conn, subject.id).await? {
            match credential_row(&credential) {
                Ok(row) => people.credentials.push(row),
                Err(why) => report.leave_out(why),
            }
        }
        for factor in mfa::list(conn, subject.id).await? {
            people.factors.push(factor_row(&factor, secrets)?);
        }
        for assignment in roles::global_assignments_of(conn, subject.id).await? {
            if let Some(row) = assignment_row(&assignment, role_keys, report) {
                people.assignments.push(row);
            }
        }
    }
    report.wrote("subjects", people.subjects.len());
    report.wrote("credentials", people.credentials.len());
    report.wrote("MFA factors", people.factors.len());
    Ok(people)
}

fn factor_row(factor: &Factor, secrets: &SecretBox) -> Result<Vec<String>, ExportError> {
    let (kind, seed, email) = match &factor.data {
        FactorData::Totp(data) => {
            let seed = secrets
                .decrypt(&EncryptedSecret {
                    key_id: data.key_id.clone(),
                    nonce: data.nonce.clone(),
                    ciphertext: data.ciphertext.clone(),
                })
                .map_err(|error| ExportError::Seed {
                    factor: factor.id,
                    message: error.to_string(),
                })?;
            (
                "totp",
                TotpSecret::from_bytes(seed).to_base32(),
                String::new(),
            )
        }
        FactorData::EmailCode(data) => ("email_code", String::new(), data.email.clone()),
    };
    Ok(vec![
        factor.id.to_string(),
        factor.subject_id.to_string(),
        kind.to_owned(),
        seed,
        email,
        factor.active.to_string(),
    ])
}

/// The active memberships' table, columns first, adding their role
/// assignments to `assignments`.
async fn memberships(
    conn: &mut Connection,
    tenants: &[Tenant],
    role_keys: &HashMap<uuid::Uuid, String>,
    assignments: &mut Vec<Vec<String>>,
    report: &mut Report,
) -> Result<(Vec<String>, Vec<Vec<String>>), ExportError> {
    let mut kept = Vec::new();
    for tenant in tenants {
        for membership in memberships::list_for_tenant(conn, tenant.id, false).await? {
            if membership.state != MembershipState::Active {
                report.leave_out("ended memberships");
            } else if membership.managed_by.is_some() {
                report.leave_out("memberships an identity provider manages");
            } else {
                for assignment in roles::assignments_of_membership(conn, membership.id).await? {
                    if let Some(row) = assignment_row(&assignment, role_keys, report) {
                        assignments.push(row);
                    }
                }
                kept.push(membership);
            }
        }
    }
    report.wrote("memberships", kept.len());
    let fact_keys: Vec<String> = kept
        .iter()
        .filter_map(|m| m.facts.as_object())
        .flat_map(|facts| facts.keys().cloned())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut rows = Vec::new();
    for membership in &kept {
        let mut row = vec![
            membership.id.to_string(),
            membership.subject_id.to_string(),
            membership.tenant_id.to_string(),
        ];
        for key in &fact_keys {
            row.push(match membership.facts.get(key) {
                None | Some(serde_json::Value::Null) => String::new(),
                Some(value) => fact_cell(key, value)?,
            });
        }
        rows.push(row);
    }
    let mut columns = vec!["id".to_owned(), "subject".into(), "tenant".into()];
    columns.extend(fact_keys.iter().map(|key| format!("fact.{key}")));
    Ok((columns, rows))
}

async fn all_tenants(conn: &mut Connection) -> Result<Vec<Tenant>, ExportError> {
    let mut all = Vec::new();
    let mut before = None;
    loop {
        let page = tenants::list(conn, None, before, PAGE).await?;
        let full = i64::try_from(page.len()) == Ok(PAGE);
        before = page.last().map(|t| t.id);
        all.extend(page.into_iter().filter(|t| t.id != ROOT));
        if !full {
            return Ok(all);
        }
    }
}

async fn all_subjects(conn: &mut Connection) -> Result<Vec<Subject>, ExportError> {
    let mut all = Vec::new();
    let mut before = None;
    loop {
        let page = subjects::list(conn, None, None, before, PAGE).await?;
        let full = i64::try_from(page.len()) == Ok(PAGE);
        before = page.last().map(|s| s.id);
        all.extend(page);
        if !full {
            all.sort_by_key(|s| s.id);
            return Ok(all);
        }
    }
}

/// Tenants with every parent before its children, siblings by id.
fn in_tree_order(mut tenants: Vec<Tenant>) -> Vec<Tenant> {
    tenants.sort_by_key(|t| t.id);
    let mut ordered = Vec::with_capacity(tenants.len());
    let mut parents = vec![ROOT];
    while let Some(parent) = parents.pop() {
        let children: Vec<Tenant> = tenants
            .iter()
            .filter(|t| t.parent_id.unwrap_or(ROOT) == parent)
            .cloned()
            .collect();
        parents.extend(children.iter().rev().map(|t| t.id));
        ordered.extend(children);
    }
    ordered
}

fn tenant_reference(id: Option<TenantId>) -> String {
    match id {
        Some(id) if id != ROOT => id.to_string(),
        _ => "root".to_owned(),
    }
}

/// A credential's row, or why it's left out.
fn credential_row(credential: &Credential) -> Result<Vec<String>, &'static str> {
    if credential.revoked_at.is_some() {
        return Err("revoked credentials");
    }
    let mut identifier = credential.identifier.clone();
    let (mut password_hash, mut provider, mut provider_subject) =
        (String::new(), String::new(), String::new());
    let mut slots = vec![String::new(); 6];
    match &credential.data {
        CredentialData::Password(data) => password_hash.clone_from(&data.hash),
        CredentialData::SecretKey(data) => {
            slots = [&data.a, &data.b]
                .into_iter()
                .flat_map(slot_cells)
                .collect();
        }
        CredentialData::EmailLink | CredentialData::PhoneOtp => {}
        CredentialData::Federated(data) => {
            // Bootstrap derives a federated credential's identifier.
            identifier = String::new();
            provider.clone_from(&data.provider);
            provider_subject.clone_from(&data.subject);
        }
        CredentialData::Client => return Err("OIDC client credentials"),
        CredentialData::PublicKey(_) => return Err("passkeys"),
    }
    let mut row = vec![
        credential.id.to_string(),
        credential.subject_id.to_string(),
        credential.data.kind().as_str().to_owned(),
        identifier,
        password_hash,
        credential.mfa_factors_required.to_string(),
        credential.session_flags.join("|"),
        provider,
        provider_subject,
    ];
    row.extend(slots);
    Ok(row)
}

fn slot_cells(slot: &SecretSlotData) -> [String; 3] {
    [
        slot.hash.clone(),
        timestamp(slot.created_at),
        slot.expires_at.map(timestamp).unwrap_or_default(),
    ]
}

fn timestamp(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::AutoSi, true)
}

fn assignment_row(
    assignment: &RoleAssignment,
    role_keys: &HashMap<uuid::Uuid, String>,
    report: &mut Report,
) -> Option<Vec<String>> {
    if assignment.managed_by.is_some() {
        report.leave_out("role assignments an identity provider manages");
        return None;
    }
    let role = role_keys.get(&assignment.role_id)?.clone();
    let (membership, subject) = match assignment.target {
        AssignmentTarget::Membership(id) => (id.to_string(), String::new()),
        AssignmentTarget::Subject(id) => (String::new(), id.to_string()),
    };
    let (scope_kind, scope_id) = assignment
        .scope
        .as_ref()
        .map(|scope| (scope.kind.clone(), scope.id.clone()))
        .unwrap_or_default();
    Some(vec![membership, subject, role, scope_kind, scope_id])
}

fn roles_value(roles: &[Role]) -> Value {
    Value::List(
        roles
            .iter()
            .filter(|role| !role.builtin)
            .map(|role| {
                let mut fields = vec![
                    ("key", Value::text(&role.key)),
                    ("priority", Value::Number(i64::from(role.priority))),
                    ("metadata", metadata_value(&role.metadata)),
                    ("policies", policies_value(&role.policies)),
                ];
                if let Some(template) = &role.template {
                    fields.push(("template", Value::text(template)));
                }
                Value::map(fields)
            })
            .collect(),
    )
}

fn policies_value(policies: &[Policy]) -> Value {
    Value::List(
        policies
            .iter()
            .map(|policy| {
                Value::map([
                    ("action", Value::text(&policy.action)),
                    (
                        "effect",
                        Value::text(match policy.effect {
                            Effect::Allow => "allow",
                            Effect::Deny => "deny",
                        }),
                    ),
                    ("scope_bound", Value::Bool(policy.scope_bound)),
                ])
            })
            .collect(),
    )
}

/// Metadata as stored. Styx has no null that Konklav reads as one, so null
/// values are left out, as they are when absent.
fn metadata_value(metadata: &serde_json::Value) -> Value {
    match metadata {
        serde_json::Value::Object(fields) => Value::Map(
            fields
                .iter()
                .filter(|(_, value)| !value.is_null())
                .map(|(key, value)| (key.clone(), metadata_value(value)))
                .collect(),
        ),
        serde_json::Value::Array(items) => Value::List(items.iter().map(metadata_value).collect()),
        serde_json::Value::String(text) => Value::text(text),
        serde_json::Value::Bool(value) => Value::Bool(*value),
        serde_json::Value::Number(number) => number
            .as_i64()
            .map_or_else(|| Value::text(number.to_string()), Value::Number),
        serde_json::Value::Null => Value::Map(Vec::new()),
    }
}

/// Facts as both formats write them: scalars as text, lists of text.
fn facts_value(facts: &serde_json::Value) -> Result<Value, ExportError> {
    let Some(fields) = facts.as_object() else {
        return Ok(Value::Map(Vec::new()));
    };
    let mut out = Vec::new();
    for (key, value) in fields {
        match value {
            serde_json::Value::Null => {}
            serde_json::Value::Array(items) => out.push((
                key.clone(),
                Value::List(
                    items
                        .iter()
                        .map(|item| scalar(key, item).map(Value::Text))
                        .collect::<Result<_, _>>()?,
                ),
            )),
            scalar_value => out.push((key.clone(), Value::Text(scalar(key, scalar_value)?))),
        }
    }
    Ok(Value::Map(out))
}

fn fact_cell(key: &str, value: &serde_json::Value) -> Result<String, ExportError> {
    match value {
        serde_json::Value::Array(items) => Ok(items
            .iter()
            .map(|item| scalar(key, item))
            .collect::<Result<Vec<_>, _>>()?
            .join("|")),
        value => scalar(key, value),
    }
}

fn scalar(key: &str, value: &serde_json::Value) -> Result<String, ExportError> {
    match value {
        serde_json::Value::String(text) => Ok(text.clone()),
        serde_json::Value::Number(number) => Ok(number.to_string()),
        serde_json::Value::Bool(value) => Ok(value.to_string()),
        _ => Err(ExportError::Unsupported(format!(
            "fact {key} holds {value}, which a bootstrap set can't write"
        ))),
    }
}

/// A value in a Styx document.
enum Value {
    Text(String),
    Number(i64),
    Bool(bool),
    List(Vec<Value>),
    Map(Vec<(String, Value)>),
}

impl Value {
    fn text(text: impl Into<String>) -> Self {
        Self::Text(text.into())
    }

    fn map<'a>(fields: impl IntoIterator<Item = (&'a str, Value)>) -> Self {
        Self::Map(
            fields
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect(),
        )
    }

    /// Strings are always quoted: JSON's string escapes are valid in Styx,
    /// and quoting keeps text such as `true` or `10` text.
    fn styx(&self, depth: usize) -> String {
        let (indent, inner) = ("    ".repeat(depth), "    ".repeat(depth + 1));
        match self {
            Self::Text(text) => quoted(text),
            Self::Number(number) => number.to_string(),
            Self::Bool(value) => value.to_string(),
            Self::List(items) if items.is_empty() => "()".to_owned(),
            Self::List(items) => {
                let mut out = "(\n".to_owned();
                for item in items {
                    let _ = writeln!(out, "{inner}{}", item.styx(depth + 1));
                }
                out + &indent + ")"
            }
            Self::Map(fields) if fields.is_empty() => "{}".to_owned(),
            Self::Map(fields) => {
                let mut out = "{\n".to_owned();
                for (key, value) in fields {
                    let key = if is_bare(key) {
                        key.clone()
                    } else {
                        quoted(key)
                    };
                    let _ = writeln!(out, "{inner}{key} {}", value.styx(depth + 1));
                }
                out + &indent + "}"
            }
        }
    }
}

fn quoted(text: &str) -> String {
    serde_json::Value::String(text.to_owned()).to_string()
}

fn is_bare(key: &str) -> bool {
    key.chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// A CSV table with a header row. A cell is quoted when it holds a comma,
/// quote or line break, or starts or ends with a space.
fn table<C: AsRef<str>>(columns: &[C], rows: &[Vec<String>]) -> String {
    let line = |cells: &mut dyn Iterator<Item = &str>| {
        cells
            .map(|cell| {
                if cell.contains([',', '"', '\n', '\r'])
                    || cell.starts_with(' ')
                    || cell.ends_with(' ')
                {
                    format!("\"{}\"", cell.replace('"', "\"\""))
                } else {
                    cell.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join(",")
            + "\n"
    };
    let mut out = line(&mut columns.iter().map(AsRef::as_ref));
    for row in rows {
        out += &line(&mut row.iter().map(String::as_str));
    }
    out
}

fn write(directory: &Path, set: &Set) -> Result<(), ExportError> {
    let failed = |path: &Path| {
        let path = path.display().to_string();
        move |source| ExportError::Write { path, source }
    };
    match std::fs::read_dir(directory) {
        Ok(mut entries) => {
            if entries.next().is_some() {
                return Err(ExportError::NotEmpty(directory.display().to_string()));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(directory).map_err(failed(directory))?;
        }
        Err(error) => return Err(failed(directory)(error)),
    }
    restrict(directory, 0o700).map_err(failed(directory))?;
    let catalog = serde_json::to_string_pretty(&set.catalog).unwrap_or_default() + "\n";
    let files = [
        ("catalog.json", catalog.as_str()),
        ("set.styx", &set.document),
    ]
    .into_iter()
    .chain(set.tables.iter().map(|(name, text)| (*name, text.as_str())));
    for (name, text) in files {
        let path = directory.join(name);
        std::fs::write(&path, text).map_err(failed(&path))?;
        restrict(&path, 0o600).map_err(failed(&path))?;
    }
    Ok(())
}

/// Only the owner may read what holds hashes and seeds.
#[cfg(unix)]
fn restrict(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn restrict(_: &Path, _: u32) -> std::io::Result<()> {
    Ok(())
}
