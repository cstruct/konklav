//! The typed control-plane commands: `tenants`, `subjects`, `invites`,
//! `roles`, `assignments`, `sessions`, `explain` and `batch`.
//!
//! Each prints a table or a short summary, or with `--json` the value
//! Konklav answered with.

use std::process::ExitCode;

use clap::{Args, Subcommand, ValueEnum};
use konklav_api::{
    AssignRole, Batch, CreateInvite, CreateSubject, CreateTenant, InviteQuery, PutRole,
    RevokeSessions, SessionFilter, SessionQuery, SubjectKind, SubjectQuery, TenantQuery,
    TenantState,
};
use konklav_cli::control::Target;
use konklav_cli::{Error, Result, Session};
use serde::Serialize;
use serde_json::{Value, json};

#[derive(Subcommand)]
pub enum Tenants {
    /// List tenants, newest first.
    List {
        /// Only children of this tenant (an id, a key or `root`).
        #[arg(long)]
        parent: Option<String>,
        #[command(flatten)]
        page: Page,
    },
    /// Show a tenant.
    Get { tenant: String },
    /// Create a tenant.
    Create {
        /// Its parent (an id, a key or `root`); the root tenant by default.
        #[arg(long, default_value = "root")]
        parent: String,
        /// A key to name it by, such as `acme-north`.
        #[arg(long)]
        key: Option<String>,
        /// Its facts, as a JSON object.
        #[arg(long, value_parser = json_object)]
        facts: Option<Value>,
        /// Templates to create its roles from.
        #[arg(long = "template")]
        templates: Vec<String>,
    },
    /// Suspend a tenant.
    Suspend { tenant: String },
    /// Make a suspended tenant active again.
    Activate { tenant: String },
}

#[derive(Subcommand)]
pub enum Subjects {
    /// List subjects, newest first.
    List {
        #[arg(long, value_enum)]
        kind: Option<Kind>,
        /// Only the subject with this login identifier.
        #[arg(long)]
        identifier: Option<String>,
        #[command(flatten)]
        page: Page,
    },
    /// Show a subject with its credentials and MFA factors.
    Get { subject: String },
    /// Create a subject, without credentials.
    Create {
        #[arg(long, value_enum)]
        kind: Kind,
    },
    /// Disable a subject: its sessions end and it can't sign in.
    Disable { subject: String },
    /// Enable a disabled subject.
    Enable { subject: String },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum Kind {
    Human,
    Service,
}

impl From<Kind> for SubjectKind {
    fn from(kind: Kind) -> Self {
        match kind {
            Kind::Human => Self::Human,
            Kind::Service => Self::Service,
        }
    }
}

#[derive(Subcommand)]
pub enum Invites {
    /// List invites, newest first.
    List {
        /// Only invites to this tenant (an id, a key or `root`).
        #[arg(long)]
        tenant: Option<String>,
        #[command(flatten)]
        page: Page,
    },
    /// Show an invite.
    Get { invite: String },
    /// Invite someone, by email or as a link.
    Create {
        /// Send the invite to this address; without it, the invite is a
        /// link, whose token is printed once.
        #[arg(long)]
        email: Option<String>,
        /// The tenant it gives a membership in (an id, a key or `root`).
        #[arg(long)]
        tenant: Option<String>,
        /// Roles it gives; repeat for more.
        #[arg(long = "role")]
        roles: Vec<String>,
        /// How long it can be redeemed.
        #[arg(long, default_value_t = 72)]
        expires_in_hours: i64,
    },
    /// Revoke a pending invite.
    Revoke { invite: String },
}

#[derive(Subcommand)]
pub enum Roles {
    /// List a tenant's roles.
    List { tenant: String },
    /// Show a role.
    Get { tenant: String, key: String },
    /// Create or replace a role from a JSON definition: inline, @file, or
    /// @- for standard input.
    Put {
        tenant: String,
        key: String,
        #[arg(long, short)]
        data: String,
    },
    /// Delete a role.
    Delete { tenant: String, key: String },
}

#[derive(Subcommand)]
pub enum Assignments {
    /// List a subject's global role assignments.
    List { subject: String },
    /// Assign a role.
    Add {
        /// Assign it to this subject, globally.
        #[arg(
            long,
            required_unless_present = "membership",
            conflicts_with = "membership"
        )]
        subject: Option<String>,
        /// Assign it within this membership.
        #[arg(long)]
        membership: Option<String>,
        /// The role's key.
        #[arg(long)]
        role: String,
        /// A scope that bounds it, as JSON.
        #[arg(long, value_parser = json_value)]
        scope: Option<Value>,
    },
    /// Remove a role assignment.
    Remove { assignment: String },
}

#[derive(Subcommand)]
pub enum Sessions {
    /// List sessions, newest first.
    List {
        #[arg(long)]
        subject: Option<String>,
        /// Only sessions that haven't ended.
        #[arg(long)]
        active: bool,
        #[command(flatten)]
        page: Page,
    },
    /// Show a session.
    Get { session: String },
    /// Revoke sessions: one, or all of a subject's, a credential's, a
    /// tenant's or a membership's.
    Revoke {
        #[arg(long)]
        session: Option<String>,
        #[arg(long)]
        subject: Option<String>,
        #[arg(long)]
        credential: Option<String>,
        #[arg(long)]
        tenant: Option<String>,
        #[arg(long)]
        membership: Option<String>,
        /// Recorded with the revocation.
        #[arg(long)]
        reason: Option<String>,
    },
}

#[derive(Args)]
pub struct Explain {
    /// The subject.
    pub subject: String,
    /// The action, such as `docs:read`.
    pub action: String,
    /// In this tenant (an id or a key).
    #[arg(long)]
    pub tenant: Option<String>,
}

#[derive(Subcommand)]
pub enum Batches {
    /// Apply a batch of writes from a JSON file (`@-` for standard input).
    /// Exits with 1 if any operation failed.
    Apply {
        file: String,
        /// Makes retrying safe: Konklav applies a batch with a key it has
        /// seen once. A new key is made unless one is given here or in the
        /// file.
        #[arg(long)]
        idempotency_key: Option<String>,
    },
}

#[derive(Args)]
pub struct Page {
    /// Continue after this id (the `next` of the previous page).
    #[arg(long)]
    before: Option<String>,
    /// At most this many.
    #[arg(long)]
    limit: Option<i64>,
}

fn json_value(text: &str) -> std::result::Result<Value, String> {
    serde_json::from_str(text).map_err(|e| format!("not JSON: {e}"))
}

fn json_object(text: &str) -> std::result::Result<Value, String> {
    json_value(text).and_then(|value| {
        if value.is_object() {
            Ok(value)
        } else {
            Err("not a JSON object".into())
        }
    })
}

fn parse<T: std::str::FromStr>(value: Option<&str>, what: &str) -> Result<Option<T>> {
    value
        .map(|value| {
            value
                .parse()
                .map_err(|_| Error::usage(format!("{what} isn't an id: {value:?}")))
        })
        .transpose()
}

/// Reads a JSON value from inline text, `@file` or `@-`.
pub fn read_json(data: &str) -> Result<Value> {
    let text = match data.strip_prefix('@') {
        Some("-") => {
            let mut text = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut text)
                .map_err(|e| Error::local(e.to_string()))?;
            text
        }
        Some(path) => {
            std::fs::read_to_string(path).map_err(|e| Error::usage(format!("{path}: {e}")))?
        }
        None => data.to_owned(),
    };
    serde_json::from_str(&text).map_err(|e| Error::usage(format!("not JSON: {e}")))
}

fn from_json<T: serde::de::DeserializeOwned>(value: Value, what: &str) -> Result<T> {
    serde_json::from_value(value).map_err(|e| Error::usage(format!("not a valid {what}: {e}")))
}

/// Prints the result: JSON, or the human rendering.
fn show<T: Serialize>(json: bool, value: &T, human: impl FnOnce(&Value) -> String) -> Result<()> {
    let value = serde_json::to_value(value).map_err(|e| Error::local(e.to_string()))?;
    if json {
        println!("{value:#}");
    } else {
        println!("{}", human(&value));
    }
    Ok(())
}

/// A text cell for a JSON value.
fn cell(value: &Value) -> String {
    match value {
        Value::Null => "-".into(),
        Value::String(text) => text.clone(),
        Value::Array(items) => items.iter().map(cell).collect::<Vec<_>>().join(","),
        other => other.to_string(),
    }
}

/// `rows` as a table of `columns`, each a header and a field.
fn table(rows: &[Value], columns: &[(&str, &str)]) -> String {
    if rows.is_empty() {
        return "(none)".into();
    }
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            columns
                .iter()
                .map(|(_, field)| cell(&row[*field]))
                .collect()
        })
        .collect();
    let widths: Vec<usize> = columns
        .iter()
        .enumerate()
        .map(|(i, (header, _))| {
            cells
                .iter()
                .map(|row| row[i].chars().count())
                .chain([header.len()])
                .max()
                .unwrap_or_default()
        })
        .collect();
    let line = |row: Vec<String>| {
        row.iter()
            .zip(&widths)
            .map(|(text, width)| format!("{text:width$}"))
            .collect::<Vec<_>>()
            .join("  ")
            .trim_end()
            .to_owned()
    };
    std::iter::once(line(columns.iter().map(|(h, _)| (*h).to_owned()).collect()))
        .chain(cells.into_iter().map(line))
        .collect::<Vec<_>>()
        .join("\n")
}

/// A page's rows, with a hint for the next page.
fn paged(value: &Value, rows: &str, columns: &[(&str, &str)]) -> String {
    let empty = Vec::new();
    let text = table(value[rows].as_array().unwrap_or(&empty), columns);
    match value["next"].as_str() {
        Some(next) => format!("{text}\n\nMore: --before {next}"),
        None => text,
    }
}

/// `field: value` lines.
fn fields(value: &Value, names: &[&str]) -> String {
    let width = names.iter().map(|n| n.len()).max().unwrap_or_default() + 1;
    names
        .iter()
        .map(|name| format!("{:width$} {}", format!("{name}:"), cell(&value[*name])))
        .collect::<Vec<_>>()
        .join("\n")
}

const TENANT: [(&str, &str); 4] = [
    ("ID", "id"),
    ("KEY", "key"),
    ("STATE", "state"),
    ("PARENT", "parent_id"),
];
const SUBJECT: [(&str, &str); 4] = [
    ("ID", "id"),
    ("KIND", "kind"),
    ("STATE", "state"),
    ("CREATED", "created_at"),
];
const INVITE: [(&str, &str); 6] = [
    ("ID", "id"),
    ("STATE", "state"),
    ("EMAIL", "email"),
    ("TENANT", "tenant"),
    ("ROLES", "roles"),
    ("EXPIRES", "expires_at"),
];
const ROLE: [(&str, &str); 4] = [
    ("KEY", "key"),
    ("TEMPLATE", "template"),
    ("PRIORITY", "priority"),
    ("BUILTIN", "builtin"),
];
const ASSIGNMENT: [(&str, &str); 4] = [
    ("ID", "id"),
    ("ROLE", "role_id"),
    ("SCOPE", "scope"),
    ("MANAGED BY", "managed_by"),
];
const SESSION: [(&str, &str); 6] = [
    ("ID", "id"),
    ("SUBJECT", "subject_id"),
    ("STAGE", "stage"),
    ("CLIENT", "client_kind"),
    ("EXPIRES", "expires_at"),
    ("REVOKED", "revoked_at"),
];

pub async fn tenants(session: &mut Session, json: bool, command: Tenants) -> Result<ExitCode> {
    match command {
        Tenants::List { parent, page } => {
            let query = TenantQuery {
                parent,
                metadata: None,
                before: parse(page.before.as_deref(), "--before")?,
                limit: page.limit,
            };
            let found = session.tenants(&query).await?;
            show(json, &found, |v| paged(v, "tenants", &TENANT))?;
        }
        Tenants::Get { tenant } => {
            let found = session.tenant(&tenant).await?;
            show(json, &found, |v| {
                fields(
                    v,
                    &["id", "key", "state", "parent_id", "facts", "created_at"],
                )
            })?;
        }
        Tenants::Create {
            parent,
            key,
            facts,
            templates,
        } => {
            let created = session
                .create_tenant(&CreateTenant {
                    parent: Some(parent),
                    key,
                    facts: facts.unwrap_or_else(|| json!({})),
                    templates,
                    metadata: json!({}),
                })
                .await?;
            show(json, &created, |v| {
                format!("Created tenant {}.", cell(&v["id"]))
            })?;
        }
        Tenants::Suspend { tenant } => {
            let changed = session
                .set_tenant_state(&tenant, TenantState::Suspended)
                .await?;
            show(json, &changed, |v| format!("Suspended {}.", cell(&v["id"])))?;
        }
        Tenants::Activate { tenant } => {
            let changed = session
                .set_tenant_state(&tenant, TenantState::Active)
                .await?;
            show(json, &changed, |v| format!("Activated {}.", cell(&v["id"])))?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

pub async fn subjects(session: &mut Session, json: bool, command: Subjects) -> Result<ExitCode> {
    match command {
        Subjects::List {
            kind,
            identifier,
            page,
        } => {
            let query = SubjectQuery {
                kind: kind.map(Into::into),
                identifier,
                metadata: None,
                before: parse(page.before.as_deref(), "--before")?,
                limit: page.limit,
            };
            let found = session.subjects(&query).await?;
            show(json, &found, |v| paged(v, "subjects", &SUBJECT))?;
        }
        Subjects::Get { subject } => {
            let found = session.subject(&subject).await?;
            show(json, &found, |v| {
                let credentials = v["credentials"].as_array().cloned().unwrap_or_default();
                format!(
                    "{}\n\nCredentials:\n{}",
                    fields(v, &["id", "kind", "state", "created_at"]),
                    table(
                        &credentials,
                        &[("ID", "id"), ("KIND", "kind"), ("STATE", "state")]
                    )
                )
            })?;
        }
        Subjects::Create { kind } => {
            let created = session
                .create_subject(&CreateSubject {
                    kind: kind.into(),
                    metadata: json!({}),
                })
                .await?;
            show(json, &created, |v| {
                format!("Created subject {}.", cell(&v["id"]))
            })?;
        }
        Subjects::Disable { subject } => {
            let changed = session.set_subject_enabled(&subject, false).await?;
            show(json, &changed, |v| format!("Disabled {}.", cell(&v["id"])))?;
        }
        Subjects::Enable { subject } => {
            let changed = session.set_subject_enabled(&subject, true).await?;
            show(json, &changed, |v| format!("Enabled {}.", cell(&v["id"])))?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

pub async fn invites(session: &mut Session, json: bool, command: Invites) -> Result<ExitCode> {
    match command {
        Invites::List { tenant, page } => {
            let query = InviteQuery {
                tenant,
                metadata: None,
                before: parse(page.before.as_deref(), "--before")?,
                limit: page.limit,
            };
            let found = session.invites(&query).await?;
            show(json, &found, |v| paged(v, "invites", &INVITE))?;
        }
        Invites::Get { invite } => {
            let found = session.invite(&invite).await?;
            show(json, &found, |v| {
                fields(
                    v,
                    &["id", "state", "email", "tenant", "roles", "expires_at"],
                )
            })?;
        }
        Invites::Create {
            email,
            tenant,
            roles,
            expires_in_hours,
        } => {
            let created = session
                .create_invite(&CreateInvite {
                    id: None,
                    email,
                    tenant,
                    roles,
                    facts: json!({}),
                    membership: None,
                    expires_in_hours,
                    metadata: json!({}),
                    public_metadata: json!({}),
                    sign_up: false,
                })
                .await?;
            // The token is the invite: shown once, as the one thing the
            // operator must pass on.
            show(json, &created, |v| match v["token"].as_str() {
                Some(token) => format!(
                    "Created invite {}, until {}.\nIts token, shown only now: {token}",
                    cell(&v["invite_id"]),
                    cell(&v["expires_at"])
                ),
                None => format!(
                    "Sent invite {}, until {}.",
                    cell(&v["invite_id"]),
                    cell(&v["expires_at"])
                ),
            })?;
        }
        Invites::Revoke { invite } => {
            let revoked = session.revoke_invite(&invite).await?;
            show(json, &revoked, |v| {
                format!("Revoked invite {}.", cell(&v["id"]))
            })?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

pub async fn roles(session: &mut Session, json: bool, command: Roles) -> Result<ExitCode> {
    match command {
        Roles::List { tenant } => {
            let found = session.roles(&tenant).await?;
            show(json, &found, |v| {
                table(v.as_array().map_or(&[][..], Vec::as_slice), &ROLE)
            })?;
        }
        Roles::Get { tenant, key } => {
            let found = session.role(&tenant, &key).await?;
            show(json, &found, |v| format!("{v:#}"))?;
        }
        Roles::Put { tenant, key, data } => {
            let role: PutRole = from_json(read_json(&data)?, "role")?;
            let written = session.put_role(&tenant, &key, &role).await?;
            show(json, &written, |v| {
                format!("Saved role {}.", cell(&v["key"]))
            })?;
        }
        Roles::Delete { tenant, key } => {
            let deleted = session.delete_role(&tenant, &key).await?;
            show(json, &deleted, |v| {
                if v["deleted"] == true {
                    format!("Deleted role {key}.")
                } else {
                    format!("There was no role {key}.")
                }
            })?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

pub async fn assignments(
    session: &mut Session,
    json: bool,
    command: Assignments,
) -> Result<ExitCode> {
    match command {
        Assignments::List { subject } => {
            let found = session.global_assignments(&subject).await?;
            show(json, &found, |v| {
                table(v.as_array().map_or(&[][..], Vec::as_slice), &ASSIGNMENT)
            })?;
        }
        Assignments::Add {
            subject,
            membership,
            role,
            scope,
        } => {
            let target = match (subject, membership) {
                (Some(subject), None) => Target::Subject(subject),
                (None, Some(membership)) => Target::Membership(membership),
                _ => return Err(Error::usage("give --subject or --membership")),
            };
            let assign = AssignRole {
                id: None,
                role,
                scope: scope.map(|s| from_json(s, "scope")).transpose()?,
            };
            let assigned = session.assign(&target, &assign).await?;
            show(json, &assigned, |v| {
                format!("Assigned: {}.", cell(&v["id"]))
            })?;
        }
        Assignments::Remove { assignment } => {
            let deleted = session.unassign(&assignment).await?;
            show(json, &deleted, |_| format!("Removed {assignment}."))?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

pub async fn sessions(session: &mut Session, json: bool, command: Sessions) -> Result<ExitCode> {
    match command {
        Sessions::List {
            subject,
            active,
            page,
        } => {
            let query = SessionQuery {
                subject: parse(subject.as_deref(), "--subject")?,
                credential: None,
                active,
                before: parse(page.before.as_deref(), "--before")?,
                limit: page.limit,
            };
            let found = session.sessions(&query).await?;
            show(json, &found, |v| paged(v, "sessions", &SESSION))?;
        }
        Sessions::Get { session: id } => {
            let found = session.konklav_session(&id).await?;
            show(json, &found, |v| {
                fields(
                    v,
                    &[
                        "id",
                        "subject_id",
                        "stage",
                        "client_kind",
                        "tenant_id",
                        "amr",
                        "auth_time",
                        "dpop_jkt",
                        "expires_at",
                        "revoked_at",
                        "revoked_reason",
                    ],
                )
            })?;
        }
        Sessions::Revoke {
            session: one,
            subject,
            credential,
            tenant,
            membership,
            reason,
        } => {
            let filter = SessionFilter {
                session: parse(one.as_deref(), "--session")?,
                subject: parse(subject.as_deref(), "--subject")?,
                credential: parse(credential.as_deref(), "--credential")?,
                tenant: parse(tenant.as_deref(), "--tenant")?,
                membership: parse(membership.as_deref(), "--membership")?,
            };
            if filter == SessionFilter::default() {
                return Err(Error::usage(
                    "name what to revoke: --session, --subject, --credential, --tenant or \
                     --membership",
                ));
            }
            // This command's own session survives a revocation that
            // includes it, so the operator isn't signed out mid-command.
            let keep = session.id().parse().ok();
            let revoked = session
                .revoke_sessions(&RevokeSessions {
                    filter,
                    keep,
                    reason,
                })
                .await?;
            show(json, &revoked, |v| {
                let count = v["revoked"].as_array().map_or(0, Vec::len);
                format!(
                    "Revoked {count} session{}.",
                    if count == 1 { "" } else { "s" }
                )
            })?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

pub async fn explain(session: &mut Session, json: bool, args: Explain) -> Result<ExitCode> {
    let explained = session
        .explain(&args.subject, &args.action, args.tenant.as_deref())
        .await?;
    show(json, &explained, |v| {
        let granted = v["granted_at"].as_array().map_or(0, Vec::len);
        let contributions = v["contributions"].as_array().cloned().unwrap_or_default();
        format!(
            "{}: {}\n\n{}",
            args.action,
            if granted == 0 {
                "not granted".to_owned()
            } else {
                format!("granted at {}", cell(&v["granted_at"]))
            },
            table(
                &contributions,
                &[
                    ("ASSIGNMENT", "assignment"),
                    ("LEVEL", "level"),
                    ("POLICY", "policy"),
                    ("EFFECT", "effect"),
                ]
            )
        )
    })?;
    Ok(ExitCode::SUCCESS)
}

pub async fn batch(session: &mut Session, json: bool, command: Batches) -> Result<ExitCode> {
    let Batches::Apply {
        file,
        idempotency_key,
    } = command;
    let data = if file.starts_with('@') {
        file
    } else {
        format!("@{file}")
    };
    let mut batch: Batch = from_json(read_json(&data)?, "batch")?;
    if idempotency_key.is_some() {
        batch.idempotency_key = idempotency_key;
    }
    let results = session.apply_batch(&batch).await?;
    show(json, &results, |v| {
        let rows: Vec<Value> = batch
            .operations
            .iter()
            .zip(v["results"].as_array().into_iter().flatten())
            .map(|(operation, result)| {
                let method = serde_json::to_value(operation.method).unwrap_or_default();
                json!({
                    "operation": format!("{} {}", cell(&method), operation.path),
                    "status": result["status"],
                })
            })
            .collect();
        table(&rows, &[("OPERATION", "operation"), ("STATUS", "status")])
    })?;
    let failed = results
        .results
        .iter()
        .any(|r| !(200..300).contains(&r.status));
    Ok(if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_align_their_columns() {
        let rows = vec![
            json!({"id": "a", "state": "active"}),
            json!({"id": "bbbb", "state": null}),
        ];
        assert_eq!(
            table(&rows, &[("ID", "id"), ("STATE", "state")]),
            "ID    STATE\na     active\nbbbb  -"
        );
        assert_eq!(table(&[], &[("ID", "id")]), "(none)");
    }
}
