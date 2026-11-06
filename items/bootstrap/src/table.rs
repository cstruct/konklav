//! Flat tables: one CSV file per kind of record, with a header row. Rows
//! name other records by id. Empty cells are absent values, lists are
//! separated by `|`, and facts are `fact.<key>` columns.

use std::collections::BTreeMap;
use std::path::Path;

use crate::model::{
    Assignment, AssignmentTarget, BootstrapSet, Credential, CredentialMaterial, FactValue, Factor,
    FactorMaterial, Facts, Id, Located, Location, Membership, MembershipRef, RegisteredScope,
    SecretSlot, Session, Subject, SubjectKind, SubjectRef, SubjectState, Tenant, TenantRef,
};
use crate::{Problem, line_of};

/// The columns each table accepts, required ones first. Facts come on top.
fn columns(table: &str) -> (&'static [&'static str], &'static [&'static str], bool) {
    match table {
        "tenants.csv" => (&["id"], &["parent", "templates"], true),
        "subjects.csv" => (&["id"], &["kind", "state"], false),
        "credentials.csv" => (
            &["id", "subject", "kind"],
            &[
                "identifier",
                "password_hash",
                "password",
                "mfa_factors_required",
                "session_flags",
                "provider",
                "provider_subject",
                "a_hash",
                "a_created_at",
                "a_expires_at",
                "b_hash",
                "b_created_at",
                "b_expires_at",
            ],
            false,
        ),
        "mfa_factors.csv" => (
            &["id", "subject", "kind"],
            &["seed_base32", "email", "active"],
            false,
        ),
        "memberships.csv" => (&["id", "subject", "tenant"], &[], true),
        "assignments.csv" => (
            &["role"],
            &["membership", "subject", "scope_kind", "scope_id"],
            false,
        ),
        "registered_scopes.csv" => (&["kind", "id", "tenant"], &["containers"], false),
        "sessions.csv" => (
            &[
                "id",
                "subject",
                "credential",
                "stage",
                "auth_time",
                "version",
                "refresh_hash",
                "expires_at",
            ],
            &[
                "tenant",
                "membership",
                "client_kind",
                "amr",
                "flags",
                "impersonator",
                "revoked_at",
            ],
            false,
        ),
        _ => (&[], &[], false),
    }
}

struct Row<'a> {
    cells: BTreeMap<&'a str, &'a str>,
    at: Location,
    problems: Vec<Problem>,
}

impl Row<'_> {
    fn get(&self, column: &str) -> Option<&str> {
        self.cells
            .get(column)
            .map(|cell| cell.trim())
            .filter(|cell| !cell.is_empty())
    }

    /// A required cell; a problem and an empty string when it is empty.
    fn required(&mut self, column: &str) -> String {
        match self.get(column) {
            Some(value) => value.to_owned(),
            None => {
                self.problems
                    .push(Problem::at(&self.at, format!("`{column}` is empty")));
                String::new()
            }
        }
    }

    fn id(&mut self, column: &str) -> Id {
        Id::parse(&self.required(column))
    }

    fn optional_id(&self, column: &str) -> Option<Id> {
        self.get(column).map(Id::parse)
    }

    fn list(&self, column: &str) -> Vec<String> {
        self.get(column)
            .map(|cell| {
                cell.split('|')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    }

    fn parsed<T: std::str::FromStr>(&mut self, column: &str, what: &str) -> Option<T> {
        let cell = self.get(column)?.to_owned();
        match cell.parse() {
            Ok(value) => Some(value),
            Err(_) => {
                self.problems.push(Problem::at(
                    &self.at,
                    format!("`{column}` must be {what}, not `{cell}`"),
                ));
                None
            }
        }
    }

    fn facts(&self) -> Facts {
        self.cells
            .iter()
            .filter_map(|(column, cell)| {
                let key = column.strip_prefix("fact.")?;
                let cell = cell.trim();
                (!cell.is_empty()).then(|| (key.to_owned(), FactValue::Text(cell.to_owned())))
            })
            .collect()
    }

    fn one_of<T>(&mut self, column: &str, options: &[(&str, T)], default: Option<T>) -> Option<T>
    where
        T: Copy,
    {
        let Some(cell) = self.get(column).map(str::to_owned) else {
            if default.is_none() {
                self.problems
                    .push(Problem::at(&self.at, format!("`{column}` is empty")));
            }
            return default;
        };
        if let Some((_, value)) = options.iter().find(|(name, _)| *name == cell) {
            return Some(*value);
        }
        let names: Vec<_> = options.iter().map(|(name, _)| *name).collect();
        self.problems.push(Problem::at(
            &self.at,
            format!(
                "`{column}` must be one of {}, not `{cell}`",
                names.join(", ")
            ),
        ));
        None
    }
}

pub(crate) fn read(file: &Path, table: &str, text: &str) -> Result<BootstrapSet, Vec<Problem>> {
    let (required, optional, facts) = columns(table);
    let mut reader = csv::ReaderBuilder::new()
        .flexible(false)
        .from_reader(text.as_bytes());
    let header_at = Location {
        file: file.to_owned(),
        line: 1,
    };
    let headers = reader
        .headers()
        .map_err(|error| vec![Problem::at(&header_at, error.to_string())])?
        .clone();
    let mut problems = Vec::new();
    for column in &headers {
        let known = required.contains(&column)
            || optional.contains(&column)
            || (facts && column.starts_with("fact.") && column.len() > "fact.".len());
        if !known {
            problems.push(Problem::at(
                &header_at,
                format!("unknown column `{column}`"),
            ));
        }
    }
    for column in required {
        if !headers.iter().any(|h| h == *column) {
            problems.push(Problem::at(
                &header_at,
                format!("missing column `{column}`"),
            ));
        }
    }
    if !problems.is_empty() {
        return Err(problems);
    }

    let mut set = BootstrapSet::default();
    let mut positions: BTreeMap<SubjectRef, usize> = BTreeMap::new();
    for record in reader.records() {
        let record = match record {
            Ok(record) => record,
            Err(error) => {
                let line = error
                    .position()
                    .map_or(1, |p| usize::try_from(p.line()).unwrap_or(1));
                problems.push(Problem::at(
                    &Location {
                        file: file.to_owned(),
                        line,
                    },
                    error.to_string(),
                ));
                continue;
            }
        };
        let line = record.position().map_or_else(
            || line_of(text, 0),
            |p| usize::try_from(p.line()).unwrap_or(1),
        );
        let mut row = Row {
            cells: headers.iter().zip(record.iter()).collect(),
            at: Location {
                file: file.to_owned(),
                line,
            },
            problems: Vec::new(),
        };
        add_row(&mut set, table, &mut row, &mut positions);
        problems.append(&mut row.problems);
    }
    if problems.is_empty() {
        Ok(set)
    } else {
        Err(problems)
    }
}

/// Turns one row of `table` into its record.
fn add_row(
    set: &mut BootstrapSet,
    table: &str,
    row: &mut Row<'_>,
    positions: &mut BTreeMap<SubjectRef, usize>,
) {
    let at = row.at.clone();
    match table {
        "tenants.csv" => {
            let tenant = Tenant {
                id: row.id("id"),
                parent: row.get("parent").map_or(TenantRef::Root, TenantRef::parse),
                facts: row.facts(),
                templates: row.list("templates"),
            };
            set.tenants.push(Located { value: tenant, at });
        }
        "subjects.csv" => {
            let id = row.id("id");
            let kind = row.one_of(
                "kind",
                &[
                    ("human", SubjectKind::Human),
                    ("service", SubjectKind::Service),
                ],
                Some(SubjectKind::Human),
            );
            let state = row.one_of(
                "state",
                &[
                    ("active", SubjectState::Active),
                    ("disabled", SubjectState::Disabled),
                ],
                Some(SubjectState::Active),
            );
            if let (Some(kind), Some(state)) = (kind, state) {
                set.subjects.push(Located {
                    value: Subject {
                        key: SubjectRef::Id(id),
                        kind,
                        state,
                    },
                    at,
                });
            }
        }
        "credentials.csv" => {
            if let Some(credential) = credential(row) {
                set.credentials.push(Located {
                    value: credential,
                    at,
                });
            }
        }
        "mfa_factors.csv" => {
            if let Some(factor) = factor(row, positions) {
                set.factors.push(Located { value: factor, at });
            }
        }
        "memberships.csv" => {
            let membership = Membership {
                id: Some(row.id("id")),
                subject: SubjectRef::Id(row.id("subject")),
                tenant: TenantRef::parse(&row.required("tenant")),
                facts: row.facts(),
            };
            set.memberships.push(Located {
                value: membership,
                at,
            });
        }
        "assignments.csv" => {
            if let Some(assignment) = assignment(row) {
                set.assignments.push(Located {
                    value: assignment,
                    at,
                });
            }
        }
        "registered_scopes.csv" => {
            if let Some(scope) = registered_scope(row) {
                set.registered_scopes.push(Located { value: scope, at });
            }
        }
        "sessions.csv" => {
            let session = session(row);
            set.sessions.push(Located { value: session, at });
        }
        _ => {}
    }
}

fn session(row: &mut Row<'_>) -> Session {
    let version = row.parsed::<i64>("version", "a whole number").unwrap_or(1);
    Session {
        id: row.id("id"),
        subject: row.id("subject"),
        credential: row.id("credential"),
        tenant: row.optional_id("tenant"),
        membership: row.optional_id("membership"),
        stage: row.required("stage"),
        client_kind: row.get("client_kind").map(str::to_owned),
        amr: row.list("amr"),
        flags: row.list("flags"),
        impersonator: row.optional_id("impersonator"),
        auth_time: row.required("auth_time"),
        version,
        refresh_hash: row.required("refresh_hash"),
        expires_at: row.required("expires_at"),
        revoked_at: row.get("revoked_at").map(str::to_owned),
    }
}

fn factor(row: &mut Row<'_>, positions: &mut BTreeMap<SubjectRef, usize>) -> Option<Factor> {
    let id = row.id("id");
    let subject = SubjectRef::Id(row.id("subject"));
    let active = row
        .parsed::<bool>("active", "true or false")
        .unwrap_or(true);
    let material = match row.required("kind").as_str() {
        "totp" => FactorMaterial::Totp {
            seed_base32: row.required("seed_base32"),
        },
        "email_code" => FactorMaterial::EmailCode {
            email: row.required("email"),
        },
        "" => return None,
        other => {
            let message = format!("`kind` must be totp or email_code, not `{other}`");
            row.problems.push(Problem::at(&row.at, message));
            return None;
        }
    };
    let position = positions.entry(subject.clone()).or_default();
    *position += 1;
    Some(Factor {
        id: Some(id),
        subject,
        position: *position,
        active,
        material,
    })
}

fn assignment(row: &mut Row<'_>) -> Option<Assignment> {
    let target = match (row.optional_id("membership"), row.optional_id("subject")) {
        (Some(membership), None) => AssignmentTarget::Membership(MembershipRef::Id(membership)),
        (None, Some(subject)) => AssignmentTarget::Global(SubjectRef::Id(subject)),
        _ => {
            row.problems.push(Problem::at(
                &row.at,
                "give either `membership` (a role in its tenant) or `subject` (a global role)",
            ));
            return None;
        }
    };
    let scope = match (row.get("scope_kind"), row.get("scope_id")) {
        (Some(kind), Some(id)) => Some((kind.to_owned(), id.to_owned())),
        (None, None) => None,
        _ => {
            row.problems.push(Problem::at(
                &row.at,
                "give both `scope_kind` and `scope_id`, or neither",
            ));
            return None;
        }
    };
    Some(Assignment {
        target,
        role: row.required("role"),
        scope,
    })
}

/// A registered scope. Its containers are `<kind>:<id>` items, split at
/// the first `:`, so a container's kind can't hold `:` here, nor its id
/// `|`; a nested document can hold any.
// r[impl bootstrap.registered.shape]
fn registered_scope(row: &mut Row<'_>) -> Option<RegisteredScope> {
    let kind = row.required("kind");
    let id = row.required("id");
    let tenant = TenantRef::parse(&row.required("tenant"));
    let mut containers = Vec::new();
    for item in row.list("containers") {
        match item.split_once(':') {
            Some((kind, id)) if !kind.trim().is_empty() && !id.trim().is_empty() => {
                containers.push((kind.trim().to_owned(), id.trim().to_owned()));
            }
            _ => {
                row.problems.push(Problem::at(
                    &row.at,
                    format!("a containing scope is `<kind>:<id>`, not `{item}`"),
                ));
                return None;
            }
        }
    }
    (!kind.is_empty() && !id.is_empty()).then_some(RegisteredScope {
        kind,
        id,
        tenant,
        containers,
    })
}

fn slot(row: &mut Row<'_>, name: &str) -> SecretSlot {
    SecretSlot {
        hash: row.required(&format!("{name}_hash")),
        created_at: row.required(&format!("{name}_created_at")),
        expires_at: row.get(&format!("{name}_expires_at")).map(str::to_owned),
    }
}

fn credential(row: &mut Row<'_>) -> Option<Credential> {
    let id = row.id("id");
    let subject = SubjectRef::Id(row.id("subject"));
    let mfa_factors_required = row
        .parsed::<i16>("mfa_factors_required", "a small whole number")
        .unwrap_or(0);
    let at = row.at.clone();
    let material = match row.required("kind").as_str() {
        "password" => match (row.get("password_hash"), row.get("password")) {
            (Some(hash), None) => CredentialMaterial::PasswordHash(hash.to_owned()),
            (None, Some(password)) => CredentialMaterial::Password(password.to_owned()),
            _ => {
                row.problems.push(Problem::at(
                    &at,
                    "a password needs exactly one of `password_hash` and `password`",
                ));
                return None;
            }
        },
        "secret_key" => CredentialMaterial::SecretKey {
            a: slot(row, "a"),
            b: slot(row, "b"),
        },
        "email_link" => CredentialMaterial::EmailLink,
        "phone_otp" => CredentialMaterial::PhoneOtp,
        "federated" => CredentialMaterial::Federated {
            provider: row.required("provider"),
            subject: row.required("provider_subject"),
        },
        "" => return None,
        other => {
            row.problems.push(Problem::at(
                &at,
                format!(
                    "`kind` must be password, secret_key, email_link, phone_otp or federated, \
                     not `{other}`"
                ),
            ));
            return None;
        }
    };
    let identifier = match material {
        CredentialMaterial::Federated { .. } => None,
        _ => Some(row.required("identifier")),
    };
    Some(Credential {
        id: Some(id),
        subject,
        identifier,
        mfa_factors_required,
        session_flags: row.list("session_flags"),
        material,
    })
}
