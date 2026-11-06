//! The `bootstrap` command: applies a bootstrap set read by
//! `konklav-bootstrap` to the database, in one transaction.
//!
//! Every record is written in a savepoint of its own. One that fails is
//! rolled back and reported, and the run goes on, so a single run reports
//! every problem and conflict. The transaction commits only when there were
//! none and the run isn't a dry run.

mod catalog;
mod records;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use diesel_async::AsyncConnection;
use konklav_authn::{PasswordHasher, SecretBox};
use konklav_bootstrap::{BootstrapSet, Located, Location, Problem};
use konklav_store::{Connection, Pool};

use crate::error::{ApiError, ErrorCode};
use crate::import::Outcome;

/// How a run behaves.
#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
    /// Do everything but commit.
    pub dry_run: bool,
    /// Accept plaintext passwords, hashing them on the way in.
    pub allow_plaintext_passwords: bool,
}

/// What happened to one kind of record.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tally {
    pub created: usize,
    pub skipped: usize,
    pub updated: usize,
    pub conflicts: usize,
}

/// The result of a run.
#[derive(Debug, Default)]
pub struct Report {
    /// Per kind of record, in the order they are applied.
    pub tallies: Vec<(&'static str, Tally)>,
    pub problems: Vec<Problem>,
    pub conflicts: Vec<Problem>,
    /// Whether the transaction was committed.
    pub committed: bool,
}

impl Report {
    fn tally(&mut self, kind: &'static str) -> &mut Tally {
        if let Some(index) = self.tallies.iter().position(|(k, _)| *k == kind) {
            return &mut self.tallies[index].1;
        }
        self.tallies.push((kind, Tally::default()));
        &mut self.tallies.last_mut().expect("just pushed").1
    }

    /// Counts a record's outcome, or reports why it failed.
    fn record(&mut self, kind: &'static str, at: &Location, outcome: Result<Outcome, ApiError>) {
        let tally = self.tally(kind);
        match outcome {
            Ok(Outcome::Created) => tally.created += 1,
            Ok(Outcome::Skipped) => tally.skipped += 1,
            Ok(Outcome::Updated) => tally.updated += 1,
            Err(error) if error.code == ErrorCode::Conflict => {
                tally.conflicts += 1;
                self.conflicts.push(Problem::at(at, error.message));
            }
            Err(error) => self.problems.push(Problem::at(at, error.message)),
        }
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{:<17} {:>8} {:>8} {:>8} {:>9}",
            "", "created", "skipped", "updated", "conflicts"
        )?;
        for (kind, tally) in &self.tallies {
            writeln!(
                f,
                "{kind:<17} {:>8} {:>8} {:>8} {:>9}",
                tally.created, tally.skipped, tally.updated, tally.conflicts
            )?;
        }
        for problem in &self.problems {
            writeln!(f, "problem: {problem}")?;
        }
        for conflict in &self.conflicts {
            writeln!(f, "conflict: {conflict}")?;
        }
        Ok(())
    }
}

/// What the records being applied need besides a connection.
pub(crate) struct Context<'a> {
    namespace: Option<uuid::Uuid>,
    secrets: &'a SecretBox,
    hasher: PasswordHasher,
    options: Options,
    /// Login identifiers the set gives credentials for, so a subject found
    /// by one is known to be findable again.
    identifiers: BTreeSet<String>,
    /// Subjects found or created by login identifier during this run.
    subjects: BTreeMap<String, konklav_core::SubjectId>,
}

/// Raised to roll the transaction back with the report.
struct Rollback(Report);

impl From<ApiError> for Rollback {
    fn from(error: ApiError) -> Self {
        Self(Report {
            problems: vec![Problem {
                at: None,
                message: error.message,
            }],
            ..Report::default()
        })
    }
}

impl From<diesel::result::Error> for Rollback {
    fn from(error: diesel::result::Error) -> Self {
        ApiError::from(error).into()
    }
}

/// Applies `set`, committing only if every record applied cleanly and the
/// run isn't a dry run.
// r[impl bootstrap.command]
// r[impl bootstrap.atomic]
// r[impl bootstrap.dry-run]
// r[impl bootstrap.events]
pub async fn run(
    pool: &Pool,
    secrets: &SecretBox,
    set: BootstrapSet,
    options: Options,
) -> Result<Report, ApiError> {
    let mut context = Context {
        namespace: set.id_namespace.as_ref().map(|n| n.value),
        secrets,
        hasher: PasswordHasher::default(),
        options,
        identifiers: set
            .credentials
            .iter()
            .filter_map(|c| c.value.identifier.as_deref())
            .map(konklav_store::credentials::normalize_identifier)
            .collect(),
        subjects: BTreeMap::new(),
    };
    let mut conn = pool.get().await?;
    let result = conn
        .transaction::<_, Rollback, _>(async |conn| {
            let report = apply(conn, &mut context, set).await?;
            if report.problems.is_empty() && report.conflicts.is_empty() && !options.dry_run {
                Ok(report)
            } else {
                Err(Rollback(report))
            }
        })
        .await;
    Ok(match result {
        Ok(mut report) => {
            report.committed = true;
            report
        }
        Err(Rollback(report)) => report,
    })
}

/// Applies every record, kind by kind, in an order where each record's
/// references come first.
async fn apply(
    conn: &mut Connection,
    context: &mut Context<'_>,
    set: BootstrapSet,
) -> Result<Report, ApiError> {
    let mut report = Report::default();
    let catalog_document = match &set.catalog {
        Some(catalog) => {
            let outcome = conn
                .transaction::<_, ApiError, _>(async |conn| records::catalog(conn, catalog).await)
                .await;
            report.record("catalog", &catalog.at, outcome);
            konklav_store::catalog::load(conn).await?
        }
        None => konklav_store::catalog::load(conn).await?,
    };
    for template in &set.templates {
        let outcome = conn
            .transaction::<_, ApiError, _>(async |conn| records::template(conn, template).await)
            .await;
        report.record("templates", &template.at, outcome);
    }
    for tenant in parents_first(&set.tenants, context.namespace) {
        let outcome = conn
            .transaction::<_, ApiError, _>(async |conn| {
                records::tenant(conn, context, &catalog_document, tenant).await
            })
            .await;
        report.record("tenants", &tenant.at, outcome);
    }
    for role in &set.roles {
        let outcome = conn
            .transaction::<_, ApiError, _>(async |conn| records::role(conn, context, role).await)
            .await;
        report.record("roles", &role.at, outcome);
    }
    for subject in &set.subjects {
        let outcome = records::subject(conn, context, subject).await;
        report.record("subjects", &subject.at, outcome);
    }
    for credential in &set.credentials {
        let outcome = records::credential(conn, context, credential).await;
        report.record("credentials", &credential.at, outcome);
    }
    for factor in &set.factors {
        let outcome = records::factor(conn, context, factor).await;
        report.record("mfa factors", &factor.at, outcome);
    }
    for membership in &set.memberships {
        let outcome = records::membership(conn, context, &catalog_document, membership).await;
        report.record("memberships", &membership.at, outcome);
    }
    for assignment in &set.assignments {
        let outcome = records::assignment(conn, context, assignment).await;
        report.record("assignments", &assignment.at, outcome);
    }
    let scopes =
        records::registered_scopes(conn, context, &catalog_document, &set.registered_scopes)
            .await?;
    for (at, outcome) in scopes {
        report.record("registered scopes", at, outcome);
    }
    for session in &set.sessions {
        let outcome = records::session(conn, context, session).await;
        report.record("sessions", &session.at, outcome);
    }
    Ok(report)
}

type TenantRecord = Located<konklav_bootstrap::Tenant>;

/// Tenants ordered so a parent in the set comes before its children.
fn parents_first(tenants: &[TenantRecord], namespace: Option<uuid::Uuid>) -> Vec<&TenantRecord> {
    let index: BTreeMap<uuid::Uuid, usize> = tenants
        .iter()
        .enumerate()
        .filter_map(|(i, t)| {
            t.value
                .id
                .resolve(namespace, konklav_bootstrap::Kind::Tenant)
                .map(|id| (id, i))
        })
        .collect();
    let mut order = Ordering {
        tenants,
        index,
        namespace,
        placed: vec![false; tenants.len()],
        ordered: Vec::with_capacity(tenants.len()),
    };
    for i in 0..tenants.len() {
        order.visit(i, 0);
    }
    order.ordered
}

struct Ordering<'a> {
    tenants: &'a [TenantRecord],
    index: BTreeMap<uuid::Uuid, usize>,
    namespace: Option<uuid::Uuid>,
    placed: Vec<bool>,
    ordered: Vec<&'a TenantRecord>,
}

impl<'a> Ordering<'a> {
    /// Places tenant `i` after its parent. `depth` stops a cycle, which
    /// the store then refuses as a missing parent.
    fn visit(&mut self, i: usize, depth: usize) {
        if self.placed[i] || depth > self.tenants.len() {
            return;
        }
        if let konklav_bootstrap::TenantRef::Id(parent) = &self.tenants[i].value.parent
            && let Some(parent) = parent.resolve(self.namespace, konklav_bootstrap::Kind::Tenant)
            && let Some(&p) = self.index.get(&parent)
            && p != i
        {
            self.visit(p, depth + 1);
        }
        if !self.placed[i] {
            self.placed[i] = true;
            let tenant: &'a TenantRecord = &self.tenants[i];
            self.ordered.push(tenant);
        }
    }
}
