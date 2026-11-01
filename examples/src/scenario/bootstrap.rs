//! Seeding a new deployment with `konklav-server bootstrap`.
//!
//! 1. A dry run reports what the nested example set would create.
//! 2. Applying it creates tenants, roles, people and their grants.
//! 3. Applying it again changes nothing.
//! 4. Konklav starts, and a person from the set signs in with the password
//!    hash they were imported with.

use std::path::Path;

use serde_json::json;

use crate::harness::{Server, Setup, data_dir};
use crate::{Result, check, fail, step};

const EMAIL: &str = "ada@acme.example";
const PASSWORD: &str = "correct horse battery";

/// Runs `bootstrap` with `args`, printing its report, and returns its exit
/// code.
async fn bootstrap(server: &Server, args: &[&str]) -> Result<i32> {
    let output = server.run(&[&["bootstrap"], args].concat()).await?;
    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    output
        .status
        .code()
        .ok_or_else(|| fail("bootstrap was killed"))
}

/// Runs the scenario against a server started from `binary`.
pub async fn run(binary: &Path) -> Result<()> {
    let mut server = Server::prepare(&Setup {
        binary: Some(binary.to_owned()),
        ..Setup::default()
    })
    .await?;
    let set = data_dir().join("bootstrap/nested/seed.styx");
    let set = set.to_str().ok_or_else(|| fail("a non-UTF-8 path"))?;

    step("a dry run of the nested example set");
    let code = bootstrap(&server, &["--dry-run", set]).await?;
    check(code == 0, || format!("the dry run exited {code}"))?;

    step("applying it");
    let code = bootstrap(&server, &[set]).await?;
    check(code == 0, || format!("applying exited {code}"))?;

    step("applying it again changes nothing");
    let output = server.run(&["bootstrap", set]).await?;
    let report = String::from_utf8_lossy(&output.stdout);
    print!("{report}");
    check(output.status.success(), || {
        format!("re-applying failed: {report}")
    })?;
    let changed = report.lines().skip(1).any(|line| {
        let columns = line.split_whitespace().collect::<Vec<_>>();
        // kind (possibly two words), created, skipped, updated, conflicts
        columns.len() >= 5
            && columns[columns.len() - 4]
                .parse::<u32>()
                .is_ok_and(|n| n > 0)
    });
    check(!changed, || format!("a re-run created something: {report}"))?;

    step("starting Konklav");
    server.serve().await?;
    step(&format!("{EMAIL} signs in with their imported password"));
    let (status, body) = server
        .post(
            "/v1/login/password",
            &json!({"identifier": EMAIL, "password": PASSWORD}),
        )
        .await?;
    check(status.is_success(), || {
        format!("signing in: {status} {body}")
    })?;
    step("signed in");
    Ok(())
}
