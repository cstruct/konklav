#![allow(clippy::too_many_lines)]

mod common;

use std::path::{Path, PathBuf};

use axum::http::{Method, StatusCode};
use common::TestApp;
use diesel_async::RunQueryDsl;
use konklav_server::bootstrap::{self, Options, Report, Tally};

const PASSWORD: &str = "correct horse battery";
const NAMESPACE: &str = "3f1c9a52-6a1e-4d0b-9a0e-6c1d8f0b2e11";

fn examples() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/bootstrap")
}

async fn apply(app: &TestApp, paths: &[PathBuf], options: Options) -> Report {
    let set = konklav_bootstrap::read(paths).unwrap();
    bootstrap::run(app.db.pool(), &app.state.auth.secrets, set, options)
        .await
        .unwrap()
}

fn tally(report: &Report, kind: &str) -> Tally {
    report
        .tallies
        .iter()
        .find(|(k, _)| *k == kind)
        .map(|(_, t)| *t)
        .unwrap_or_default()
}

fn created(n: usize) -> Tally {
    Tally {
        created: n,
        ..Tally::default()
    }
}

fn skipped(n: usize) -> Tally {
    Tally {
        skipped: n,
        ..Tally::default()
    }
}

/// A copy of an example directory with `edits` applied to its files.
fn edited(example: &str, name: &str, edits: &[(&str, &str, &str)]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("konklav-bootstrap-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(example)).unwrap();
    std::fs::copy(examples().join("catalog.json"), dir.join("catalog.json")).unwrap();
    for entry in std::fs::read_dir(examples().join(example)).unwrap() {
        let path = entry.unwrap().path();
        let mut text = std::fs::read_to_string(&path).unwrap();
        for (file, old, new) in edits {
            if path.file_name().unwrap() == *file {
                assert!(text.contains(old), "{file} lacks {old}");
                text = text.replace(old, new);
            }
        }
        std::fs::write(dir.join(example).join(path.file_name().unwrap()), text).unwrap();
    }
    dir.join(example)
}

async fn count(app: &TestApp, table: &str) -> i64 {
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        count: i64,
    }
    let mut conn = app.db.pool().get().await.unwrap();
    diesel::sql_query(format!("select count(*) as count from {table}"))
        .get_result::<Count>(&mut conn)
        .await
        .unwrap()
        .count
}

// r[verify bootstrap.command]
// r[verify bootstrap.idempotent]
// r[verify bootstrap.events]
#[tokio::test(flavor = "multi_thread")]
async fn the_nested_example_applies_once_and_then_skips() {
    let app = TestApp::new().await;
    let seed = [examples().join("nested/seed.styx")];
    let events_before = count(&app, "event").await;
    let first = apply(&app, &seed, Options::default()).await;
    assert!(first.committed, "{first}");
    assert!(
        first.problems.is_empty() && first.conflicts.is_empty(),
        "{first}"
    );
    assert_eq!(tally(&first, "catalog"), created(1));
    assert_eq!(tally(&first, "templates"), created(1));
    assert_eq!(tally(&first, "tenants"), created(2));
    assert_eq!(tally(&first, "roles"), created(2));
    assert_eq!(tally(&first, "subjects"), created(3));
    assert_eq!(tally(&first, "credentials"), created(3));
    assert_eq!(tally(&first, "memberships"), created(2));
    assert_eq!(tally(&first, "assignments"), created(5));
    assert!(
        count(&app, "event").await > events_before,
        "writes emit events"
    );

    let again = apply(&app, &seed, Options::default()).await;
    assert!(
        again.problems.is_empty() && again.conflicts.is_empty(),
        "{again}"
    );
    for (kind, tally) in &again.tallies {
        assert_eq!(
            tally.created + tally.updated,
            0,
            "{kind} changed on a re-run: {again}"
        );
    }
    assert_eq!(tally(&again, "subjects"), skipped(3));

    // Imported people sign in with their imported hashes, and the operator
    // holds what its global roles grant.
    let login = app.login("ada@acme.example", PASSWORD).await;
    assert_eq!(login.status, StatusCode::OK, "{:?}", login.body);
    let ops = app.login("ops@konklav.example", PASSWORD).await;
    let token = ops.body["access_token"].as_str().unwrap();
    let held = app
        .with_bearer(Method::GET, "/v1/capabilities", token)
        .await;
    let capabilities = held.body["capabilities"].as_array().unwrap();
    assert!(
        capabilities.iter().any(|c| c == "konklav:control:all"),
        "{:?}",
        held.body
    );
    assert!(
        capabilities
            .iter()
            .any(|c| c == "konklav:subject:impersonate")
    );
}

// r[verify bootstrap.ids]
// r[verify bootstrap.formats]
// r[verify session.flags.credential]
#[tokio::test(flavor = "multi_thread")]
async fn the_flat_example_derives_ids_from_external_ones() {
    let app = TestApp::new().await;
    let report = apply(&app, &[examples().join("flat")], Options::default()).await;
    assert!(report.committed, "{report}");
    let namespace = uuid::Uuid::parse_str(NAMESPACE).unwrap();
    let subject = uuid::Uuid::new_v5(&namespace, b"subject:4711");
    let detail = app
        .control(Method::GET, &format!("/v1/subjects/{subject}"), None)
        .await;
    assert_eq!(detail.status, StatusCode::OK, "{:?}", detail.body);
    assert_eq!(
        detail.body["credentials"][0]["id"],
        uuid::Uuid::new_v5(&namespace, b"credential:c-4711").to_string()
    );
    let disabled = uuid::Uuid::new_v5(&namespace, b"subject:4712");
    let detail = app
        .control(Method::GET, &format!("/v1/subjects/{disabled}"), None)
        .await;
    assert_eq!(detail.body["state"], "disabled");
    assert_eq!(
        detail.body["credentials"][0]["session_flags"],
        serde_json::json!(["passwordless"]),
        "an email link carries its session flags"
    );
    let child = uuid::Uuid::new_v5(&namespace, b"tenant:org-2");
    let tenant = app
        .control(Method::GET, &format!("/v1/tenants/{child}"), None)
        .await;
    assert_eq!(
        tenant.body["parent_id"],
        uuid::Uuid::new_v5(&namespace, b"tenant:org-1").to_string(),
        "{:?}",
        tenant.body
    );
    let membership = uuid::Uuid::new_v5(&namespace, b"membership:m-4711");
    let detail = app
        .control(Method::GET, &format!("/v1/memberships/{membership}"), None)
        .await;
    assert_eq!(detail.body["facts"]["member_type"], "professional");
    assert_eq!(detail.body["assignments"].as_array().unwrap().len(), 1);
    assert_eq!(
        app.login("cy@org.example", PASSWORD).await.status,
        StatusCode::OK
    );
}

// r[verify bootstrap.dry-run]
#[tokio::test(flavor = "multi_thread")]
async fn a_dry_run_reports_and_writes_nothing() {
    let app = TestApp::new().await;
    let subjects = count(&app, "subject").await;
    let report = apply(
        &app,
        &[examples().join("nested/seed.styx")],
        Options {
            dry_run: true,
            ..Options::default()
        },
    )
    .await;
    assert!(!report.committed);
    assert_eq!(tally(&report, "subjects"), created(3));
    assert_eq!(count(&app, "subject").await, subjects);
}

// r[verify bootstrap.metadata]
#[tokio::test(flavor = "multi_thread")]
async fn template_and_role_metadata_is_stored_and_compared() {
    let app = TestApp::new().await;
    let seed = [examples().join("nested/seed.styx")];
    apply(&app, &seed, Options::default()).await;
    let template = app.control(Method::GET, "/v1/templates/reader", None).await;
    assert_eq!(
        template.body["metadata"],
        serde_json::json!({"label": "Reader", "shown_to": ["members", "admins"]}),
        "{:?}",
        template.body
    );
    let tenant = konklav_bootstrap::derive(
        uuid::Uuid::parse_str(NAMESPACE).unwrap(),
        konklav_bootstrap::Kind::Tenant,
        "acme",
    );
    let role = app
        .control(
            Method::GET,
            &format!("/v1/tenants/{tenant}/roles/editor"),
            None,
        )
        .await;
    assert_eq!(
        role.body["metadata"],
        serde_json::json!({"label": "Editor"}),
        "{:?}",
        role.body
    );

    let changed = edited(
        "nested",
        "metadata",
        &[(
            "seed.styx",
            "metadata {label Editor}",
            "metadata {label Author}",
        )],
    );
    let report = apply(&app, &[changed], Options::default()).await;
    assert!(!report.committed);
    assert_eq!(report.conflicts.len(), 1, "{report}");
}

// r[verify bootstrap.atomic]
// r[verify bootstrap.idempotent]
#[tokio::test(flavor = "multi_thread")]
async fn a_changed_record_is_a_conflict_and_nothing_is_written() {
    let app = TestApp::new().await;
    let flat = examples().join("flat");
    apply(&app, std::slice::from_ref(&flat), Options::default()).await;
    let changed = edited(
        "flat",
        "conflict",
        &[
            ("subjects.csv", "4712,human,disabled", "4712,human,active"),
            (
                "memberships.csv",
                "m-4711,4711,org-1,professional",
                "m-4711,4711,org-1,student",
            ),
            (
                "subjects.csv",
                "4711,human,active\n",
                "4711,human,active\n4713,human,active\n",
            ),
        ],
    );
    let subjects = count(&app, "subject").await;
    let report = apply(&app, &[changed], Options::default()).await;
    assert!(!report.committed);
    assert_eq!(report.conflicts.len(), 2, "{report}");
    assert!(
        report
            .conflicts
            .iter()
            .any(|c| c.at.as_ref().unwrap().line == 4),
        "the disabled subject's row: {report}"
    );
    assert_eq!(
        count(&app, "subject").await,
        subjects,
        "4713 was not written"
    );
}

// r[verify bootstrap.validate-first]
#[tokio::test(flavor = "multi_thread")]
async fn every_problem_with_the_records_is_reported() {
    let app = TestApp::new().await;
    let broken = edited(
        "flat",
        "problems",
        &[
            (
                "memberships.csv",
                "m-4712,4712,org-2,",
                "m-4712,9999,org-2,",
            ),
            (
                "assignments.csv",
                "m-4712,,reader,,",
                "m-4712,,nonexistent,,",
            ),
            (
                "tenants.csv",
                "org-1,root,reader,10",
                "org-1,root,reader,ten",
            ),
        ],
    );
    let tenants = count(&app, "tenant").await;
    let report = apply(&app, std::slice::from_ref(&broken), Options::default()).await;
    assert!(!report.committed);
    let has = |file: &str, line: usize, text: &str| {
        report.problems.iter().any(|p| {
            p.at.as_ref()
                .is_some_and(|at| at.file == broken.join(file) && at.line == line)
                && p.message.contains(text)
        })
    };
    assert!(has("tenants.csv", 2, "whole number"), "{report}");
    assert!(has("memberships.csv", 3, "subject not found"), "{report}");
    assert!(has("assignments.csv", 3, "not found"), "{report}");
    assert_eq!(count(&app, "tenant").await, tenants, "nothing was written");
}

// r[verify bootstrap.secrets]
#[tokio::test(flavor = "multi_thread")]
async fn plaintext_passwords_need_to_be_allowed() {
    let app = TestApp::new().await;
    let dir = std::env::temp_dir().join(format!("konklav-bootstrap-plain-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let seed = dir.join("seed.styx");
    std::fs::write(
        &seed,
        format!("subjects ({{email dev@example.com, password \"{PASSWORD}\"}})\n"),
    )
    .unwrap();
    let refused = apply(&app, std::slice::from_ref(&seed), Options::default()).await;
    assert!(
        refused.problems[0]
            .message
            .contains("--allow-plaintext-passwords"),
        "{refused}"
    );
    let allowed = apply(
        &app,
        std::slice::from_ref(&seed),
        Options {
            allow_plaintext_passwords: true,
            ..Options::default()
        },
    )
    .await;
    assert!(allowed.committed, "{allowed}");
    assert_eq!(
        app.login("dev@example.com", PASSWORD).await.status,
        StatusCode::OK
    );
    let again = apply(
        &app,
        &[seed],
        Options {
            allow_plaintext_passwords: true,
            ..Options::default()
        },
    )
    .await;
    assert_eq!(tally(&again, "credentials"), skipped(1), "{again}");
}

fn read_dir(dir: &Path) -> std::collections::BTreeMap<String, String> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            (name, std::fs::read_to_string(&path).unwrap())
        })
        .collect()
}

// r[verify bootstrap.export]
// r[verify bootstrap.export.registered]
#[tokio::test(flavor = "multi_thread")]
async fn an_exported_set_bootstraps_an_empty_database_unchanged() {
    let app = TestApp::new().await;
    let seeded = apply(
        &app,
        &[examples().join("nested/seed.styx")],
        Options::default(),
    )
    .await;
    assert!(seeded.committed, "{seeded}");
    // What the example lacks: a secret key, a TOTP factor, a global role,
    // a scoped assignment and a disabled subject.
    let service = uuid::Uuid::now_v7();
    app.control(
        Method::PUT,
        &format!("/v1/subjects/{service}"),
        Some(serde_json::json!({"kind": "service"})),
    )
    .await;
    let key = app
        .control(
            Method::POST,
            &format!("/v1/subjects/{service}/credentials"),
            Some(serde_json::json!({"kind": "secret_key"})),
        )
        .await;
    let key_id = key.body["credential"]["id"].as_str().unwrap().to_owned();
    let secret = key.body["secret_keys"]["b"]
        .as_str()
        .unwrap()
        .split_once('.')
        .unwrap()
        .1
        .to_owned();
    let ada = app.human("ada@example.com", PASSWORD).await;
    let seed = konklav_authn::TotpSecret::generate();
    let imported = app
        .control(
            Method::POST,
            "/v1/import/mfa-factors",
            Some(serde_json::json!({"factors": [{
                "id": uuid::Uuid::now_v7(),
                "subject": ada,
                "kind": "totp",
                "seed_base32": seed.to_base32(),
            }]})),
        )
        .await;
    assert_eq!(imported.body["imported"], 1, "{:?}", imported.body);
    app.control(
        Method::PUT,
        "/v1/tenants/root/roles/AUDITOR",
        Some(serde_json::json!({"policies": [{"action": "project:read", "effect": "allow"}]})),
    )
    .await;
    let granted = app
        .control(
            Method::POST,
            &format!("/v1/subjects/{ada}/global-assignments"),
            Some(serde_json::json!({"role": "AUDITOR"})),
        )
        .await;
    assert!(granted.status.is_success(), "{:?}", granted.body);
    let disabled = app.human("gone@example.com", PASSWORD).await;
    app.control(
        Method::POST,
        &format!("/v1/subjects/{disabled}/disable"),
        None,
    )
    .await;

    // A registered scope a table can't hold as written, and a removed one.
    let acme = konklav_bootstrap::derive(
        NAMESPACE.parse().unwrap(),
        konklav_bootstrap::Kind::Tenant,
        "acme",
    );
    let recorded = app
        .control(
            Method::POST,
            "/v1/registered-scopes",
            Some(serde_json::json!({"changes": [
                {"op": "record", "kind": "document", "id": " odd|id", "tenant": acme,
                 "containers": [{"kind": "project", "id": "p|1"}]},
                {"op": "record", "kind": "document", "id": "d-gone", "tenant": acme},
            ]})),
        )
        .await;
    assert!(recorded.status.is_success(), "{:?}", recorded.body);
    let removed = app
        .control(
            Method::DELETE,
            "/v1/registered-scopes/document/d-gone",
            None,
        )
        .await;
    assert!(removed.status.is_success(), "{:?}", removed.body);

    let dir = std::env::temp_dir().join(format!("konklav-export-{}", uuid::Uuid::now_v7()));
    let first =
        konklav_server::export::run(app.db.pool(), &app.state.auth.secrets, &dir.join("first"))
            .await
            .unwrap();
    assert_eq!(first.written["subjects"], 6, "{first}");
    let files = read_dir(&dir.join("first"));
    assert!(
        files["credentials.csv"].contains("$argon2id$"),
        "hashes are kept"
    );
    assert!(
        files["mfa_factors.csv"].contains(&seed.to_base32()),
        "seeds are decrypted"
    );
    assert_eq!(first.written["registered scopes"], 3, "{first}");
    assert_eq!(first.left_out["removed registered scopes"], 1, "{first}");
    assert_eq!(
        files["registered_scopes.csv"],
        format!(
            "kind,id,tenant,containers\ndocument,d-1,{acme},project:p-1\ndocument,d-2,{acme},\n"
        )
    );
    assert!(
        files["set.styx"].contains("registered_scopes")
            && files["set.styx"].contains("\" odd|id\""),
        "what a table can't hold goes in the document"
    );

    let copy = TestApp::new().await;
    let applied = apply(&copy, &[dir.join("first")], Options::default()).await;
    assert!(applied.committed, "{applied}");
    assert!(
        applied.problems.is_empty() && applied.conflicts.is_empty(),
        "{applied}"
    );
    konklav_server::export::run(
        copy.db.pool(),
        &copy.state.auth.secrets,
        &dir.join("second"),
    )
    .await
    .unwrap();
    assert_eq!(
        read_dir(&dir.join("second")),
        files,
        "the copy exports the same set"
    );

    // The copy lets the same people and keys in.
    let login = copy.login("ada@example.com", PASSWORD).await;
    assert_eq!(login.status, StatusCode::OK, "{:?}", login.body);
    let signed_in = copy
        .post(
            "/v1/login/secret-key",
            serde_json::json!({"key_id": key_id, "secret": secret}),
        )
        .await;
    assert_eq!(signed_in.status, StatusCode::OK, "{:?}", signed_in.body);
    assert_eq!(
        copy.login("gone@example.com", PASSWORD).await.status,
        StatusCode::UNAUTHORIZED
    );

    let refused =
        konklav_server::export::run(app.db.pool(), &app.state.auth.secrets, &dir.join("first"))
            .await;
    assert!(
        matches!(
            refused,
            Err(konklav_server::export::ExportError::NotEmpty(_))
        ),
        "never overwrites"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

/// A scratch directory with `files` in it.
fn scratch(name: &str, files: &[(&str, String)]) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("konklav-bootstrap-{name}-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    for (file, text) in files {
        std::fs::write(dir.join(file), text).unwrap();
    }
    dir
}

/// A catalog with a registered `patient` kind in `workspace`s, and two
/// tenants, plus `registered_scopes.csv`.
fn patients(name: &str, rows: &str) -> PathBuf {
    let catalog = serde_json::json!({
        "actions": [{"name": "patient:read"}],
        "scope_kinds": [{"name": "workspace"}, {"name": "patient", "registered": true}],
    });
    scratch(
        name,
        &[
            ("catalog.json", catalog.to_string()),
            (
                "set.styx",
                format!(
                    "id_namespace {NAMESPACE}\n\
                     tenants ({{key clinic}} {{key personal}})\n"
                ),
            ),
            (
                "registered_scopes.csv",
                format!("kind,id,tenant,containers\n{rows}"),
            ),
        ],
    )
}

#[derive(diesel::QueryableByName)]
struct Payload {
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    payload: serde_json::Value,
}

async fn scope_events(app: &TestApp) -> Vec<serde_json::Value> {
    let mut conn = app.db.pool().get().await.unwrap();
    diesel::sql_query("select payload from event where kind = 'scope.changed' order by cursor")
        .load::<Payload>(&mut conn)
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.payload)
        .collect()
}

// r[verify bootstrap.registered.idempotent]
// r[verify bootstrap.registered.events]
// r[verify bootstrap.events]
#[tokio::test(flavor = "multi_thread")]
async fn registered_scopes_apply_in_one_event_and_then_skip() {
    let app = TestApp::new().await;
    // More than one control-plane batch holds.
    let mut rows = String::new();
    for i in 0..1500 {
        let _ = std::fmt::Write::write_fmt(
            &mut rows,
            format_args!("patient,w-{i},clinic,workspace:w-{}|workspace:w-0\n", i % 3),
        );
    }
    rows += "patient,personal-1,personal,\n";
    let dir = patients("registered", &rows);
    let first = apply(&app, std::slice::from_ref(&dir), Options::default()).await;
    assert!(first.committed, "{first}");
    assert_eq!(tally(&first, "registered scopes"), created(1501));
    assert_eq!(count(&app, "registered_scope").await, 1501);
    let events = scope_events(&app).await;
    assert_eq!(events.len(), 1, "one event for the run");
    assert_eq!(events[0]["scopes"].as_array().unwrap().len(), 1501);

    // The containers are a set: order and repeats don't make them differ.
    let reordered = rows.replace(
        "patient,w-1,clinic,workspace:w-1|workspace:w-0",
        "patient,w-1,clinic,workspace:w-0|workspace:w-1|workspace:w-0",
    );
    std::fs::write(
        dir.join("registered_scopes.csv"),
        format!("kind,id,tenant,containers\n{reordered}"),
    )
    .unwrap();
    let again = apply(&app, std::slice::from_ref(&dir), Options::default()).await;
    assert!(again.committed, "{again}");
    assert_eq!(tally(&again, "registered scopes"), skipped(1501));
    assert_eq!(scope_events(&app).await.len(), 1, "nothing changed");

    std::fs::remove_dir_all(dir).unwrap();
}

// r[verify bootstrap.registered.validate]
// r[verify bootstrap.registered.idempotent]
// r[verify bootstrap.validate-first]
// r[verify bootstrap.atomic]
#[tokio::test(flavor = "multi_thread")]
async fn registered_scope_problems_and_conflicts_are_all_reported() {
    let app = TestApp::new().await;
    let base = patients(
        "registered-base",
        "patient,p-1,clinic,workspace:w-1\npatient,p-2,clinic,\npatient,p-9,clinic,workspace:w-1\n",
    );
    let seeded = apply(&app, std::slice::from_ref(&base), Options::default()).await;
    assert!(seeded.committed, "{seeded}");
    let removed = app
        .control(Method::DELETE, "/v1/registered-scopes/patient/p-2", None)
        .await;
    assert!(removed.status.is_success(), "{:?}", removed.body);
    let events = scope_events(&app).await.len();

    let dir = patients(
        "registered-broken",
        "patient,p-1,personal,workspace:w-1\n\
         patient,p-2,clinic,\n\
         patient,p-3,clinic,\n\
         workspace,w-4,clinic,\n\
         patient,p-5,clinic,patient:p-1\n\
         patient,p-6,clinic,ward:u-1\n\
         patient,p-7,nowhere,\n\
         patient,p-3,clinic,\n\
         patient,p-9,clinic,workspace:w-2\n",
    );
    let report = apply(&app, std::slice::from_ref(&dir), Options::default()).await;
    assert!(!report.committed, "{report}");
    let file = dir.join("registered_scopes.csv");
    let at = |found: &[konklav_bootstrap::Problem], line: usize, text: &str| {
        found.iter().any(|p| {
            p.at.as_ref()
                .is_some_and(|at| at.file == file && at.line == line)
                && p.message.contains(text)
        })
    };
    assert!(
        at(&report.conflicts, 2, "its tenant can't change"),
        "{report}"
    );
    assert!(at(&report.conflicts, 3, "was removed"), "{report}");
    assert!(
        at(
            &report.problems,
            5,
            "`workspace` isn't a registered scope kind"
        ),
        "{report}"
    );
    assert!(
        at(
            &report.problems,
            6,
            "`patient` isn't a declared kind that isn't registered"
        ),
        "{report}"
    );
    assert!(
        at(&report.problems, 7, "`ward` isn't a declared kind"),
        "{report}"
    );
    assert!(at(&report.problems, 8, "doesn't exist"), "{report}");
    assert!(at(&report.problems, 9, "more than once"), "{report}");
    assert!(
        at(&report.conflicts, 10, "other containing scopes"),
        "{report}"
    );
    assert_eq!(report.conflicts.len(), 3, "{report}");
    assert_eq!(report.problems.len(), 5, "{report}");

    assert_eq!(
        count(&app, "registered_scope").await,
        3,
        "nothing is written"
    );
    assert_eq!(scope_events(&app).await.len(), events);
    for dir in [base, dir] {
        std::fs::remove_dir_all(dir).unwrap();
    }
}
