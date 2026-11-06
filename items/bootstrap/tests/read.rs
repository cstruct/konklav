use std::path::{Path, PathBuf};

use konklav_bootstrap::{
    AssignmentTarget, CredentialMaterial, FactValue, Id, Kind, MembershipRef, RegisteredScope,
    SubjectRef, TenantRef, derive, read,
};

fn examples() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/bootstrap")
}

/// A scratch directory with `files` in it.
fn scratch(name: &str, files: &[(&str, &str)]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("konklav-bootstrap-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for (file, text) in files {
        std::fs::write(dir.join(file), text).unwrap();
    }
    dir
}

const NAMESPACE: &str = "3f1c9a52-6a1e-4d0b-9a0e-6c1d8f0b2e11";

// r[verify bootstrap.formats]
// r[verify bootstrap.contents]
// r[verify bootstrap.metadata]
#[test]
fn the_nested_example_reads_into_records_with_natural_keys() {
    let set = read(&[examples().join("nested/seed.styx")]).unwrap();
    assert_eq!(set.id_namespace.unwrap().value.to_string(), NAMESPACE);
    assert!(set.catalog.is_some());
    assert_eq!(set.templates.len(), 1);
    assert_eq!(
        set.templates[0].value.metadata,
        serde_json::json!({"label": "Reader", "shown_to": ["members", "admins"]})
    );
    assert_eq!(set.roles.len(), 2, "a global role and a tenant role");
    assert_eq!(set.roles[0].value.metadata, serde_json::json!({}));
    assert_eq!(
        set.roles[1].value.metadata,
        serde_json::json!({"label": "Editor"})
    );
    let tenants: Vec<_> = set.tenants.iter().map(|t| &t.value).collect();
    assert_eq!(tenants[0].id, Id::External("acme".into()));
    assert_eq!(tenants[0].parent, TenantRef::Root);
    assert_eq!(tenants[0].facts["seats"], FactValue::Text("25".into()));
    assert_eq!(
        tenants[1].parent,
        TenantRef::Id(Id::External("acme".into()))
    );

    let ada = SubjectRef::Identifier("ada@acme.example".into());
    assert_eq!(set.subjects.len(), 3);
    assert_eq!(set.subjects[0].value.key, ada);
    assert_eq!(set.subjects[0].at.line, 23, "where the member opens");
    assert!(matches!(
        set.credentials[0].value.material,
        CredentialMaterial::PasswordHash(_)
    ));
    assert_eq!(
        set.credentials[1].value.material,
        CredentialMaterial::EmailLink
    );
    assert_eq!(set.memberships[0].value.subject, ada);
    let scoped = set
        .assignments
        .iter()
        .find(|a| a.value.scope.is_some())
        .unwrap();
    assert_eq!(
        scoped.value.target,
        AssignmentTarget::Membership(MembershipRef::Of {
            subject: ada,
            tenant: TenantRef::Id(Id::External("acme".into())),
        })
    );
    let globals = set
        .assignments
        .iter()
        .filter(|a| matches!(a.value.target, AssignmentTarget::Global(_)))
        .count();
    assert_eq!(globals, 2);
}

// r[verify bootstrap.formats]
#[test]
fn the_flat_example_reads_tables_and_a_document_together() {
    let set = read(&[examples().join("flat")]).unwrap();
    assert!(set.id_namespace.is_some(), "from set.styx");
    assert_eq!(set.tenants.len(), 2);
    assert_eq!(
        set.tenants[1].value.parent,
        TenantRef::Id(Id::External("org-1".into()))
    );
    assert_eq!(set.tenants[1].at.line, 3);
    assert_eq!(set.subjects.len(), 2);
    assert_eq!(set.credentials.len(), 2);
    assert_eq!(
        set.memberships[0].value.facts["member_type"],
        FactValue::Text("professional".into())
    );
    assert!(
        set.memberships[1].value.facts.is_empty(),
        "empty cells are absent"
    );
    assert_eq!(set.assignments.len(), 2);
    assert_eq!(set.templates.len(), 1);
}

// r[verify bootstrap.ids]
#[test]
fn external_ids_derive_uuid_v5_under_the_namespace() {
    let namespace = uuid::Uuid::parse_str(NAMESPACE).unwrap();
    let id = Id::parse("4711");
    let derived = id.resolve(Some(namespace), Kind::Subject).unwrap();
    assert_eq!(derived, uuid::Uuid::new_v5(&namespace, b"subject:4711"));
    assert_eq!(derived, derive(namespace, Kind::Subject, "4711"));
    assert_ne!(derived, id.resolve(Some(namespace), Kind::Tenant).unwrap());
    assert_eq!(id.resolve(None, Kind::Subject), None);
    let uuid = uuid::Uuid::now_v7();
    assert_eq!(
        Id::parse(&uuid.to_string()).resolve(None, Kind::Subject),
        Some(uuid)
    );
}

// r[verify bootstrap.ids]
#[test]
fn external_ids_need_a_namespace() {
    let dir = scratch("no-namespace", &[("subjects.csv", "id\n4711\n")]);
    let problems = read(&[dir]).unwrap_err();
    assert!(problems[0].message.contains("id_namespace"), "{problems:?}");
}

// r[verify bootstrap.validate-first]
#[test]
fn every_problem_is_reported_with_its_place() {
    let dir = scratch(
        "problems",
        &[
            ("subjects.csv", "id,kind\n4711,robot\n4712,human\n4713,\n"),
            (
                "credentials.csv",
                "id,subject,kind,shoe_size\nc,4711,password,44\n",
            ),
            ("memberships.csv", "id,subject,tenant\nm-1,4711,\n"),
            ("seed.styx", "tenants ({key a, colour blue})\n"),
            ("users.csv", "id\n1\n"),
        ],
    );
    let problems = read(std::slice::from_ref(&dir)).unwrap_err();
    let rendered: Vec<String> = problems.iter().map(ToString::to_string).collect();
    let has = |file: &str, line: usize, text: &str| {
        problems.iter().any(|p| {
            p.at.as_ref()
                .is_some_and(|at| at.file == dir.join(file) && at.line == line)
                && p.message.contains(text)
        })
    };
    assert!(
        has("subjects.csv", 2, "`kind` must be one of human, service"),
        "{rendered:#?}"
    );
    assert!(
        has("credentials.csv", 1, "unknown column `shoe_size`"),
        "{rendered:#?}"
    );
    assert!(
        has("memberships.csv", 2, "`tenant` is empty"),
        "{rendered:#?}"
    );
    assert!(has("users.csv", 1, "unknown table"), "{rendered:#?}");
    assert!(
        problems
            .iter()
            .any(|p| p.message.contains("unknown field 'colour'")
                && p.message.contains("seed.styx:1")),
        "{rendered:#?}"
    );
    assert!(
        !rendered.iter().any(|p| p.contains("4713")),
        "an empty kind is the default"
    );
}

#[test]
fn a_subject_without_an_id_needs_something_to_be_found_by() {
    let dir = scratch("anonymous", &[("seed.styx", "subjects ({kind service})\n")]);
    let problems = read(&[dir]).unwrap_err();
    assert!(
        problems[0].message.contains("needs an email"),
        "{problems:?}"
    );
}

// r[verify bootstrap.registered.shape]
// r[verify bootstrap.contents]
#[test]
fn registered_scopes_read_from_both_formats() {
    let nested = read(&[examples().join("nested/seed.styx")]).unwrap();
    let scopes: Vec<_> = nested.registered_scopes.iter().map(|s| &s.value).collect();
    assert_eq!(scopes.len(), 2);
    assert_eq!(
        *scopes[0],
        RegisteredScope {
            kind: "document".into(),
            id: "d-1".into(),
            tenant: TenantRef::Id(Id::External("acme".into())),
            containers: vec![("project".into(), "p-1".into())],
        },
        "a tenant's scopes belong to it"
    );
    assert_eq!(scopes[1].containers, Vec::<(String, String)>::new());

    let flat = read(&[examples().join("flat")]).unwrap();
    let scopes: Vec<_> = flat.registered_scopes.iter().map(|s| &s.value).collect();
    assert_eq!(
        scopes[0].containers,
        vec![
            ("project".into(), "p-1".into()),
            ("project".into(), "p-2".into())
        ]
    );
    assert_eq!(
        scopes[0].tenant,
        TenantRef::Id(Id::External("org-1".into()))
    );
    assert_eq!(
        scopes[1].containers,
        Vec::<(String, String)>::new(),
        "an empty cell is none"
    );
    assert_eq!(flat.registered_scopes[1].at.line, 3);

    // A container's id is split from its kind at the first `:`, and ids
    // are used as written, never resolved.
    let dir = scratch(
        "registered",
        &[
            (
                "registered_scopes.csv",
                "kind,id,tenant,containers\npatient,p:1,root,workspace:w:1\n",
            ),
            (
                "seed.styx",
                "registered_scopes ({kind patient, id \"a|b\", tenant root, containers ({kind \"x:y\", id \"1|2\"})})\n",
            ),
        ],
    );
    let set = read(&[dir]).unwrap();
    assert_eq!(
        set.registered_scopes[0].value,
        RegisteredScope {
            kind: "patient".into(),
            id: "p:1".into(),
            tenant: TenantRef::Root,
            containers: vec![("workspace".into(), "w:1".into())],
        }
    );
    assert_eq!(
        set.registered_scopes[1].value.containers,
        vec![("x:y".into(), "1|2".into())],
        "a document holds what a table can't"
    );
}

// r[verify bootstrap.registered.shape]
// r[verify bootstrap.validate-first]
#[test]
fn malformed_registered_scopes_are_reported_with_their_place() {
    let dir = scratch(
        "registered-problems",
        &[
            (
                "registered_scopes.csv",
                "kind,id,tenant,containers\npatient,,root,\npatient,p-1,root,workspace\n",
            ),
            (
                "seed.styx",
                "registered_scopes ({kind patient, id p-2})\n\
                 tenants ({id 0195f0c4-0000-7000-8000-000000000001, registered_scopes ({kind patient, id p-3, tenant root})})\n",
            ),
        ],
    );
    let problems = read(std::slice::from_ref(&dir)).unwrap_err();
    let has = |file: &str, line: usize, text: &str| {
        problems.iter().any(|p| {
            p.at.as_ref()
                .is_some_and(|at| at.file == dir.join(file) && at.line == line)
                && p.message.contains(text)
        })
    };
    let rendered: Vec<String> = problems.iter().map(ToString::to_string).collect();
    assert!(
        has("registered_scopes.csv", 2, "`id` is empty"),
        "{rendered:#?}"
    );
    assert!(
        has("registered_scopes.csv", 3, "`<kind>:<id>`, not `workspace`"),
        "{rendered:#?}"
    );
    assert!(has("seed.styx", 1, "needs a `tenant`"), "{rendered:#?}");
    assert!(has("seed.styx", 2, "the tenant it is in"), "{rendered:#?}");
}
