//! The format bump check, a test in the spirit of cargo-semver-checks.
//!
//! It snapshots the format as the readers define it: every table and its
//! columns from `table::columns`, and every key of the Styx documents by
//! reflecting on `nested::Document`. Each format version has a directory,
//! `examples/bootstrap/formats/<version>/`, with its snapshot in
//! `format.snapshot` and at least one set that uses it.
//!
//! A format is pending until a release ships it: `mise run release:bump`
//! stamps the snapshot of every pending format with `released in
//! <version>`, and from then on the directory is frozen. The check
//! compares the readers with the latest released format, classifies each
//! difference as needing a minor or a major bump, and checks that
//! [`FORMAT`] is that format bumped accordingly, or 1.0 while nothing is
//! released. Comparing with the released format, not the pending one, lets
//! every change between two releases share one bump.
//!
//! The pending format's snapshot must then match what the readers define,
//! so a pull request that changes the format shows the change.
//! `UPDATE_FORMAT_SNAPSHOT=1 cargo test -p konklav-bootstrap format`
//! rewrites it once the version is right.
//!
//! A snapshot is one entry per line, `<path>: <required|optional> <kind>`.
//! Paths are `/`-separated: `csv/<table>/<column>`, and `styx/<key>/...`
//! for keys, where the keys of a list's records sit under the list's key.
//! What a value means isn't in the snapshot; changing it needs a major bump
//! by hand, and the frozen sets help catch it.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use facet::{Def, Facet, Shape, Type, UserType};

use super::{FORMAT, FormatVersion, UNDECLARED};
use crate::TABLES;
use crate::nested::Document;
use crate::table::columns;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    required: bool,
    kind: String,
}

type Entries = BTreeMap<String, Entry>;

fn optional(kind: &str) -> Entry {
    Entry {
        required: false,
        kind: kind.to_owned(),
    }
}

/// The format as the readers define it.
fn current() -> Entries {
    let mut entries = Entries::new();
    entries.insert("catalog.json".into(), optional("catalog"));
    for table in TABLES {
        let path = format!("csv/{table}");
        let (required, optional_columns, facts) = columns(table);
        for column in required {
            let entry = Entry {
                required: true,
                kind: "column".into(),
            };
            entries.insert(format!("{path}/{column}"), entry);
        }
        for column in optional_columns {
            entries.insert(format!("{path}/{column}"), optional("column"));
        }
        if facts {
            entries.insert(format!("{path}/fact.*"), optional("column"));
        }
        entries.insert(path, optional("table"));
    }
    record(Document::SHAPE, "styx", &mut Vec::new(), &mut entries);
    entries
}

/// Adds the keys of the struct `shape` under `path`. `enclosing` holds the
/// records being walked, so a record inside itself, such as a tenant's
/// children, refers back to where it was first described.
fn record(
    shape: &'static Shape,
    path: &str,
    enclosing: &mut Vec<(&'static Shape, String)>,
    entries: &mut Entries,
) {
    let Type::User(UserType::Struct(fields)) = shape.ty else {
        panic!("{path} is not a record");
    };
    enclosing.push((shape, path.to_owned()));
    for field in fields.fields {
        let name = field.effective_name();
        // The declaration itself, which every version has.
        if field.is_metadata() || (path == "styx" && name == "format") {
            continue;
        }
        let path = format!("{path}/{name}");
        let (required, inner) = match field.shape().def {
            Def::Option(option) => (false, option.t),
            _ => (!field.has_default(), field.shape()),
        };
        let kind = kind(inner, &path, enclosing, entries);
        entries.insert(path, Entry { required, kind });
    }
    enclosing.pop();
}

fn kind(
    shape: &'static Shape,
    path: &str,
    enclosing: &mut Vec<(&'static Shape, String)>,
    entries: &mut Entries,
) -> String {
    let shape = unspanned(shape);
    match shape.def {
        Def::List(list) => format!("list of {}", kind(list.t(), path, enclosing, entries)),
        Def::Map(map) => format!("map of {}", kind(map.v, path, enclosing, entries)),
        Def::DynamicValue(_) => "value".into(),
        Def::Scalar => match shape.type_identifier {
            "String" => "text".into(),
            other => other.to_owned(),
        },
        _ if matches!(shape.ty, Type::User(UserType::Struct(_))) => {
            if let Some((_, at)) = enclosing.iter().find(|(seen, _)| *seen == shape) {
                format!("record like {at}")
            } else {
                record(shape, path, enclosing, entries);
                "record".into()
            }
        }
        _ => panic!("{path}: no snapshot kind for {}", shape.type_identifier),
    }
}

/// What a `Spanned<T>` holds: its `T`.
fn unspanned(shape: &'static Shape) -> &'static Shape {
    if !shape.is_metadata_container() {
        return shape;
    }
    let Type::User(UserType::Struct(fields)) = shape.ty else {
        return shape;
    };
    fields
        .fields
        .iter()
        .find(|field| !field.is_metadata())
        .map_or(shape, |field| field.shape())
}

/// One format version's snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Snapshot {
    version: FormatVersion,
    /// The Konklav release that shipped it; `None` while it is pending.
    released: Option<String>,
    entries: Entries,
}

fn render(snapshot: &Snapshot) -> String {
    let mut text = String::from(
        "# The bootstrap format's tables, columns and keys, generated from the\n\
         # readers by items/bootstrap/src/format/check.rs. Don't edit it by hand.\n",
    );
    let _ = writeln!(text, "format {}", snapshot.version);
    if let Some(release) = &snapshot.released {
        let _ = writeln!(text, "released in {release}");
    }
    text.push('\n');
    let entries = &snapshot.entries;
    for (path, entry) in entries {
        let required = if entry.required {
            "required"
        } else {
            "optional"
        };
        let _ = writeln!(text, "{path}: {required} {}", entry.kind);
    }
    text
}

fn parse(file: &Path) -> Snapshot {
    let text =
        std::fs::read_to_string(file).unwrap_or_else(|error| panic!("{}: {error}", file.display()));
    let mut version = None;
    let mut released = None;
    let mut entries = Entries::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(declared) = line.strip_prefix("format ") {
            version = Some(declared.parse().expect("a format version"));
            continue;
        }
        if let Some(release) = line.strip_prefix("released in ") {
            released = Some(release.to_owned());
            continue;
        }
        let (path, entry) = line
            .split_once(": ")
            .and_then(|(path, rest)| Some((path, rest.split_once(' ')?)))
            .unwrap_or_else(|| panic!("{}: can't read `{line}`", file.display()));
        let required = match entry.0 {
            "required" => true,
            "optional" => false,
            other => panic!(
                "{}: `{other}` is neither required nor optional",
                file.display()
            ),
        };
        let entry = Entry {
            required,
            kind: entry.1.to_owned(),
        };
        entries.insert(path.to_owned(), entry);
    }
    let version = version.unwrap_or_else(|| panic!("{} has no format line", file.display()));
    Snapshot {
        version,
        released,
        entries,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Bump {
    None,
    Minor,
    Major,
}

impl Bump {
    fn of(self, version: FormatVersion) -> FormatVersion {
        match self {
            Self::None => version,
            Self::Minor => FormatVersion::new(version.major, version.minor + 1),
            Self::Major => FormatVersion::new(version.major + 1, 0),
        }
    }
}

#[derive(Debug)]
struct Change {
    path: String,
    bump: Bump,
    what: String,
}

/// How `new` differs from `old`, and what each difference needs: adding
/// an optional entry, or any entry inside an added one, is a minor change;
/// removing an entry, adding a required one to what exists, making one
/// required or changing its kind is a major one.
// r[impl bootstrap.format.released]
fn changes(old: &Entries, new: &Entries) -> Vec<Change> {
    let added = |path: &str| new.contains_key(path) && !old.contains_key(path);
    let parent = |path: &str| path.rsplit_once('/').map(|(parent, _)| parent.to_owned());
    let mut changes = Vec::new();
    let mut change = |path: &str, bump, what: String| {
        changes.push(Change {
            path: path.to_owned(),
            bump,
            what,
        });
    };
    for (path, was) in old {
        match new.get(path) {
            None => change(path, Bump::Major, "removed".into()),
            Some(now) if now.kind != was.kind => change(
                path,
                Bump::Major,
                format!("changed from {} to {}", was.kind, now.kind),
            ),
            Some(now) if now.required && !was.required => {
                change(path, Bump::Major, "made required".into());
            }
            Some(now) if !now.required && was.required => {
                change(path, Bump::Minor, "made optional".into());
            }
            Some(_) => {}
        }
    }
    for (path, now) in new {
        if old.contains_key(path) {
            continue;
        }
        if !now.required {
            change(path, Bump::Minor, "added as optional".into());
        } else if parent(path).is_some_and(|parent| added(&parent)) {
            change(
                path,
                Bump::Minor,
                "added as required, inside something added".into(),
            );
        } else {
            change(path, Bump::Major, "added as required".into());
        }
    }
    changes
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn formats_dir() -> PathBuf {
    manifest_dir().join("../../examples/bootstrap/formats")
}

/// Every format's snapshot, oldest first.
fn formats() -> Vec<Snapshot> {
    let formats = formats_dir();
    let mut found: Vec<_> = std::fs::read_dir(&formats)
        .unwrap_or_else(|error| panic!("{}: {error}", formats.display()))
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .map(|dir| {
            let name: FormatVersion = dir
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.parse().ok())
                .unwrap_or_else(|| panic!("{} is not named by a format version", dir.display()));
            let snapshot = parse(&dir.join("format.snapshot"));
            assert_eq!(
                snapshot.version,
                name,
                "{} holds another version's snapshot",
                dir.display()
            );
            snapshot
        })
        .collect();
    found.sort_by_key(|snapshot| snapshot.version);
    found
}

/// The version the readers' format must have: the latest released one
/// bumped as `current` needs, or 1.0 while nothing is released.
fn expected(formats: &[Snapshot], current: &Entries) -> (FormatVersion, String) {
    let Some(released) = formats.iter().rev().find(|s| s.released.is_some()) else {
        return (UNDECLARED, "no format is released yet".into());
    };
    let changes = changes(&released.entries, current);
    let needed = changes.iter().map(|c| c.bump).max().unwrap_or(Bump::None);
    let mut listed = format!(
        "the format changed since released format {}:",
        released.version
    );
    for c in &changes {
        let _ = write!(listed, "\n  {:?}: {} {}", c.bump, c.path, c.what);
    }
    (needed.of(released.version), listed)
}

// r[verify bootstrap.format.released]
// r[verify bootstrap.format.version]
#[test]
fn the_format_version_is_the_released_one_bumped_as_its_changes_need() {
    let current = current();
    let formats = formats();
    let (expected, why) = expected(&formats, &current);
    assert_eq!(FORMAT, expected, "FORMAT must be {expected}: {why}");

    let file = formats_dir()
        .join(FORMAT.to_string())
        .join("format.snapshot");
    let snapshot = Snapshot {
        version: FORMAT,
        released: None,
        entries: current,
    };
    match formats.iter().find(|s| s.version == FORMAT) {
        // Released and unchanged: the bump check above saw no change.
        Some(own) if own.released.is_some() => {}
        Some(own) if *own == snapshot => {}
        _ if std::env::var_os("UPDATE_FORMAT_SNAPSHOT").is_some() => {
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(&file, render(&snapshot)).unwrap();
        }
        _ => panic!(
            "{} is out of date; rewrite it with \
             UPDATE_FORMAT_SNAPSHOT=1 cargo test -p konklav-bootstrap format, \
             and give the format a set that uses what changed",
            file.display()
        ),
    }
}

#[test]
fn only_the_current_format_is_pending() {
    for snapshot in formats() {
        assert!(
            snapshot.version <= FORMAT,
            "format {} exists but FORMAT is {FORMAT}",
            snapshot.version
        );
        assert!(
            snapshot.released.is_some() || snapshot.version == FORMAT,
            "format {} was never released, but FORMAT is {FORMAT}",
            snapshot.version
        );
    }
}

#[test]
fn only_changes_since_the_last_release_need_a_bump() {
    let snapshot = |version, released: Option<&str>, lines: &[(&str, bool, &str)]| Snapshot {
        version,
        released: released.map(str::to_owned),
        entries: entries(lines),
    };
    let table = with(&[("csv/u.csv", false, "table")]);
    let v1_0 = FormatVersion::new(1, 0);
    let pending = [snapshot(v1_0, None, &BASE)];
    assert_eq!(
        expected(&pending, &entries(&table)).0,
        v1_0,
        "an unreleased format takes changes as they are"
    );
    let released = [snapshot(v1_0, Some("1.5.0"), &BASE)];
    assert_eq!(
        expected(&released, &entries(&table)).0,
        FormatVersion::new(1, 1)
    );
    let both = [
        snapshot(v1_0, Some("1.5.0"), &BASE),
        snapshot(FormatVersion::new(1, 1), None, &table),
    ];
    let more = [table.clone(), vec![("csv/v.csv", false, "table")]].concat();
    assert_eq!(
        expected(&both, &entries(&more)).0,
        FormatVersion::new(1, 1),
        "changes before a release share one bump"
    );
}

#[test]
fn the_snapshot_reflects_tables_and_nested_keys() {
    let current = current();
    let entry = |path: &str| current.get(path).unwrap_or_else(|| panic!("no {path}"));
    assert_eq!(entry("csv/tenants.csv"), &optional("table"));
    assert!(entry("csv/tenants.csv/id").required);
    assert_eq!(entry("csv/memberships.csv/fact.*"), &optional("column"));
    assert_eq!(entry("styx/tenants"), &optional("list of record"));
    assert_eq!(entry("styx/tenants/key"), &optional("text"));
    assert_eq!(
        entry("styx/tenants/children"),
        &optional("list of record like styx/tenants"),
        "a record inside itself refers back"
    );
    assert_eq!(entry("styx/tenants/facts"), &optional("map of value"));
    assert!(entry("styx/templates/policies/action").required);
    assert_eq!(
        entry("styx/subjects/mfa_factors_required"),
        &optional("i16")
    );
    assert!(!current.contains_key("styx/format"));
    assert!(!current.keys().any(|path| path.ends_with("/span")));
}

fn entries(lines: &[(&str, bool, &str)]) -> Entries {
    lines
        .iter()
        .map(|(path, required, kind)| {
            let entry = Entry {
                required: *required,
                kind: (*kind).to_owned(),
            };
            ((*path).to_owned(), entry)
        })
        .collect()
}

fn needed(old: &[(&str, bool, &str)], new: &[(&str, bool, &str)]) -> Bump {
    changes(&entries(old), &entries(new))
        .iter()
        .map(|c| c.bump)
        .max()
        .unwrap_or(Bump::None)
}

const BASE: [(&str, bool, &str); 3] = [
    ("csv/t.csv", false, "table"),
    ("csv/t.csv/id", true, "column"),
    ("csv/t.csv/note", false, "column"),
];

fn with(extra: &[(&'static str, bool, &'static str)]) -> Vec<(&'static str, bool, &'static str)> {
    BASE.iter().chain(extra).copied().collect()
}

#[test]
fn additions_of_optional_entries_need_a_minor_bump() {
    assert_eq!(needed(&BASE, &BASE), Bump::None);
    assert_eq!(
        needed(&BASE, &with(&[("csv/t.csv/more", false, "column")])),
        Bump::Minor
    );
    let table = [
        ("csv/u.csv", false, "table"),
        ("csv/u.csv/id", true, "column"),
    ];
    assert_eq!(
        needed(&BASE, &with(&table)),
        Bump::Minor,
        "a new table may require columns"
    );
    let mut optional_id = with(&[]);
    optional_id[1].1 = false;
    assert_eq!(needed(&BASE, &optional_id), Bump::Minor);
}

#[test]
fn anything_else_needs_a_major_bump() {
    assert_eq!(needed(&BASE, &BASE[..2]), Bump::Major, "removed");
    assert_eq!(
        needed(&BASE, &with(&[("csv/t.csv/must", true, "column")])),
        Bump::Major
    );
    let mut required = with(&[]);
    required[2].1 = true;
    assert_eq!(needed(&BASE, &required), Bump::Major, "made required");
    let mut retyped = with(&[]);
    retyped[2].2 = "list of text";
    assert_eq!(needed(&BASE, &retyped), Bump::Major, "changed kind");
    let renamed = [BASE[0], BASE[1], ("csv/t.csv/notes", false, "column")];
    assert_eq!(needed(&BASE, &renamed), Bump::Major, "renamed");
}

#[test]
fn bumps_reset_the_minor_version_on_a_major_one() {
    let version = FormatVersion::new(1, 3);
    assert_eq!(Bump::None.of(version), version);
    assert_eq!(Bump::Minor.of(version), FormatVersion::new(1, 4));
    assert_eq!(Bump::Major.of(version), FormatVersion::new(2, 0));
}

#[test]
fn snapshots_read_back_as_rendered() {
    let file = std::env::temp_dir().join(format!("konklav-format-{}.snapshot", std::process::id()));
    for released in [None, Some("1.5.0".to_owned())] {
        let snapshot = Snapshot {
            version: FormatVersion::new(3, 1),
            released,
            entries: entries(&BASE),
        };
        std::fs::write(&file, render(&snapshot)).unwrap();
        assert_eq!(parse(&file), snapshot);
    }
    let _ = std::fs::remove_file(file);
}
