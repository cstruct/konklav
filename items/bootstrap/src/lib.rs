//! Reads bootstrap sets: tenants, people, credentials and grants written as
//! flat CSV tables or nested Styx documents, into one [`BootstrapSet`].
//!
//! Reading is pure: it touches only the files it is given and knows nothing
//! about the database. The server resolves identifiers against stored
//! records and applies the set.

mod format;
mod model;
mod nested;
mod table;

use std::fmt;
use std::path::{Path, PathBuf};

pub use format::{FORMAT, FormatVersion, InvalidFormatVersion, UNDECLARED};
pub use model::*;

/// Something wrong with the files, and where.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    pub at: Option<Location>,
    pub message: String,
}

impl Problem {
    #[must_use]
    pub fn at(at: &Location, message: impl Into<String>) -> Self {
        Self {
            at: Some(at.clone()),
            message: message.into(),
        }
    }

    #[must_use]
    pub fn in_file(file: &Path, message: impl Into<String>) -> Self {
        Self::at(
            &Location {
                file: file.to_owned(),
                line: 1,
            },
            message,
        )
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.at {
            Some(at) => write!(f, "{at}: {}", self.message),
            None => f.write_str(&self.message),
        }
    }
}

/// The flat tables a directory may hold, by file name.
pub const TABLES: [&str; 8] = [
    "tenants.csv",
    "subjects.csv",
    "credentials.csv",
    "mfa_factors.csv",
    "memberships.csv",
    "assignments.csv",
    "registered_scopes.csv",
    "sessions.csv",
];

/// Reads every path into one set: a directory's flat tables, `catalog.json`
/// and `.styx` documents, or a single file of any of those kinds. Every
/// problem in every file is returned together.
// r[impl bootstrap.formats]
// r[impl bootstrap.validate-first]
pub fn read(paths: &[PathBuf]) -> Result<BootstrapSet, Vec<Problem>> {
    let mut files = Vec::new();
    let mut problems = Vec::new();
    for path in paths {
        if path.is_dir() {
            match std::fs::read_dir(path) {
                Ok(entries) => {
                    let mut found: Vec<PathBuf> = entries
                        .filter_map(Result::ok)
                        .map(|entry| entry.path())
                        .filter(|path| path.is_file())
                        .collect();
                    found.sort();
                    files.extend(found.into_iter().filter(|file| {
                        matches!(
                            file.extension().and_then(|e| e.to_str()),
                            Some("csv" | "styx")
                        ) || file.file_name().is_some_and(|name| name == "catalog.json")
                    }));
                }
                Err(error) => problems.push(Problem::in_file(path, error.to_string())),
            }
        } else {
            files.push(path.clone());
        }
    }
    let mut texts = Vec::new();
    for file in &files {
        match std::fs::read_to_string(file) {
            Ok(text) => texts.push((file, text)),
            Err(error) => problems.push(Problem::in_file(file, error.to_string())),
        }
    }
    let declarations = texts
        .iter()
        .filter(|(file, _)| file.extension().is_some_and(|e| e == "styx"))
        .filter_map(|(file, text)| nested::declared_format(file, text))
        .filter_map(|declared| declared.map_err(|problem| problems.push(problem)).ok())
        .collect();
    let format = format::merge(declarations, &mut problems);
    if let Err(problem) = format::readable(format.as_ref()) {
        problems.push(problem);
        return Err(problems);
    }
    // Tables before documents, so a document's tenant tree and roles can
    // be read in any order relative to them; the server orders records by
    // kind anyway.
    let mut set = BootstrapSet::default();
    for (file, text) in &texts {
        match read_text(file, text) {
            Ok(read) => set.extend(read, &mut problems),
            Err(mut found) => problems.append(&mut found),
        }
    }
    if set.id_namespace.is_none() && set.uses_external_ids() {
        problems.push(Problem {
            at: None,
            message: "records use external ids or tenant keys, but no file declares an \
                      id_namespace"
                .into(),
        });
    }
    if problems.is_empty() {
        Ok(set)
    } else {
        Err(problems)
    }
}

fn read_text(file: &Path, text: &str) -> Result<BootstrapSet, Vec<Problem>> {
    let name = file
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    match file.extension().and_then(|e| e.to_str()) {
        Some("styx") => nested::read(file, text),
        Some("csv") if TABLES.contains(&name) => table::read(file, name, text),
        Some("csv") => Err(vec![Problem::in_file(
            file,
            format!("unknown table; expected one of {}", TABLES.join(", ")),
        )]),
        Some("json") => read_catalog(file, text),
        _ => Err(vec![Problem::in_file(
            file,
            "expected a .csv table, a .styx document or catalog.json",
        )]),
    }
}

fn read_catalog(file: &Path, text: &str) -> Result<BootstrapSet, Vec<Problem>> {
    let value: serde_json::Value = serde_json::from_str(text).map_err(|error| {
        vec![Problem::at(
            &Location {
                file: file.to_owned(),
                line: error.line(),
            },
            error.to_string(),
        )]
    })?;
    Ok(BootstrapSet {
        catalog: Some(Located {
            value,
            at: Location {
                file: file.to_owned(),
                line: 1,
            },
        }),
        ..BootstrapSet::default()
    })
}

/// The 1-based line of byte `offset` in `text`.
pub(crate) fn line_of(text: &str, offset: usize) -> usize {
    text.get(..offset).unwrap_or(text).matches('\n').count() + 1
}
