//! The bootstrap format version: which tables, columns and keys a set may
//! use, versioned apart from Konklav's releases.
//!
//! A minor version only adds optional tables, columns or keys, so this
//! reader reads every minor version of its major as it is. A set of an
//! older major would be read by that major's own readers and upgraded in
//! memory to the current model in [`readable`]'s caller, so applying sees
//! one shape; 1 is the first major, so there are none yet.
//!
//! `format.snapshot`, next to this file, records the tables, columns and
//! keys of [`FORMAT`] as the readers define them. A test regenerates it and
//! checks the version against the latest released format's frozen snapshot
//! in `examples/bootstrap/formats/`; see the crate's README.

use std::fmt;
use std::str::FromStr;

use crate::Problem;
use crate::model::{Located, Location};

/// A bootstrap format version, `major.minor`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FormatVersion {
    pub major: u16,
    pub minor: u16,
}

/// The format this crate reads, up to and including, and `export` writes.
// r[impl bootstrap.format.version]
pub const FORMAT: FormatVersion = FormatVersion { major: 1, minor: 0 };

/// What a set that declares no format is.
pub const UNDECLARED: FormatVersion = FormatVersion { major: 1, minor: 0 };

impl FormatVersion {
    #[must_use]
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }
}

impl fmt::Display for FormatVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// The version is not `<major>.<minor>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidFormatVersion;

impl FromStr for FormatVersion {
    type Err = InvalidFormatVersion;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let number = |part: &str| {
            let digits = !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
            digits
                .then(|| part.parse().ok())
                .flatten()
                .ok_or(InvalidFormatVersion)
        };
        let (major, minor) = text.trim().split_once('.').ok_or(InvalidFormatVersion)?;
        Ok(Self::new(number(major)?, number(minor)?))
    }
}

/// Parses one document's `format` declaration.
pub(crate) fn declaration(at: &Location, text: &str) -> Result<Located<FormatVersion>, Problem> {
    text.parse()
        .map(|value| Located {
            value,
            at: at.clone(),
        })
        .map_err(|_| {
            Problem::at(
                at,
                format!("format must be a version such as {FORMAT}, not `{text}`"),
            )
        })
}

/// Merges the declarations of a set's documents into one, reporting those
/// that differ from the first.
// r[impl bootstrap.format.declare]
pub(crate) fn merge(
    declarations: Vec<Located<FormatVersion>>,
    problems: &mut Vec<Problem>,
) -> Option<Located<FormatVersion>> {
    let mut declarations = declarations.into_iter();
    let first = declarations.next()?;
    for other in declarations {
        if other.value != first.value {
            problems.push(Problem::at(
                &other.at,
                format!(
                    "format {} differs from {} declared at {}",
                    other.value, first.value, first.at
                ),
            ));
        }
    }
    Some(first)
}

/// Whether this crate reads a set of the declared format, and if not, the
/// one problem that says so.
// r[impl bootstrap.format.read]
pub(crate) fn readable(declared: Option<&Located<FormatVersion>>) -> Result<(), Problem> {
    let version = declared.map_or(UNDECLARED, |d| d.value);
    if version.major == FORMAT.major && version <= FORMAT {
        return Ok(());
    }
    let reads = format!("this server reads format {}.0 up to {FORMAT}", FORMAT.major);
    Err(match declared {
        Some(declared) => Problem::at(
            &declared.at,
            format!("this set needs format {version}; {reads}"),
        ),
        None => Problem {
            at: None,
            message: format!("this set declares no format, so it needs {version}; {reads}"),
        },
    })
}

#[cfg(test)]
mod check;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_two_whole_numbers() {
        assert_eq!("1.0".parse(), Ok(FormatVersion::new(1, 0)));
        assert_eq!(" 12.3 ".parse(), Ok(FormatVersion::new(12, 3)));
        for bad in ["1", "1.", ".1", "1.0.0", "v1.0", "1.-1", "1.x", "+1.0", ""] {
            assert_eq!(
                bad.parse::<FormatVersion>(),
                Err(InvalidFormatVersion),
                "{bad}"
            );
        }
    }

    #[test]
    fn versions_order_by_major_then_minor() {
        assert!(FormatVersion::new(1, 10) > FormatVersion::new(1, 9));
        assert!(FormatVersion::new(2, 0) > FormatVersion::new(1, 10));
    }
}
