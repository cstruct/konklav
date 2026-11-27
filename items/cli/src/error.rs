//! The CLI's errors, and the exit code each one ends the process with.

use std::process::ExitCode;

/// Everything a command can fail with.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The command line or the configuration asks for something impossible.
    #[error("{0}")]
    Usage(String),
    /// Konklav answered with an error.
    #[error("{status}: {code}: {message}")]
    Api {
        status: u16,
        code: String,
        message: String,
    },
    /// There is no session for the profile, or it has ended.
    #[error("{0}")]
    NotSignedIn(String),
    /// Konklav couldn't be reached.
    #[error("couldn't reach Konklav: {0}")]
    Unreachable(String),
    /// The credential store, the configuration directory or another local
    /// resource failed.
    #[error("{0}")]
    Local(String),
}

impl Error {
    /// A usage error.
    pub fn usage(message: impl Into<String>) -> Self {
        Self::Usage(message.into())
    }

    /// A local failure.
    pub fn local(message: impl Into<String>) -> Self {
        Self::Local(message.into())
    }

    /// The exit code: 1 for an error Konklav answered or a local failure,
    /// 2 for a usage error, 3 when not signed in, and 4 when Konklav
    /// couldn't be reached.
    // r[impl item.cli.exit-codes]
    #[must_use]
    pub fn exit_code(&self) -> ExitCode {
        ExitCode::from(match self {
            Self::Api { .. } | Self::Local(_) => 1,
            Self::Usage(_) => 2,
            Self::NotSignedIn(_) => 3,
            Self::Unreachable(_) => 4,
        })
    }
}

impl From<reqwest::Error> for Error {
    fn from(error: reqwest::Error) -> Self {
        // reqwest's messages can name the URL, never a header, and the CLI
        // never puts a token in a URL.
        Self::Unreachable(error.to_string())
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
