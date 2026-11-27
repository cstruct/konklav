//! Profiles: which Konklav deployment a command talks to, kept in
//! `config.styx` in the CLI's configuration directory.
//!
//! The file holds no secrets (`item.cli.secrets-in-keyring`): those are in
//! the profile's credential store.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use facet::Facet;

use crate::error::{Error, Result};

/// Where a profile's DPoP key and tokens are kept.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Facet)]
#[repr(u8)]
#[facet(rename_all = "snake_case")]
pub enum CredentialStore {
    /// The operating system's credential store: Keychain, Secret Service or
    /// Credential Manager.
    #[default]
    Keyring,
    /// A file readable only by the user, next to the configuration.
    File,
}

impl std::str::FromStr for CredentialStore {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "keyring" => Ok(Self::Keyring),
            "file" => Ok(Self::File),
            other => Err(Error::usage(format!(
                "unknown credential store {other:?}; use keyring or file"
            ))),
        }
    }
}

/// One deployment.
#[derive(Debug, Clone, PartialEq, Eq, Facet)]
pub struct Profile {
    /// The issuer: the base URL of the subject-facing surface.
    pub url: String,
    /// The base URL of the control-plane surface, when it isn't `url`. It
    /// must be one of the server's `tokens.dpop_urls`.
    #[facet(default, skip_serializing_if = Option::is_none)]
    pub control_url: Option<String>,
    #[facet(default)]
    pub credential_store: CredentialStore,
}

impl Profile {
    /// A profile for `url`, checked to be an `http` or `https` base URL.
    ///
    /// # Errors
    ///
    /// A usage error for anything else.
    pub fn new(url: &str, control_url: Option<&str>) -> Result<Self> {
        Ok(Self {
            url: base_url(url)?,
            control_url: control_url.map(base_url).transpose()?,
            credential_store: CredentialStore::default(),
        })
    }

    /// Where control-plane requests go.
    #[must_use]
    pub fn control_base(&self) -> &str {
        self.control_url.as_deref().unwrap_or(&self.url)
    }
}

/// A base URL without a trailing slash, query or fragment.
fn base_url(url: &str) -> Result<String> {
    let parsed =
        url::Url::parse(url).map_err(|e| Error::usage(format!("not a URL: {url:?}: {e}")))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host().is_none() {
        return Err(Error::usage(format!("not an http(s) URL: {url:?}")));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(Error::usage(format!(
            "a base URL has no query or fragment: {url:?}"
        )));
    }
    Ok(parsed.as_str().trim_end_matches('/').to_owned())
}

/// The whole configuration file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Facet)]
pub struct Config {
    /// The profile commands use when none is named.
    #[facet(default, skip_serializing_if = Option::is_none)]
    pub default: Option<String>,
    #[facet(default)]
    pub profiles: BTreeMap<String, Profile>,
}

/// The CLI's configuration directory: `KONKLAV_CONFIG_DIR`, or `konklav`
/// in the platform's configuration directory.
///
/// # Errors
///
/// When the platform has no configuration directory and none is set.
pub fn config_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("KONKLAV_CONFIG_DIR") {
        return Ok(PathBuf::from(dir));
    }
    dirs::config_dir()
        .map(|dir| dir.join("konklav"))
        .ok_or_else(|| Error::local("no configuration directory; set KONKLAV_CONFIG_DIR"))
}

impl Config {
    fn path(dir: &Path) -> PathBuf {
        dir.join("config.styx")
    }

    /// Reads the configuration in `dir`; a missing file is an empty one.
    ///
    /// # Errors
    ///
    /// When the file can't be read or isn't a valid configuration.
    pub fn load(dir: &Path) -> Result<Self> {
        let path = Self::path(dir);
        match std::fs::read_to_string(&path) {
            Ok(text) => facet_styx::from_str(&text)
                .map_err(|e| Error::local(format!("{}: {e}", path.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(Error::local(format!("{}: {e}", path.display()))),
        }
    }

    /// Writes the configuration to `dir`, creating it.
    ///
    /// # Errors
    ///
    /// When the directory or file can't be written.
    pub fn save(&self, dir: &Path) -> Result<()> {
        let text = facet_styx::to_string(self)
            .map_err(|e| Error::local(format!("can't write the configuration: {e}")))?;
        std::fs::create_dir_all(dir)
            .and_then(|()| std::fs::write(Self::path(dir), text))
            .map_err(|e| Error::local(format!("{}: {e}", Self::path(dir).display())))
    }

    /// The profile named `name`, or the default one.
    ///
    /// # Errors
    ///
    /// A not-signed-in error when there is no such profile.
    pub fn profile(&self, name: Option<&str>) -> Result<(String, Profile)> {
        let name = name
            .map(str::to_owned)
            .or_else(|| self.default.clone())
            .ok_or_else(|| {
                Error::NotSignedIn("no profile; run `konklav login --url <issuer>`".into())
            })?;
        let profile = self.profiles.get(&name).cloned().ok_or_else(|| {
            Error::NotSignedIn(format!(
                "no profile {name:?}; run `konklav login --profile {name} --url <issuer>`"
            ))
        })?;
        Ok((name, profile))
    }
}

/// A profile name: letters, digits, `-` and `_`, since it names files and
/// credential-store entries.
///
/// # Errors
///
/// A usage error for any other name.
pub fn check_name(name: &str) -> Result<()> {
    if !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        Ok(())
    } else {
        Err(Error::usage(format!(
            "a profile name is 1 to 64 letters, digits, - or _: {name:?}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_configuration_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(Config::load(dir.path()).unwrap(), Config::default());
        let mut config = Config {
            default: Some("dev".into()),
            ..Config::default()
        };
        config.profiles.insert(
            "dev".into(),
            Profile::new("http://localhost:8080/", None).unwrap(),
        );
        let mut prod =
            Profile::new("https://id.example", Some("https://admin.example/control/")).unwrap();
        prod.credential_store = CredentialStore::File;
        config.profiles.insert("prod".into(), prod);
        config.save(dir.path()).unwrap();
        let loaded = Config::load(dir.path()).unwrap();
        assert_eq!(loaded, config);
        let (name, dev) = loaded.profile(None).unwrap();
        assert_eq!(name, "dev");
        assert_eq!(dev.url, "http://localhost:8080");
        assert_eq!(dev.control_base(), "http://localhost:8080");
        let (_, prod) = loaded.profile(Some("prod")).unwrap();
        assert_eq!(prod.control_base(), "https://admin.example/control");
        assert!(matches!(
            loaded.profile(Some("missing")),
            Err(Error::NotSignedIn(_))
        ));
    }

    #[test]
    fn base_urls_are_checked() {
        assert!(Profile::new("ftp://id.example", None).is_err());
        assert!(Profile::new("https://id.example/?a=b", None).is_err());
        assert!(Profile::new("id.example", None).is_err());
        assert_eq!(
            Profile::new("https://id.example/base/", None).unwrap().url,
            "https://id.example/base"
        );
    }

    #[test]
    fn profile_names_are_checked() {
        check_name("prod-eu_1").unwrap();
        assert!(check_name("").is_err());
        assert!(check_name("../x").is_err());
    }
}
