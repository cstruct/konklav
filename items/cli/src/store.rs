//! Where a profile's DPoP key and tokens are kept between commands.
//!
//! Everything secret about a profile is one JSON record in one entry of its
//! credential store (`item.cli.secrets-in-keyring`). The access token is
//! kept too, so that commands run one after another don't each rotate the
//! refresh token; it is sender-constrained, so it is no more useful to a
//! thief than the refresh token beside it.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::profile::CredentialStore;

/// A profile's session, as stored.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredSession {
    /// The DPoP key's secret scalar, base64url.
    pub dpop_key: String,
    pub session_id: String,
    pub refresh_token: String,
    pub access_token: String,
    /// When the access token expires, Unix seconds.
    pub access_expires_at: i64,
}

impl std::fmt::Debug for StoredSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredSession")
            .field("session_id", &self.session_id)
            .finish_non_exhaustive()
    }
}

/// A credential store: one record per profile.
pub trait SecretStore: Send + Sync {
    /// The profile's record, if there is one.
    ///
    /// # Errors
    ///
    /// When the store can't be read.
    fn get(&self, profile: &str) -> Result<Option<StoredSession>>;

    /// Replaces the profile's record.
    ///
    /// # Errors
    ///
    /// When the store can't be written.
    fn set(&self, profile: &str, session: &StoredSession) -> Result<()>;

    /// Deletes the profile's record; a missing one is fine.
    ///
    /// # Errors
    ///
    /// When the store can't be written.
    fn delete(&self, profile: &str) -> Result<()>;
}

/// The store a profile's configuration names, rooted at `dir` for files.
#[must_use]
pub fn open(kind: CredentialStore, dir: &Path) -> Arc<dyn SecretStore> {
    match kind {
        CredentialStore::Keyring => Arc::new(Keyring),
        CredentialStore::File => Arc::new(FileStore {
            dir: dir.join("credentials"),
        }),
    }
}

const SERVICE: &str = "konklav";

/// The operating system's credential store.
// r[impl item.cli.secrets-in-keyring]
pub struct Keyring;

impl Keyring {
    fn entry(profile: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(SERVICE, profile).map_err(|e| keyring_error(&e))
    }
}

fn keyring_error(error: &keyring::Error) -> Error {
    Error::local(format!(
        "the credential store failed: {error}; `konklav login --credential-store file` keeps the \
         credentials in a file instead"
    ))
}

impl SecretStore for Keyring {
    fn get(&self, profile: &str) -> Result<Option<StoredSession>> {
        match Self::entry(profile)?.get_password() {
            Ok(text) => decode(&text).map(Some),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(keyring_error(&e)),
        }
    }

    fn set(&self, profile: &str, session: &StoredSession) -> Result<()> {
        Self::entry(profile)?
            .set_password(&encode(session))
            .map_err(|e| keyring_error(&e))
    }

    fn delete(&self, profile: &str) -> Result<()> {
        match Self::entry(profile)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(keyring_error(&e)),
        }
    }
}

/// Files readable only by the user, one per profile.
pub struct FileStore {
    dir: PathBuf,
}

impl FileStore {
    fn path(&self, profile: &str) -> PathBuf {
        self.dir.join(format!("{profile}.json"))
    }
}

impl SecretStore for FileStore {
    fn get(&self, profile: &str) -> Result<Option<StoredSession>> {
        match std::fs::read_to_string(self.path(profile)) {
            Ok(text) => decode(&text).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::local(format!(
                "{}: {e}",
                self.path(profile).display()
            ))),
        }
    }

    fn set(&self, profile: &str, session: &StoredSession) -> Result<()> {
        let path = self.path(profile);
        write_private(&self.dir, &path, encode(session).as_bytes())
            .map_err(|e| Error::local(format!("{}: {e}", path.display())))
    }

    fn delete(&self, profile: &str) -> Result<()> {
        match std::fs::remove_file(self.path(profile)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::local(format!(
                "{}: {e}",
                self.path(profile).display()
            ))),
        }
    }
}

/// Writes `bytes` to `path` so that only the user can read it, replacing
/// any earlier file in one rename.
fn write_private(dir: &Path, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    std::fs::create_dir_all(dir)?;
    let temporary = path.with_extension("json.tmp");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(temporary, path)
}

/// A store in memory, for tests and for one-off sessions.
#[derive(Default)]
pub struct MemoryStore(Mutex<std::collections::BTreeMap<String, StoredSession>>);

impl SecretStore for MemoryStore {
    fn get(&self, profile: &str) -> Result<Option<StoredSession>> {
        Ok(self.0.lock().expect("unpoisoned").get(profile).cloned())
    }

    fn set(&self, profile: &str, session: &StoredSession) -> Result<()> {
        self.0
            .lock()
            .expect("unpoisoned")
            .insert(profile.to_owned(), session.clone());
        Ok(())
    }

    fn delete(&self, profile: &str) -> Result<()> {
        self.0.lock().expect("unpoisoned").remove(profile);
        Ok(())
    }
}

fn encode(session: &StoredSession) -> String {
    serde_json::to_string(session).expect("a record always serializes")
}

fn decode(text: &str) -> Result<StoredSession> {
    serde_json::from_str(text).map_err(|_| {
        Error::NotSignedIn("the stored session is unreadable; run `konklav login` again".into())
    })
}

/// Holds a profile's lock while it reads, refreshes and stores its session,
/// so that two commands never present the same refresh token: Konklav would
/// see that as reuse and end the session.
pub struct ProfileLock {
    lock: fd_lock::RwLock<std::fs::File>,
}

impl ProfileLock {
    /// The lock file for `profile` in `dir`.
    ///
    /// # Errors
    ///
    /// When the lock file can't be opened.
    pub fn open(dir: &Path, profile: &str) -> Result<Self> {
        let locks = dir.join("locks");
        std::fs::create_dir_all(&locks)
            .map_err(|e| Error::local(format!("{}: {e}", locks.display())))?;
        let path = locks.join(format!("{profile}.lock"));
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|e| Error::local(format!("{}: {e}", path.display())))?;
        Ok(Self {
            lock: fd_lock::RwLock::new(file),
        })
    }

    /// Waits for the lock without blocking the thread; it is held until
    /// the guard is dropped.
    ///
    /// # Errors
    ///
    /// When the lock can't be taken.
    pub async fn lock(&mut self) -> Result<fd_lock::RwLockWriteGuard<'_, std::fs::File>> {
        loop {
            match self.lock.try_write() {
                Ok(_) => break,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                }
                Err(e) => return Err(Error::local(format!("can't lock the profile: {e}"))),
            }
        }
        // The probe above released the lock again: taking it here can only
        // wait as long as another command holds it, which is brief.
        self.lock
            .write()
            .map_err(|e| Error::local(format!("can't lock the profile: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> StoredSession {
        StoredSession {
            dpop_key: "key".into(),
            session_id: "sid".into(),
            refresh_token: "refresh".into(),
            access_token: "access".into(),
            access_expires_at: 1,
        }
    }

    // r[verify item.cli.secrets-in-keyring]
    #[test]
    fn the_file_store_keeps_records_private() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(CredentialStore::File, dir.path());
        assert!(store.get("dev").unwrap().is_none());
        store.set("dev", &session()).unwrap();
        assert_eq!(store.get("dev").unwrap().unwrap().refresh_token, "refresh");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(dir.path().join("credentials/dev.json"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        store.delete("dev").unwrap();
        store.delete("dev").unwrap();
        assert!(store.get("dev").unwrap().is_none());
    }

    #[test]
    fn debug_shows_no_secret() {
        let debug = format!("{:?}", session());
        assert!(!debug.contains("refresh\""));
        assert!(!debug.contains("access\""));
    }
}
