//! The change feed's wire format, shared by the server that produces it and
//! the relying core that consumes it.

use serde::{Deserialize, Serialize};

use crate::{Cursor, SessionId, SubjectId, TenantId};

/// One event as served by the change feed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedEvent {
    pub cursor: Cursor,
    pub kind: String,
    pub payload: serde_json::Value,
}

/// The kind of the synthetic event telling a consumer it could not resume
/// exactly where it left off, so every cached state may be stale.
pub const RESET: &str = "reset";

/// The kind of the synthetic event that begins a stream which needs no
/// reset, telling a consumer the cursor it starts after.
pub const POSITION: &str = "position";

/// `session.changed`: enough to apply without calling back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionChanged {
    pub session: SessionId,
    pub subject: SubjectId,
    pub version: i64,
    pub revoked: bool,
    /// Unix seconds.
    pub expires_at: i64,
}

/// `entitlements.changed`: either named subjects or everything, optionally
/// narrowed to one tenant.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntitlementsChanged {
    #[serde(default)]
    pub subjects: Vec<SubjectId>,
    #[serde(default)]
    pub all: bool,
    #[serde(default)]
    pub tenant: Option<TenantId>,
}

/// `signing_keys.changed`
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningKeysChanged {
    #[serde(default)]
    pub kids: Vec<String>,
}

/// One registered scope in a `scope.changed` event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangedScope {
    pub kind: String,
    pub id: String,
    pub tenant: TenantId,
    /// `active` or `removed`.
    pub state: String,
}

/// `scope.changed`: the registered scopes one transaction recorded,
/// changed or removed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeChanged {
    #[serde(default)]
    pub scopes: Vec<ChangedScope>,
}

/// A parsed feed event. Unknown kinds are kept as `Other`, so consumers
/// tolerate kinds added later.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FeedPayload {
    SessionChanged(SessionChanged),
    EntitlementsChanged(EntitlementsChanged),
    SigningKeysChanged(SigningKeysChanged),
    ScopeChanged(ScopeChanged),
    Reset,
    Position,
    Other,
}

impl FeedEvent {
    /// Parses the payload by kind. Malformed payloads of known kinds are an
    /// error rather than `Other`, because silently skipping one would hide
    /// an invalidation.
    pub fn parse(&self) -> Result<FeedPayload, serde_json::Error> {
        let payload = self.payload.clone();
        Ok(match self.kind.as_str() {
            "session.changed" => FeedPayload::SessionChanged(serde_json::from_value(payload)?),
            "entitlements.changed" => {
                FeedPayload::EntitlementsChanged(serde_json::from_value(payload)?)
            }
            "signing_keys.changed" => {
                FeedPayload::SigningKeysChanged(serde_json::from_value(payload)?)
            }
            "scope.changed" => FeedPayload::ScopeChanged(serde_json::from_value(payload)?),
            RESET => FeedPayload::Reset,
            POSITION => FeedPayload::Position,
            _ => FeedPayload::Other,
        })
    }
}
