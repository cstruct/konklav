use std::collections::{BTreeMap, BTreeSet};

use konklav_authz::{Decision, DenyReason, EntitlementSet, Requirements, evaluate};
use konklav_core::feed::{EntitlementsChanged, FeedEvent, FeedPayload, SessionChanged};
use konklav_core::{Cursor, SessionId, SubjectId, TenantId};
use konklav_token::{AccessClaims, JwkSet, VerifyOptions};
use serde::{Deserialize, Serialize};

use crate::Config;

/// Which entitlement set: a subject in a tenant, or its global-only set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Key {
    pub subject: SubjectId,
    pub tenant: Option<TenantId>,
}

/// Something the core needs before it can decide.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "need", rename_all = "snake_case")]
pub enum Need {
    /// Fetch `/.well-known/jwks.json` and call [`Relying::on_jwks`].
    Jwks,
    /// Fetch `/v1/session-states/{session}` and call
    /// [`Relying::on_session`].
    Session { session: SessionId },
    /// Fetch `/v1/entitlements/{subject}[/{tenant}]` and call
    /// [`Relying::on_entitlements`].
    Entitlements { key: Key },
    /// The caches can't be trusted: ask `POST /v1/check` instead.
    Check,
}

/// The answer to [`Relying::decide`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Outcome {
    Decided {
        decision: Decision,
    },
    /// Provide these, then ask again.
    Need {
        needs: Vec<Need>,
    },
}

/// The answer to [`Relying::verify`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Verification {
    /// The token verifies and its session is current.
    Verified {
        claims: Box<konklav_token::AccessClaims>,
    },
    /// The token doesn't verify, or its session has ended or moved on.
    Invalid,
    /// Provide these, then ask again.
    Need { needs: Vec<Need> },
}

/// Background fetches that are due, and when to poll again.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Work {
    pub fetch: Vec<Need>,
    /// Milliseconds; poll again no later than this.
    pub next_poll_at: u64,
}

/// The request a token was presented with. Unused until sender-constrained
/// tokens arrive, but part of the API so adding them is not a breaking
/// change.
// r[impl item.relying.request-descriptor]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestDescriptor {
    pub method: String,
    pub url: String,
}

#[derive(Clone, Debug)]
struct Entry {
    set: Option<EntitlementSet>,
    fetched_at: u64,
    /// When an invalidation arrived, and the cursor of that event.
    stale: Option<(u64, Cursor)>,
    last_used: u64,
    in_flight: bool,
}

#[derive(Clone, Debug, Default)]
struct Feed {
    connected: bool,
    last_seen: u64,
    cursor: Option<Cursor>,
}

/// The relying core's state. See the crate docs for how hosts drive it.
#[derive(Clone, Debug)]
pub struct Relying {
    config: Config,
    jwks: Option<JwkSet>,
    jwks_fetched_at: Option<u64>,
    jwks_wanted: bool,
    jwks_in_flight: bool,
    sessions: BTreeMap<SessionId, SessionChanged>,
    /// Sessions Konklav doesn't know: tokens for them are never valid.
    unknown_sessions: BTreeSet<SessionId>,
    entries: BTreeMap<Key, Entry>,
    feed: Feed,
    /// The highest cursor a caller waits to read its own writes at.
    awaited: Option<Cursor>,
}

impl Relying {
    #[must_use]
    pub fn new(config: Config) -> Self {
        Self {
            config,
            jwks: None,
            jwks_fetched_at: None,
            jwks_wanted: true,
            jwks_in_flight: false,
            sessions: BTreeMap::new(),
            unknown_sessions: BTreeSet::new(),
            entries: BTreeMap::new(),
            feed: Feed::default(),
            awaited: None,
        }
    }

    #[must_use]
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Whether local decisions can be trusted: the feed is connected and has
    /// been heard from recently.
    // r[impl relying.fallback.lag]
    #[must_use]
    pub fn is_trusted(&self, now: u64) -> bool {
        let silence = self.config.heartbeat_ms * self.config.missed_heartbeats;
        self.feed.connected && now.saturating_sub(self.feed.last_seen) < silence
    }

    /// The cursor to resume the feed from (`Last-Event-ID`).
    #[must_use]
    pub fn feed_cursor(&self) -> Option<Cursor> {
        self.feed.cursor
    }

    /// Verifies `token` and checks its session, without evaluating any
    /// requirements: for hosts that build their own request context.
    pub fn verify(&mut self, token: &str, now: u64) -> Verification {
        match self.check_token(token, now) {
            Ok((claims, needs)) if needs.is_empty() => Verification::Verified {
                claims: Box::new(claims),
            },
            Ok((_, needs)) | Err(Outcome::Need { needs }) => Verification::Need { needs },
            Err(Outcome::Decided { .. }) => Verification::Invalid,
        }
    }

    /// The cached entitlement set for `key`, or what to fetch first.
    pub fn entitlements(&mut self, key: Key, now: u64) -> Result<EntitlementSet, Vec<Need>> {
        if !self.is_trusted(now) {
            return Err(vec![Need::Check]);
        }
        let usable = self.usable_entry(key, now);
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.last_used = now;
        }
        usable.ok_or_else(|| vec![Need::Entitlements { key }])
    }

    /// Verifies the token and its session. `Err` carries the outcome to
    /// return; `Ok` carries the claims and any session fetch still needed.
    fn check_token(&mut self, token: &str, now: u64) -> Result<(AccessClaims, Vec<Need>), Outcome> {
        let invalid = || Outcome::Decided {
            decision: Decision::Deny {
                reason: DenyReason::InvalidToken,
            },
        };
        if !self.is_trusted(now) {
            return Err(Outcome::Need {
                needs: vec![Need::Check],
            });
        }

        let Ok(kid) = konklav_token::decode_unverified_kid(token) else {
            return Err(invalid());
        };
        let key = self.jwks.as_ref().and_then(|jwks| jwks.find(&kid));
        let Some(key) = key else {
            let recently = self
                .jwks_fetched_at
                .is_some_and(|at| now.saturating_sub(at) < self.config.jwks_min_refresh_ms);
            if recently {
                return Err(invalid());
            }
            self.jwks_wanted = true;
            return Err(Outcome::Need {
                needs: vec![Need::Jwks],
            });
        };
        let now_seconds = i64::try_from(now / 1000).unwrap_or(i64::MAX);
        let options = VerifyOptions {
            issuer: &self.config.issuer,
            audience: &self.config.audience,
            now: now_seconds,
            leeway: self.config.leeway_seconds,
        };
        let Ok(claims) = konklav_token::verify(token, |_| Some(key), &options) else {
            return Err(invalid());
        };

        if self.unknown_sessions.contains(&claims.sid) {
            return Err(invalid());
        }
        let mut needs = Vec::new();
        match self.sessions.get(&claims.sid) {
            Some(session)
                if session.revoked
                    || session.expires_at <= now_seconds
                    || claims.sv < session.version =>
            {
                return Err(invalid());
            }
            // A token newer than what we know means we missed an event.
            Some(session) if claims.sv > session.version => needs.push(Need::Session {
                session: claims.sid,
            }),
            Some(_) => {}
            None => needs.push(Need::Session {
                session: claims.sid,
            }),
        }
        Ok((claims, needs))
    }

    /// Decides `requirements` for `token`, or says what is missing.
    // r[impl relying.decision.local]
    // r[impl relying.verify.offline]
    // r[impl relying.verify.session]
    // r[depends item.authz.single-evaluator]
    pub fn decide(
        &mut self,
        token: &str,
        requirements: &Requirements,
        _request: Option<&RequestDescriptor>,
        now: u64,
    ) -> Outcome {
        let (claims, mut needs) = match self.check_token(token, now) {
            Ok(checked) => checked,
            Err(outcome) => return outcome,
        };
        let now_seconds = i64::try_from(now / 1000).unwrap_or(i64::MAX);

        let key = Key {
            subject: claims.sub,
            tenant: claims.tid,
        };
        let usable = self.usable_entry(key, now);
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.last_used = now;
        }
        let Some(set) = usable else {
            needs.push(Need::Entitlements { key });
            return Outcome::Need { needs };
        };
        if !needs.is_empty() {
            return Outcome::Need { needs };
        }
        Outcome::Decided {
            decision: evaluate(
                requirements,
                &claims,
                &set.restrictive_flags,
                &set.entitlements,
                now_seconds,
            ),
        }
    }

    /// The entry's set, if it may be used now.
    fn usable_entry(&self, key: Key, now: u64) -> Option<EntitlementSet> {
        let entry = self.entries.get(&key)?;
        let set = entry.set.as_ref()?;
        if now >= entry.fetched_at + self.config.entitlement_ttl_ms {
            return None;
        }
        if let Some((since, cursor)) = entry.stale {
            let awaited = self.awaited.is_some_and(|awaited| cursor <= awaited);
            if awaited || now >= since + self.config.debounce_ms {
                return None;
            }
        }
        Some(set.clone())
    }

    pub fn on_jwks(&mut self, jwks: JwkSet, now: u64) {
        self.jwks = Some(jwks);
        self.jwks_fetched_at = Some(now);
        self.jwks_wanted = false;
        self.jwks_in_flight = false;
    }

    pub fn on_session(&mut self, state: SessionChanged) {
        let newer = self
            .sessions
            .get(&state.session)
            .is_none_or(|known| state.version >= known.version);
        if newer {
            self.sessions.insert(state.session, state);
        }
    }

    /// Konklav has no such session (a forged or long-pruned one).
    pub fn on_session_unknown(&mut self, session: SessionId) {
        self.unknown_sessions.insert(session);
    }

    pub fn on_entitlements(&mut self, set: EntitlementSet, now: u64) {
        let key = Key {
            subject: set.subject_id,
            tenant: set.tenant_id,
        };
        let entry = self.entries.entry(key).or_insert(Entry {
            set: None,
            fetched_at: now,
            stale: None,
            last_used: now,
            in_flight: false,
        });
        // A set compiled before the invalidation it should reflect stays
        // stale.
        let still_stale = entry.stale.filter(|(_, cursor)| set.revision < *cursor);
        entry.set = Some(set);
        entry.fetched_at = now;
        entry.stale = still_stale;
        entry.in_flight = false;
    }

    /// A fetch the core asked for failed; it may be asked for again.
    pub fn on_fetch_failed(&mut self, need: &Need) {
        match need {
            Need::Jwks => self.jwks_in_flight = false,
            Need::Entitlements { key } => {
                if let Some(entry) = self.entries.get_mut(key) {
                    entry.in_flight = false;
                }
            }
            Need::Session { .. } | Need::Check => {}
        }
    }

    pub fn on_feed_connected(&mut self, now: u64) {
        self.feed.connected = true;
        self.feed.last_seen = now;
    }

    /// Anything arrived on the feed, including heartbeats.
    pub fn on_feed_activity(&mut self, now: u64) {
        self.feed.last_seen = now;
    }

    pub fn on_feed_lost(&mut self) {
        self.feed.connected = false;
    }

    /// Applies one feed event. Malformed events of known kinds are an error,
    /// and the host should reconnect so it doesn't skip an invalidation.
    // r[impl relying.feed.consume]
    // r[impl relying.cache.session-immediate]
    pub fn on_feed_event(&mut self, event: &FeedEvent, now: u64) -> Result<(), serde_json::Error> {
        self.feed.last_seen = now;
        match event.parse()? {
            FeedPayload::SessionChanged(state) => self.on_session(state),
            FeedPayload::EntitlementsChanged(changed) => {
                self.invalidate(&changed, event.cursor, now);
            }
            FeedPayload::SigningKeysChanged(_) => self.jwks_wanted = true,
            // r[impl relying.feed.reset]
            FeedPayload::Reset => {
                self.sessions.clear();
                self.unknown_sessions.clear();
                self.jwks_wanted = true;
                for entry in self.entries.values_mut() {
                    entry.stale.get_or_insert((now, event.cursor));
                }
            }
            FeedPayload::Other => {}
        }
        self.feed.cursor = Some(event.cursor);
        Ok(())
    }

    fn invalidate(&mut self, changed: &EntitlementsChanged, cursor: Cursor, now: u64) {
        let subjects: BTreeSet<SubjectId> = changed.subjects.iter().copied().collect();
        for (key, entry) in &mut self.entries {
            let subject_matches = changed.all || subjects.contains(&key.subject);
            // A tenant-narrowed change never affects global-only sets of
            // other subjects, but global sets of named subjects do change.
            let tenant_matches = match changed.tenant {
                None => true,
                Some(tenant) => {
                    key.tenant == Some(tenant) || (!changed.all && key.tenant.is_none())
                }
            };
            if subject_matches && tenant_matches {
                match entry.stale {
                    Some((_, ref mut stale_cursor)) => *stale_cursor = (*stale_cursor).max(cursor),
                    None => entry.stale = Some((now, cursor)),
                }
            }
        }
    }

    /// Marks that the caller wants to read its own writes up to `cursor`.
    /// Returns whether that is already possible: the feed has passed the
    /// cursor and every entry invalidated up to it has been refreshed.
    // r[impl relying.cache.await-cursor]
    pub fn await_cursor(&mut self, cursor: Cursor) -> bool {
        self.awaited = Some(self.awaited.map_or(cursor, |awaited| awaited.max(cursor)));
        let caught_up = self.feed.cursor.is_some_and(|seen| seen >= cursor);
        let refreshed = self
            .entries
            .values()
            .all(|entry| entry.stale.is_none_or(|(_, stale)| stale > cursor));
        caught_up && refreshed
    }

    /// Background fetches that are due. Entries handed out are marked in
    /// flight until their result or failure is reported.
    // r[impl relying.cache.background-refresh]
    // r[impl item.relying.scheduler]
    pub fn poll_work(&mut self, now: u64) -> Work {
        let config = &self.config;
        let mut fetch = Vec::new();
        let mut next = now + config.heartbeat_ms;

        if self.jwks_wanted && !self.jwks_in_flight {
            self.jwks_in_flight = true;
            fetch.push(Need::Jwks);
        }

        // Forget entries nobody has used for a whole TTL.
        let ttl = config.entitlement_ttl_ms;
        self.entries
            .retain(|_, entry| now.saturating_sub(entry.last_used) < ttl);
        let now_seconds = i64::try_from(now / 1000).unwrap_or(i64::MAX);
        self.sessions
            .retain(|_, session| session.expires_at > now_seconds);

        let awaited = self.awaited;
        let mut handed_out = 0;
        for (key, entry) in &mut self.entries {
            if entry.in_flight {
                continue;
            }
            let due_at = match entry.stale {
                Some((_, cursor)) if awaited.is_some_and(|a| cursor <= a) => now,
                Some((since, _)) => since + config.debounce_ms,
                None => (entry.fetched_at + ttl).saturating_sub(config.refresh_margin_ms),
            };
            if due_at <= now && handed_out < config.sweep_batch {
                entry.in_flight = true;
                handed_out += 1;
                fetch.push(Need::Entitlements { key: *key });
            } else {
                next = next.min(due_at.max(now + 1));
            }
        }
        if handed_out == config.sweep_batch {
            next = now;
        }
        Work {
            fetch,
            next_poll_at: next,
        }
    }

    /// Records a decision made through the check API in the same form as a
    /// local one.
    // r[impl relying.fallback.equivalence]
    #[must_use]
    pub fn from_check(decision: Decision) -> Outcome {
        Outcome::Decided { decision }
    }
}
