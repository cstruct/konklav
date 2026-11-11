use std::collections::{BTreeMap, BTreeSet};

use konklav_authz::{
    Decision, DenyReason, EntitlementSet, RegisteredScopes, Registration, Requirements, Scope,
    evaluate,
};
use konklav_core::feed::{
    EntitlementsChanged, FeedEvent, FeedPayload, ScopeChanged, SessionChanged, SubjectErased,
};
use konklav_core::{Cursor, SessionId, SubjectId, TenantId};
use konklav_token::{AccessClaims, JwkSet, VerifyOptions};
use serde::{Deserialize, Serialize};

use crate::Config;
use crate::presented::{self, Held, PresentationId, Presented, ProofSettings, Refused, Replays};

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
    /// Fetch `/v1/registered-scopes/{kind}/{id}` (each segment
    /// percent-encoded) and call [`Relying::on_registered_scope`], or
    /// [`Relying::on_registered_scope_unknown`] on `404`.
    RegisteredScope { kind: String, id: String },
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
    /// Refused for the DPoP proof or the authorization scheme: a
    /// sender-constrained token without a valid proof, or a bearer token
    /// under the `DPoP` scheme. Answer with a `WWW-Authenticate: DPoP`
    /// challenge.
    // r[impl relying.verify.dpop-challenge]
    InvalidProof,
    /// Provide these, then ask again.
    Need { needs: Vec<Need> },
}

/// The answer to [`Relying::accept_presented`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Acceptance {
    /// The token verifies, its session is current and any proof is
    /// accepted: decide with [`Relying::decide_accepted`] and `presentation`.
    Accepted {
        claims: Box<konklav_token::AccessClaims>,
        presentation: PresentationId,
    },
    /// Any proof is accepted, but the caches can't be trusted: verify the
    /// token with the check API, then decide with `presentation`.
    Check { presentation: PresentationId },
    /// As [`Verification::Invalid`].
    Invalid,
    /// As [`Verification::InvalidProof`].
    InvalidProof,
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

/// The request a token was presented with: the method and the URL the
/// client addressed, which a DPoP proof must name.
/// What a feed event means for the data the relying system itself keeps
/// about subjects. The core has dealt with its own caches already; the host
/// binding hands the notice to the relying system.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "notice", rename_all = "snake_case")]
pub enum ErasureNotice {
    /// Konklav erased the subject. The same erasure may be handed over more
    /// than once.
    Erased(SubjectErased),
    /// Erasures may have been missed, so the relying system should read the
    /// erased subjects from Konklav.
    Missed {
        /// When this core applied its last feed event before the gap, in
        /// Unix seconds by the host's clock; `None` when it had applied
        /// none, as when the relying system has just started.
        since: Option<i64>,
    },
}

// r[impl item.relying.request-descriptor]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestDescriptor {
    pub method: String,
    pub url: String,
}

/// A registered scope's record, as `/v1/registered-scopes/{kind}/{id}`
/// serves it. Other fields are ignored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeRecord {
    pub kind: String,
    pub id: String,
    pub tenant: TenantId,
    #[serde(default)]
    pub containers: Vec<Scope>,
    /// `active` or `removed`.
    pub state: String,
}

impl ScopeRecord {
    fn registration(self) -> Option<Registration> {
        (self.state == "active").then_some(Registration {
            kind: self.kind,
            id: self.id,
            tenant: self.tenant,
            containers: self.containers,
        })
    }
}

/// What the core learned about a registered scope.
#[derive(Clone, Debug)]
enum Known {
    Active(Registration),
    /// Konklav doesn't know it, or it was removed.
    Absent,
}

impl Known {
    fn registration(&self) -> Option<Registration> {
        match self {
            Self::Active(record) => Some(record.clone()),
            Self::Absent => None,
        }
    }
}

/// A cached registered scope; `known` is `None` until it is fetched.
#[derive(Clone, Debug)]
struct ScopeEntry {
    known: Option<Known>,
    /// Whether Konklav answered `404`: such entries expire sooner and go
    /// as soon as an event names the scope.
    unknown: bool,
    fetched_at: u64,
    stale: Option<(u64, Cursor)>,
    last_used: u64,
    in_flight: bool,
    /// The feed cursor when the fetch was asked for: an event after it may
    /// not be reflected in the result.
    asked_at: Option<Cursor>,
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
    /// When the last event was applied, for telling the host since when
    /// erasures may have been missed.
    applied_at: Option<u64>,
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
    scopes: BTreeMap<Scope, ScopeEntry>,
    feed: Feed,
    /// The highest cursor a caller waits to read its own writes at.
    awaited: Option<Cursor>,
    /// DPoP proofs accepted recently, so none is accepted twice.
    replays: Replays,
    /// Presentations accepted for one decision.
    held: Held,
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
            scopes: BTreeMap::new(),
            feed: Feed::default(),
            awaited: None,
            replays: Replays::default(),
            held: Held::default(),
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

    /// Verifies a bearer `token` and checks its session, without
    /// evaluating any requirements: for hosts that build their own request
    /// context. A sender-constrained token is refused: use
    /// [`Relying::verify_presented`] for those.
    pub fn verify(&mut self, token: &str, now: u64) -> Verification {
        self.verify_presented(&Presented::bearer(token), now)
    }

    /// [`Relying::verify`] for a request's raw `Authorization` and `DPoP`
    /// headers, so sender-constrained tokens verify too.
    pub fn verify_presented(&mut self, presented: &Presented, now: u64) -> Verification {
        let (token, accepted) =
            match presented::token(presented, &self.replays, &self.proof_settings(), now) {
                Ok(found) => found,
                Err(Refused::Token) => return Verification::Invalid,
                Err(Refused::Proof) => return Verification::InvalidProof,
            };
        let verification = match self.check_token(token, now) {
            Ok((claims, needs)) if needs.is_empty() => Verification::Verified {
                claims: Box::new(claims),
            },
            Ok((_, needs)) | Err(Outcome::Need { needs }) => Verification::Need { needs },
            Err(Outcome::Decided { .. }) => Verification::Invalid,
        };
        let answered = match &verification {
            Verification::Need { needs } => needs.contains(&Need::Check),
            _ => true,
        };
        if answered && !self.remember(accepted, now) {
            return Verification::InvalidProof;
        }
        verification
    }

    /// [`Relying::verify_presented`] for a host that decides afterwards:
    /// accepts the presentation once, remembering its proof, and holds it
    /// for one [`Relying::decide_accepted`], which doesn't check the proof
    /// again.
    // r[impl relying.verify.accepted-presentation]
    pub fn accept_presented(&mut self, presented: &Presented, now: u64) -> Acceptance {
        let (token, accepted) =
            match presented::token(presented, &self.replays, &self.proof_settings(), now) {
                Ok(found) => found,
                Err(Refused::Token) => return Acceptance::Invalid,
                Err(Refused::Proof) => return Acceptance::InvalidProof,
            };
        // A bearer token is held as long as a proof would be.
        let until = accepted.as_ref().map_or_else(
            || {
                let seconds = self.config.dpop_max_age_seconds + self.config.leeway_seconds;
                now.saturating_add(u64::try_from(seconds).unwrap_or(0).saturating_mul(1000))
            },
            presented::Accepted::until,
        );
        // Verified claims, or `None` for a hand-off to the check API.
        let verified = match self.check_token(token, now) {
            Ok((claims, needs)) if needs.is_empty() => Some(claims),
            Ok((_, needs)) | Err(Outcome::Need { needs }) => {
                if !needs.contains(&Need::Check) {
                    // Not answered: the host asks again with the same proof.
                    return Acceptance::Need { needs };
                }
                None
            }
            Err(Outcome::Decided { .. }) => {
                // Answered, so the proof is used.
                return if self.remember(accepted, now) {
                    Acceptance::Invalid
                } else {
                    Acceptance::InvalidProof
                };
            }
        };
        if !self.remember(accepted, now) {
            return Acceptance::InvalidProof;
        }
        let capacity = self.config.dpop_replay_capacity;
        let Some(presentation) = self.held.hold(token, until, capacity, now) else {
            return Acceptance::InvalidProof;
        };
        match verified {
            Some(claims) => Acceptance::Accepted {
                claims: Box::new(claims),
                presentation,
            },
            None => Acceptance::Check { presentation },
        }
    }

    /// Decides `requirements` for a presentation [`Relying::accept_presented`]
    /// accepted, without checking its proof again; the token and its session
    /// are checked as [`Relying::decide`] checks them. Once answered (a
    /// decision, or a hand-off to the check API), the presentation is gone.
    /// An unknown, answered or expired one is denied as `invalid_token`.
    // r[impl relying.verify.accepted-presentation]
    pub fn decide_accepted(
        &mut self,
        presentation: PresentationId,
        requirements: &Requirements,
        now: u64,
    ) -> Outcome {
        let Some(token) = self.held.token(presentation, now) else {
            self.held.release(presentation);
            return Outcome::Decided {
                decision: Decision::Deny {
                    reason: DenyReason::InvalidToken,
                },
            };
        };
        let outcome = self.decide_token(&token, requirements, now);
        let answered = match &outcome {
            Outcome::Need { needs } => needs.contains(&Need::Check),
            Outcome::Decided { .. } => true,
        };
        if answered {
            self.held.release(presentation);
        }
        outcome
    }

    fn proof_settings(&self) -> ProofSettings {
        ProofSettings {
            max_age_seconds: self.config.dpop_max_age_seconds,
            leeway_seconds: self.config.leeway_seconds,
        }
    }

    /// Remembers an accepted proof once the core has answered with it: a
    /// decision, or a hand-off to the check API. Not while it still waits
    /// for a fetch, since the host then asks again with the same proof.
    /// Returns false if the replay set is full.
    fn remember(&mut self, accepted: Option<presented::Accepted>, now: u64) -> bool {
        accepted.is_none_or(|accepted| {
            self.replays
                .remember(accepted, self.config.dpop_replay_capacity, now)
        })
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
            audiences: &self.config.audiences,
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
    ///
    /// `token` is a bearer token; a sender-constrained one is denied. Use
    /// [`Relying::decide_presented`] for requests that may carry DPoP.
    pub fn decide(
        &mut self,
        token: &str,
        requirements: &Requirements,
        request: Option<&RequestDescriptor>,
        now: u64,
    ) -> Outcome {
        let presented = Presented {
            request: request.cloned(),
            ..Presented::bearer(token)
        };
        self.decide_presented(&presented, requirements, now)
    }

    /// [`Relying::decide`] for a request's raw `Authorization` and `DPoP`
    /// headers and its request descriptor. The DPoP proof is checked before
    /// anything else, including before a hand-off to the check API, which
    /// never sees it (`r[relying.verify.dpop-before-check]`).
    // r[impl relying.verify.dpop-before-check]
    pub fn decide_presented(
        &mut self,
        presented: &Presented,
        requirements: &Requirements,
        now: u64,
    ) -> Outcome {
        let deny = |reason| Outcome::Decided {
            decision: Decision::Deny { reason },
        };
        let (token, accepted) =
            match presented::token(presented, &self.replays, &self.proof_settings(), now) {
                Ok(found) => found,
                Err(Refused::Token) => return deny(DenyReason::InvalidToken),
                Err(Refused::Proof) => return deny(DenyReason::InvalidDpopProof),
            };
        let outcome = self.decide_token(token, requirements, now);
        let answered = match &outcome {
            Outcome::Need { needs } => needs.contains(&Need::Check),
            Outcome::Decided { .. } => true,
        };
        if answered && !self.remember(accepted, now) {
            return deny(DenyReason::InvalidDpopProof);
        }
        outcome
    }

    fn decide_token(&mut self, token: &str, requirements: &Requirements, now: u64) -> Outcome {
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
        let registered = self.registered_for(&set, requirements, now, &mut needs);
        if !needs.is_empty() {
            return Outcome::Need { needs };
        }
        Outcome::Decided {
            decision: evaluate(
                requirements,
                &claims,
                &set.restrictive_flags,
                &set.confinements,
                &set.entitlements,
                &registered,
                now_seconds,
            ),
        }
    }

    /// The records of the registered scopes `requirements` name, adding a
    /// need for each one that isn't usable.
    // r[impl relying.cache.registered]
    fn registered_for(
        &mut self,
        set: &EntitlementSet,
        requirements: &Requirements,
        now: u64,
        needs: &mut Vec<Need>,
    ) -> RegisteredScopes {
        let mut registered = RegisteredScopes {
            kinds: set.registered_kinds.clone(),
            records: BTreeMap::new(),
        };
        for required in &requirements.scopes {
            if !registered.kinds.contains(&required.kind) {
                continue;
            }
            let scope = Scope {
                kind: required.kind.clone(),
                id: required.id.clone(),
            };
            match self.usable_scope(&scope, now) {
                Some(known) => {
                    registered
                        .records
                        .insert(scope.clone(), known.registration());
                }
                None => {
                    let asked_at = self.feed.cursor;
                    let entry = self.scope_entry(&scope, now);
                    entry.asked_at = asked_at;
                    needs.push(Need::RegisteredScope {
                        kind: scope.kind.clone(),
                        id: scope.id.clone(),
                    });
                }
            }
            if let Some(entry) = self.scopes.get_mut(&scope) {
                entry.last_used = now;
            }
        }
        registered
    }

    /// The cached record of `scope`, if it may be used now.
    // r[impl relying.cache.registered-debounce]
    fn usable_scope(&self, scope: &Scope, now: u64) -> Option<Known> {
        let entry = self.scopes.get(scope)?;
        let known = entry.known.as_ref()?;
        let ttl = if entry.unknown {
            self.config.unknown_scope_ttl_ms
        } else {
            self.config.entitlement_ttl_ms
        };
        if now >= entry.fetched_at + ttl {
            return None;
        }
        if let Some((since, cursor)) = entry.stale {
            let awaited = self.awaited.is_some_and(|awaited| cursor <= awaited);
            if awaited || now >= since + self.config.debounce_ms {
                return None;
            }
        }
        Some(known.clone())
    }

    fn scope_entry(&mut self, scope: &Scope, now: u64) -> &mut ScopeEntry {
        self.scopes.entry(scope.clone()).or_insert(ScopeEntry {
            known: None,
            unknown: false,
            fetched_at: now,
            stale: None,
            last_used: now,
            in_flight: false,
            asked_at: None,
        })
    }

    /// Applies a registered scope's record fetched from Konklav.
    pub fn on_registered_scope(&mut self, record: ScopeRecord, now: u64) {
        let scope = Scope {
            kind: record.kind.clone(),
            id: record.id.clone(),
        };
        let known = record.registration().map_or(Known::Absent, Known::Active);
        self.store_scope(&scope, known, false, now);
    }

    /// Konklav answered `404`: the scope was never registered.
    // r[impl relying.cache.registered-unknown]
    pub fn on_registered_scope_unknown(&mut self, kind: &str, id: &str, now: u64) {
        let scope = Scope {
            kind: kind.to_owned(),
            id: id.to_owned(),
        };
        self.store_scope(&scope, Known::Absent, true, now);
    }

    fn store_scope(&mut self, scope: &Scope, known: Known, unknown: bool, now: u64) {
        let entry = self.scope_entry(scope, now);
        // An event after the fetch was asked for may not be reflected.
        let still_stale = entry
            .stale
            .filter(|(_, cursor)| entry.asked_at.is_none_or(|asked| *cursor > asked));
        entry.known = Some(known);
        entry.unknown = unknown;
        entry.fetched_at = now;
        entry.stale = still_stale;
        entry.in_flight = false;
        self.evict_scopes();
    }

    /// Keeps at most the configured number of records, dropping the least
    /// recently used.
    fn evict_scopes(&mut self) {
        let excess = self
            .scopes
            .len()
            .saturating_sub(self.config.registered_capacity);
        if excess == 0 {
            return;
        }
        let mut by_use: Vec<(u64, Scope)> = self
            .scopes
            .iter()
            .filter(|(_, entry)| !entry.in_flight)
            .map(|(scope, entry)| (entry.last_used, scope.clone()))
            .collect();
        by_use.sort();
        for (_, scope) in by_use.into_iter().take(excess) {
            self.scopes.remove(&scope);
        }
    }

    fn invalidate_scopes(&mut self, changed: &ScopeChanged, cursor: Cursor, now: u64) {
        for changed in &changed.scopes {
            let scope = Scope {
                kind: changed.kind.clone(),
                id: changed.id.clone(),
            };
            let Some(entry) = self.scopes.get_mut(&scope) else {
                continue;
            };
            if entry.unknown && !entry.in_flight {
                self.scopes.remove(&scope);
                continue;
            }
            match entry.stale {
                Some((_, ref mut stale_cursor)) => *stale_cursor = (*stale_cursor).max(cursor),
                None => entry.stale = Some((now, cursor)),
            }
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
            Need::RegisteredScope { kind, id } => {
                let scope = Scope {
                    kind: kind.clone(),
                    id: id.clone(),
                };
                if let Some(entry) = self.scopes.get_mut(&scope) {
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
    ///
    /// Returns what the host must pass on to the relying system, if
    /// anything.
    // r[impl relying.feed.consume]
    // r[impl relying.cache.session-immediate]
    pub fn on_feed_event(
        &mut self,
        event: &FeedEvent,
        now: u64,
    ) -> Result<Option<ErasureNotice>, serde_json::Error> {
        self.feed.last_seen = now;
        let mut notice = None;
        match event.parse()? {
            FeedPayload::SessionChanged(state) => self.on_session(state),
            FeedPayload::EntitlementsChanged(changed) => {
                self.invalidate(&changed, event.cursor, now);
            }
            FeedPayload::SigningKeysChanged(_) => self.jwks_wanted = true,
            FeedPayload::ScopeChanged(changed) => {
                self.invalidate_scopes(&changed, event.cursor, now);
            }
            // r[impl relying.erasure.notify]
            FeedPayload::SubjectErased(erased) => {
                self.sessions
                    .retain(|_, session| session.subject != erased.subject);
                self.entries.retain(|key, _| key.subject != erased.subject);
                notice = Some(ErasureNotice::Erased(erased));
            }
            // r[impl relying.feed.reset]
            FeedPayload::Reset => {
                self.sessions.clear();
                self.unknown_sessions.clear();
                self.jwks_wanted = true;
                for entry in self.entries.values_mut() {
                    entry.stale.get_or_insert((now, event.cursor));
                }
                self.scopes
                    .retain(|_, entry| !entry.unknown || entry.in_flight);
                for entry in self.scopes.values_mut() {
                    entry.stale.get_or_insert((now, event.cursor));
                }
                // r[impl relying.erasure.reset]
                notice = Some(ErasureNotice::Missed {
                    since: self.applied_seconds(),
                });
            }
            // The cursor below is all a position carries. A stream that
            // starts at a position without resuming from one of this core's
            // own has skipped whatever happened before it.
            // r[impl relying.feed.position]
            // r[impl relying.erasure.reset]
            FeedPayload::Position => {
                if self.feed.cursor.is_none() {
                    notice = Some(ErasureNotice::Missed { since: None });
                }
            }
            FeedPayload::Other => {}
        }
        self.feed.cursor = Some(event.cursor);
        self.feed.applied_at = Some(now);
        Ok(notice)
    }

    fn applied_seconds(&self) -> Option<i64> {
        self.feed
            .applied_at
            .map(|at| i64::try_from(at / 1000).unwrap_or(i64::MAX))
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
            .map(|entry| entry.stale)
            .chain(self.scopes.values().map(|entry| entry.stale))
            .all(|stale| stale.is_none_or(|(_, stale)| stale > cursor));
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
        let unknown_ttl = config.unknown_scope_ttl_ms;
        self.scopes.retain(|_, entry| {
            entry.in_flight
                || (now.saturating_sub(entry.last_used) < ttl
                    && !(entry.unknown && now >= entry.fetched_at + unknown_ttl))
        });
        let cursor = self.feed.cursor;
        for (scope, entry) in &mut self.scopes {
            // Records the core never got are fetched by `decide` itself.
            if entry.in_flight || entry.known.is_none() || entry.unknown {
                continue;
            }
            let due_at = match entry.stale {
                Some((_, stale)) if awaited.is_some_and(|a| stale <= a) => now,
                Some((since, _)) => since + config.debounce_ms,
                None => (entry.fetched_at + ttl).saturating_sub(config.refresh_margin_ms),
            };
            if due_at <= now && handed_out < config.sweep_batch {
                entry.in_flight = true;
                entry.asked_at = cursor;
                handed_out += 1;
                fetch.push(Need::RegisteredScope {
                    kind: scope.kind.clone(),
                    id: scope.id.clone(),
                });
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
