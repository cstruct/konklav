use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;
use konklav_authz::{Decision, DenyReason, EntitlementSet, Entitlements, Requirements};
use konklav_core::feed::{FeedEvent, SessionChanged};
use konklav_core::{Cursor, SessionId, SubjectId, TenantId};
use konklav_relying::{Config, Key, Need, Outcome, Relying};
use konklav_token::{AccessClaims, Jwk, JwkSet, Signer, TokenKind};
use serde_json::json;

const T0: u64 = 1_800_000_000_000;

struct Fixture {
    core: Relying,
    signer: Signer,
    subject: SubjectId,
    tenant: TenantId,
    session: SessionId,
}

fn config() -> Config {
    Config {
        issuer: "https://auth.example".into(),
        audience: "api".into(),
        ..Config::default()
    }
}

impl Fixture {
    fn new() -> Self {
        let signer = Signer::new(SigningKey::from_bytes(&[9; 32]));
        let mut core = Relying::new(config());
        core.on_feed_connected(T0);
        core.on_jwks(
            JwkSet {
                keys: vec![Jwk::from_verifying_key(&signer.verifying_key())],
            },
            T0,
        );
        Self {
            core,
            signer,
            subject: SubjectId::new_v7(),
            tenant: TenantId::new_v7(),
            session: SessionId::new_v7(),
        }
    }

    fn token(&self, version: i64, now: u64) -> String {
        let now = i64::try_from(now / 1000).unwrap();
        self.signer.sign(&AccessClaims {
            iss: "https://auth.example".into(),
            aud: "api".into(),
            sub: self.subject,
            jti: "j".into(),
            iat: now,
            exp: now + 900,
            knd: TokenKind::Tenant,
            sid: self.session,
            cid: None,
            sv: version,
            amr: vec!["pwd".into()],
            auth_time: now,
            tid: Some(self.tenant),
            mid: None,
            sfl: vec![],
            fct: BTreeMap::new(),
            act: None,
        })
    }

    fn key(&self) -> Key {
        Key {
            subject: self.subject,
            tenant: Some(self.tenant),
        }
    }

    fn session_state(&self, version: i64, revoked: bool) -> SessionChanged {
        SessionChanged {
            session: self.session,
            subject: self.subject,
            version,
            revoked,
            expires_at: i64::try_from(T0 / 1000).unwrap() + 86_400,
        }
    }

    fn set(&self, actions: &[&str], revision: i64) -> EntitlementSet {
        EntitlementSet {
            subject_id: self.subject,
            tenant_id: Some(self.tenant),
            revision: Cursor::new(revision),
            entitlements: Entitlements {
                tenant: actions.iter().map(|a| (*a).to_owned()).collect(),
                ..Entitlements::default()
            },
            restrictive_flags: BTreeSet::new(),
        }
    }

    /// Warms the caches: a version-1 session and `workspace:read`.
    fn warm(&mut self, now: u64) {
        self.core.on_session(self.session_state(1, false));
        let set = self.set(&["workspace:read"], 1);
        self.core.on_entitlements(set, now);
    }

    fn decide(&mut self, version: i64, now: u64) -> Outcome {
        let token = self.token(version, now);
        self.core.decide(&token, &reading(), None, now)
    }

    fn event(&mut self, cursor: i64, kind: &str, payload: serde_json::Value, now: u64) {
        let event = FeedEvent {
            cursor: Cursor::new(cursor),
            kind: kind.into(),
            payload,
        };
        self.core.on_feed_event(&event, now).unwrap();
    }
}

fn reading() -> Requirements {
    Requirements {
        tenant: BTreeSet::from(["workspace:read".to_owned()]),
        ..Requirements::default()
    }
}

fn allowed() -> Outcome {
    Outcome::Decided {
        decision: Decision::Allow,
    }
}

fn invalid() -> Outcome {
    Outcome::Decided {
        decision: Decision::Deny {
            reason: DenyReason::InvalidToken,
        },
    }
}

fn needs(outcome: &Outcome) -> Vec<Need> {
    match outcome {
        Outcome::Need { needs } => needs.clone(),
        Outcome::Decided { .. } => vec![],
    }
}

// r[verify relying.decision.local]
// r[verify relying.verify.offline]
#[test]
fn decides_locally_once_caches_are_warm() {
    let mut f = Fixture::new();
    let first = f.decide(1, T0);
    assert_eq!(
        needs(&first),
        vec![
            Need::Session { session: f.session },
            Need::Entitlements { key: f.key() }
        ]
    );
    f.warm(T0);
    assert_eq!(f.decide(1, T0), allowed());

    let mut forged = f.token(1, T0);
    forged.replace_range(forged.len() - 4.., "AAAA");
    assert_eq!(f.core.decide(&forged, &reading(), None, T0), invalid());
}

// r[verify relying.fallback.lag]
// r[verify relying.decision.fail-closed]
#[test]
fn falls_back_to_the_check_api_when_the_feed_lags() {
    let mut f = Fixture::new();
    f.warm(T0);
    let mut cold = Relying::new(config());
    assert_eq!(
        cold.decide(&f.token(1, T0), &reading(), None, T0),
        Outcome::Need {
            needs: vec![Need::Check]
        }
    );

    // Three missed heartbeats make the cache untrusted.
    assert_eq!(f.decide(1, T0 + 29_000), allowed());
    assert_eq!(needs(&f.decide(1, T0 + 30_000)), vec![Need::Check]);
    f.core.on_feed_activity(T0 + 30_500);
    assert_eq!(f.decide(1, T0 + 31_000), allowed());
    f.core.on_feed_lost();
    assert_eq!(needs(&f.decide(1, T0 + 31_000)), vec![Need::Check]);
}

// r[verify relying.verify.session]
// r[verify relying.cache.session-immediate]
#[test]
fn session_changes_apply_immediately() {
    let mut f = Fixture::new();
    f.warm(T0);
    let refreshed = json!({"session": f.session, "subject": f.subject, "version": 2, "revoked": false, "expires_at": T0 / 1000 + 86_400});
    f.event(10, "session.changed", refreshed, T0 + 1);
    assert_eq!(
        f.decide(1, T0 + 2),
        invalid(),
        "the old version is superseded at once"
    );
    assert_eq!(f.decide(2, T0 + 2), allowed());

    let revoked = json!({"session": f.session, "subject": f.subject, "version": 3, "revoked": true, "expires_at": T0 / 1000 + 86_400});
    f.event(11, "session.changed", revoked, T0 + 3);
    assert_eq!(f.decide(3, T0 + 4), invalid());
}

#[test]
fn tokens_newer_than_the_cache_trigger_a_session_fetch() {
    let mut f = Fixture::new();
    f.warm(T0);
    assert_eq!(
        needs(&f.decide(2, T0)),
        vec![Need::Session { session: f.session }]
    );
}

// r[verify relying.cache.debounce-bound]
// r[verify relying.cache.background-refresh]
#[test]
fn invalidated_entries_are_usable_only_within_the_debounce_window() {
    let mut f = Fixture::new();
    f.warm(T0);
    f.event(
        20,
        "entitlements.changed",
        json!({"subjects": [f.subject], "tenant": f.tenant}),
        T0 + 100,
    );
    assert_eq!(
        f.decide(1, T0 + 599),
        allowed(),
        "within 500 ms of the event"
    );
    assert_eq!(f.core.poll_work(T0 + 599).fetch, vec![], "debounced");
    assert_eq!(
        needs(&f.decide(1, T0 + 600)),
        vec![Need::Entitlements { key: f.key() }]
    );

    assert_eq!(
        f.core.poll_work(T0 + 600).fetch,
        vec![Need::Entitlements { key: f.key() }]
    );
    assert_eq!(
        f.core.poll_work(T0 + 601).fetch,
        vec![],
        "coalesced while in flight"
    );

    // A set compiled before the invalidation doesn't clear it.
    f.core
        .on_entitlements(f.set(&["workspace:read"], 19), T0 + 650);
    assert_eq!(
        needs(&f.decide(1, T0 + 651)),
        vec![Need::Entitlements { key: f.key() }]
    );
    f.core.on_entitlements(f.set(&[], 20), T0 + 700);
    assert_eq!(
        f.decide(1, T0 + 701),
        Outcome::Decided {
            decision: Decision::Deny {
                reason: DenyReason::MissingActions {
                    actions: BTreeSet::from(["workspace:read".to_owned()])
                }
            }
        }
    );
}

// r[verify relying.cache.ttl]
#[test]
fn entries_expire_after_the_ttl_and_busy_ones_refresh_first() {
    let mut f = Fixture::new();
    f.warm(T0);
    let ttl = 15 * 60 * 1000;
    // Keep the feed alive and the entry in use.
    f.core.on_feed_activity(T0 + ttl - 60_000);
    assert_eq!(f.decide(1, T0 + ttl - 60_000), allowed());
    assert_eq!(
        f.core.poll_work(T0 + ttl - 60_000).fetch,
        vec![Need::Entitlements { key: f.key() }]
    );
    f.core.on_fetch_failed(&Need::Entitlements { key: f.key() });
    f.core.on_feed_activity(T0 + ttl);
    assert_eq!(
        needs(&f.decide(1, T0 + ttl)),
        vec![Need::Entitlements { key: f.key() }]
    );
}

// r[verify relying.feed.reset]
#[test]
fn a_reset_forgets_sessions_and_marks_everything_stale() {
    let mut f = Fixture::new();
    f.warm(T0);
    f.event(30, "reset", json!({}), T0 + 10);
    let outcome = f.decide(1, T0 + 11);
    assert_eq!(needs(&outcome), vec![Need::Session { session: f.session }]);
    assert!(f.core.poll_work(T0 + 11).fetch.contains(&Need::Jwks));
    assert_eq!(f.core.feed_cursor(), Some(Cursor::new(30)));
}

// r[verify relying.verify.jwks-refresh]
#[test]
fn unknown_key_ids_refresh_jwks_at_most_so_often() {
    let mut f = Fixture::new();
    f.warm(T0);
    let stranger = Signer::new(SigningKey::from_bytes(&[3; 32]));
    let mut claims_token = f.token(1, T0);
    claims_token = {
        // Re-sign the same claims with an unknown key.
        let payload = claims_token.split('.').nth(1).unwrap();
        let claims: AccessClaims = serde_json::from_slice(&base64_decode(payload)).unwrap();
        stranger.sign(&claims)
    };
    assert_eq!(
        f.core.decide(&claims_token, &reading(), None, T0 + 1),
        invalid(),
        "JWKS fetched just now"
    );
    let later = T0 + 31_000;
    f.core.on_feed_activity(later);
    assert_eq!(
        needs(&f.core.decide(&claims_token, &reading(), None, later)),
        vec![Need::Jwks]
    );
    f.event(
        40,
        "signing_keys.changed",
        json!({"kids": [stranger.kid()]}),
        later,
    );
    assert!(f.core.poll_work(later).fetch.contains(&Need::Jwks));
}

fn base64_decode(input: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut bits = 0u32;
    let mut count = 0;
    let mut out = Vec::new();
    for byte in input.bytes() {
        let value = u32::try_from(ALPHABET.iter().position(|c| *c == byte).unwrap()).unwrap();
        bits = (bits << 6) | value;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push(u8::try_from((bits >> count) & 0xff).unwrap());
        }
    }
    out
}

// r[verify relying.cache.await-cursor]
#[test]
fn awaiting_a_cursor_forces_a_synchronous_refresh() {
    let mut f = Fixture::new();
    f.warm(T0);
    assert!(
        !f.core.await_cursor(Cursor::new(50)),
        "the feed hasn't reached it"
    );
    f.event(
        50,
        "entitlements.changed",
        json!({"subjects": [f.subject]}),
        T0 + 1,
    );
    assert!(
        !f.core.await_cursor(Cursor::new(50)),
        "the entry it invalidated is stale"
    );
    assert_eq!(
        needs(&f.decide(1, T0 + 2)),
        vec![Need::Entitlements { key: f.key() }],
        "no debounce grace"
    );
    assert_eq!(
        f.core.poll_work(T0 + 2).fetch,
        vec![Need::Entitlements { key: f.key() }],
        "due at once"
    );
    f.core
        .on_entitlements(f.set(&["workspace:read"], 50), T0 + 3);
    assert!(f.core.await_cursor(Cursor::new(50)));
}

// r[verify relying.cache.wildcard-sweep]
#[test]
fn wildcard_invalidations_sweep_in_batches() {
    let mut core = Relying::new(Config {
        sweep_batch: 2,
        ..config()
    });
    core.on_feed_connected(T0);
    for _ in 0..5 {
        let set = EntitlementSet {
            subject_id: SubjectId::new_v7(),
            tenant_id: None,
            revision: Cursor::new(1),
            entitlements: Entitlements::default(),
            restrictive_flags: BTreeSet::new(),
        };
        core.on_entitlements(set, T0);
    }
    let event = FeedEvent {
        cursor: Cursor::new(2),
        kind: "entitlements.changed".into(),
        payload: json!({"all": true}),
    };
    core.on_feed_event(&event, T0).unwrap();
    let entitlements = |work: &konklav_relying::Work| {
        work.fetch
            .iter()
            .filter(|n| matches!(n, Need::Entitlements { .. }))
            .count()
    };
    let first = core.poll_work(T0 + 500);
    assert_eq!(entitlements(&first), 2);
    assert_eq!(first.next_poll_at, T0 + 500, "more are due right away");
    assert_eq!(entitlements(&core.poll_work(T0 + 500)), 2);
    assert_eq!(entitlements(&core.poll_work(T0 + 500)), 1);
}

#[test]
fn tenant_narrowed_invalidations_leave_other_tenants_alone() {
    let mut f = Fixture::new();
    f.warm(T0);
    f.event(
        60,
        "entitlements.changed",
        json!({"all": true, "tenant": TenantId::new_v7()}),
        T0 + 1,
    );
    assert_eq!(f.decide(1, T0 + 10_000), allowed());
}

#[test]
fn malformed_known_events_are_errors() {
    let mut f = Fixture::new();
    let event = FeedEvent {
        cursor: Cursor::new(1),
        kind: "session.changed".into(),
        payload: json!({"nope": 1}),
    };
    assert!(f.core.on_feed_event(&event, T0).is_err());
    let unknown = FeedEvent {
        cursor: Cursor::new(2),
        kind: "delivery.requested".into(),
        payload: json!({}),
    };
    assert!(f.core.on_feed_event(&unknown, T0).is_ok());
}

#[test]
fn verifies_tokens_without_needing_entitlements() {
    use konklav_relying::Verification;
    let mut f = Fixture::new();
    f.core.on_session(f.session_state(1, false));
    let token = f.token(1, T0);
    match f.core.verify(&token, T0) {
        Verification::Verified { claims } => assert_eq!(claims.sid, f.session),
        other => panic!("expected verified, got {other:?}"),
    }
    assert_eq!(
        f.core.verify(&f.token(0, T0), T0),
        Verification::Invalid,
        "superseded"
    );
    let mut cold = Fixture::new();
    assert_eq!(
        cold.core.verify(&cold.token(1, T0), T0),
        Verification::Need {
            needs: vec![Need::Session {
                session: cold.session
            }]
        }
    );
}

#[test]
fn serves_cached_entitlement_sets() {
    let mut f = Fixture::new();
    assert_eq!(
        f.core.entitlements(f.key(), T0),
        Err(vec![Need::Entitlements { key: f.key() }])
    );
    f.warm(T0);
    let set = f.core.entitlements(f.key(), T0).unwrap();
    assert!(set.entitlements.tenant.contains("workspace:read"));
    f.core.on_feed_lost();
    assert_eq!(f.core.entitlements(f.key(), T0), Err(vec![Need::Check]));
}
