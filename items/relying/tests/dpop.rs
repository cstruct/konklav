//! Sender-constrained (DPoP) access tokens in the relying core.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;
use konklav_authz::{Decision, DenyReason, EntitlementSet, Entitlements, Requirements};
use konklav_core::feed::SessionChanged;
use konklav_core::{Cursor, SessionId, SubjectId, TenantId};
use konklav_relying::{
    Acceptance, Config, Need, Outcome, PresentationId, Presented, Relying, RequestDescriptor,
    Verification,
};
use konklav_test_support::DpopKey;
use konklav_token::{AccessClaims, Confirmation, Jwk, JwkSet, Signer, TokenKind};

const T0: u64 = 1_800_000_000_000;
const URL: &str = "https://api.example/projects/1";

fn seconds(now: u64) -> i64 {
    i64::try_from(now / 1000).unwrap()
}

struct Fixture {
    core: Relying,
    signer: Signer,
    key: DpopKey,
    subject: SubjectId,
    tenant: TenantId,
    session: SessionId,
}

fn config() -> Config {
    Config {
        issuer: "https://auth.example".into(),
        audiences: vec!["api".into()],
        ..Config::default()
    }
}

impl Fixture {
    fn new(config: Config) -> Self {
        let signer = Signer::new(SigningKey::from_bytes(&[9; 32]));
        let mut core = Relying::new(config);
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
            key: DpopKey::new(1),
            subject: SubjectId::new_v7(),
            tenant: TenantId::new_v7(),
            session: SessionId::new_v7(),
        }
    }

    fn token(&self, jkt: Option<String>) -> String {
        let now = seconds(T0);
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
            sv: 1,
            amr: vec!["pwd".into()],
            auth_time: now,
            tid: Some(self.tenant),
            mid: None,
            sfl: vec![],
            fct: BTreeMap::new(),
            act: None,
            cnf: jkt.map(|jkt| Confirmation { jkt }),
        })
    }

    fn bound(&self) -> String {
        self.token(Some(self.key.jkt()))
    }

    fn warm(&mut self) {
        self.core.on_session(SessionChanged {
            session: self.session,
            subject: self.subject,
            version: 1,
            revoked: false,
            expires_at: seconds(T0) + 86_400,
        });
        self.core.on_entitlements(
            EntitlementSet {
                subject_id: self.subject,
                tenant_id: Some(self.tenant),
                revision: Cursor::new(1),
                entitlements: Entitlements {
                    tenant: BTreeSet::from(["project:read".to_owned()]),
                    ..Entitlements::default()
                },
                restrictive_flags: BTreeSet::new(),
                registered_kinds: BTreeSet::new(),
                confinements: konklav_authz::Confinements::default(),
            },
            T0,
        );
    }

    fn proof(&self, token: &str, jti: &str) -> String {
        self.key.proof_at("GET", URL, Some(token), seconds(T0), jti)
    }

    fn decide(&mut self, presented: &Presented, now: u64) -> Outcome {
        self.core.decide_presented(presented, &reading(), now)
    }
}

fn dpop(token: &str, proof: Option<String>) -> Presented {
    Presented {
        authorization: format!("DPoP {token}"),
        dpop: proof,
        request: Some(RequestDescriptor {
            method: "GET".into(),
            url: URL.into(),
        }),
    }
}

fn reading() -> Requirements {
    Requirements {
        tenant: BTreeSet::from(["project:read".to_owned()]),
        ..Requirements::default()
    }
}

fn allowed() -> Outcome {
    Outcome::Decided {
        decision: Decision::allow(),
    }
}

fn denied(reason: DenyReason) -> Outcome {
    Outcome::Decided {
        decision: Decision::Deny { reason },
    }
}

// r[verify relying.verify.dpop]
// r[verify token.dpop.scheme]
// r[verify item.relying.raw-headers]
#[test]
fn sender_constrained_tokens_need_the_dpop_scheme_and_a_proof() {
    let mut f = Fixture::new(config());
    f.warm();
    let token = f.bound();
    let proof = f.proof(&token, "a");
    assert_eq!(f.decide(&dpop(&token, Some(proof)), T0), allowed());

    let refused = denied(DenyReason::InvalidDpopProof);
    // As a bearer token, through either API.
    assert_eq!(f.decide(&Presented::bearer(&token), T0), refused);
    assert_eq!(f.core.decide(&token, &reading(), None, T0), refused);
    // Without a proof, or without the request it must name.
    assert_eq!(f.decide(&dpop(&token, None), T0), refused);
    let no_request = Presented {
        request: None,
        ..dpop(&token, Some(f.proof(&token, "b")))
    };
    assert_eq!(f.decide(&no_request, T0), refused);
    // A proof for another request, or from another key.
    let elsewhere = f.key.proof_at("POST", URL, Some(&token), seconds(T0), "c");
    assert_eq!(f.decide(&dpop(&token, Some(elsewhere)), T0), refused);
    let other = DpopKey::new(2).proof_at("GET", URL, Some(&token), seconds(T0), "d");
    assert_eq!(f.decide(&dpop(&token, Some(other)), T0), refused);

    // A bearer token is refused under the DPoP scheme, and fine as Bearer.
    let bearer = f.token(None);
    let proof = f.proof(&bearer, "e");
    assert_eq!(f.decide(&dpop(&bearer, Some(proof)), T0), refused);
    assert_eq!(f.decide(&Presented::bearer(&bearer), T0), allowed());

    // Unknown schemes are plain invalid tokens.
    let basic = Presented {
        authorization: "Basic abc".into(),
        ..Presented::bearer("")
    };
    assert_eq!(f.decide(&basic, T0), denied(DenyReason::InvalidToken));
}

// r[verify relying.verify.dpop-challenge]
#[test]
fn verification_reports_proof_refusals_apart_from_invalid_tokens() {
    let mut f = Fixture::new(config());
    f.warm();
    let token = f.bound();
    assert_eq!(
        f.core.verify_presented(&dpop(&token, None), T0),
        Verification::InvalidProof
    );
    assert_eq!(f.core.verify(&token, T0), Verification::InvalidProof);
    let proof = f.proof(&token, "a");
    assert!(matches!(
        f.core.verify_presented(&dpop(&token, Some(proof)), T0),
        Verification::Verified { .. }
    ));
    assert_eq!(
        f.core.verify_presented(&Presented::bearer("garbage"), T0),
        Verification::Invalid
    );
}

// r[verify relying.verify.dpop-replay]
// r[verify token.dpop.replay]
#[test]
fn a_proof_is_accepted_once_but_survives_the_hosts_fetches() {
    let mut f = Fixture::new(config());
    let token = f.bound();
    let presented = dpop(&token, Some(f.proof(&token, "a")));
    // Cold caches: the host fetches and asks again with the same proof.
    assert!(matches!(f.decide(&presented, T0), Outcome::Need { .. }));
    f.warm();
    assert_eq!(f.decide(&presented, T0), allowed());
    // Answered once, the proof is a replay.
    assert_eq!(
        f.decide(&presented, T0),
        denied(DenyReason::InvalidDpopProof)
    );
}

// r[verify relying.verify.dpop-replay]
#[test]
fn a_full_replay_set_refuses_new_proofs_until_old_ones_expire() {
    let mut f = Fixture::new(Config {
        dpop_replay_capacity: 1,
        ..config()
    });
    f.warm();
    let token = f.bound();
    assert_eq!(
        f.decide(&dpop(&token, Some(f.proof(&token, "a"))), T0),
        allowed()
    );
    assert_eq!(
        f.decide(&dpop(&token, Some(f.proof(&token, "b"))), T0),
        denied(DenyReason::InvalidDpopProof)
    );
    // Once the first proof is too old to be replayed, its slot is free. The
    // feed must still be trusted then.
    let later = T0 + 95_000;
    f.core.on_feed_activity(later);
    let fresh = f
        .key
        .proof_at("GET", URL, Some(&token), seconds(later), "c");
    assert_eq!(f.decide(&dpop(&token, Some(fresh)), later), allowed());
}

// r[verify relying.verify.dpop-before-check]
#[test]
fn proofs_are_checked_before_the_check_api_and_count_as_answered() {
    let mut f = Fixture::new(config());
    f.core.on_feed_lost();
    let token = f.bound();
    assert_eq!(
        f.decide(&dpop(&token, None), T0),
        denied(DenyReason::InvalidDpopProof)
    );
    let presented = dpop(&token, Some(f.proof(&token, "a")));
    assert_eq!(
        f.decide(&presented, T0),
        Outcome::Need {
            needs: vec![Need::Check]
        }
    );
    // The host decided through the check API with this proof, so it's used.
    assert_eq!(
        f.decide(&presented, T0),
        denied(DenyReason::InvalidDpopProof)
    );
}

fn accepted(acceptance: Acceptance) -> PresentationId {
    match acceptance {
        Acceptance::Accepted { presentation, .. } => presentation,
        other => panic!("not accepted: {other:?}"),
    }
}

// r[verify relying.verify.accepted-presentation]
#[test]
fn an_accepted_presentation_answers_its_requests_decisions_without_its_proof_again() {
    let mut f = Fixture::new(config());
    f.warm();
    let token = f.bound();
    let presented = dpop(&token, Some(f.proof(&token, "a")));
    let acceptance = f.core.accept_presented(&presented, T0);
    let Acceptance::Accepted {
        claims,
        presentation,
    } = acceptance
    else {
        panic!("not accepted: {acceptance:?}");
    };
    assert_eq!(claims.sid, f.session);
    // The proof was spent on accepting.
    assert_eq!(
        f.decide(&presented, T0),
        denied(DenyReason::InvalidDpopProof)
    );
    // Every decision of the request, until it is released.
    for _ in 0..3 {
        assert_eq!(
            f.core.decide_accepted(presentation, &reading(), false, T0),
            allowed()
        );
    }
    f.core.release_accepted(presentation);
    assert_eq!(
        f.core.decide_accepted(presentation, &reading(), false, T0),
        denied(DenyReason::InvalidToken)
    );
    // Another core doesn't take it for its own, even while holding one.
    let mut other = Fixture::new(config());
    other.warm();
    let own = other.token(None);
    let held = accepted(other.core.accept_presented(&Presented::bearer(&own), T0));
    assert_eq!(
        other
            .core
            .decide_accepted(presentation, &reading(), false, T0),
        denied(DenyReason::InvalidToken)
    );
    assert_eq!(
        other.core.decide_accepted(held, &reading(), false, T0),
        allowed()
    );
}

// r[verify relying.verify.accepted-presentation]
#[test]
fn an_accepted_presentation_still_checks_the_session_and_expires_with_its_proof() {
    let mut f = Fixture::new(config());
    f.warm();
    let token = f.bound();
    let revoked = accepted(
        f.core
            .accept_presented(&dpop(&token, Some(f.proof(&token, "a"))), T0),
    );
    let stale = accepted(
        f.core
            .accept_presented(&dpop(&token, Some(f.proof(&token, "b"))), T0),
    );
    // A proof dated T0 is fresh for 60 seconds plus 30 seconds of leeway.
    let later = T0 + 91_000;
    f.core.on_feed_activity(later);
    assert_eq!(
        f.core.decide_accepted(stale, &reading(), false, later),
        denied(DenyReason::InvalidToken)
    );
    f.core.on_session(SessionChanged {
        session: f.session,
        subject: f.subject,
        version: 2,
        revoked: true,
        expires_at: seconds(T0) + 86_400,
    });
    assert_eq!(
        f.core.decide_accepted(revoked, &reading(), false, T0),
        denied(DenyReason::InvalidToken)
    );
}

// r[verify relying.verify.accepted-presentation]
#[test]
fn accepting_waits_for_fetches_and_hands_bearer_tokens_and_the_check_api_a_presentation() {
    let mut f = Fixture::new(config());
    let token = f.bound();
    let presented = dpop(&token, Some(f.proof(&token, "a")));
    // The session isn't known yet: not answered, so the proof isn't spent.
    assert!(matches!(
        f.core.accept_presented(&presented, T0),
        Acceptance::Need { .. }
    ));
    f.warm();
    accepted(f.core.accept_presented(&presented, T0));

    let bearer = f.token(None);
    let presentation = accepted(f.core.accept_presented(&Presented::bearer(&bearer), T0));
    assert_eq!(
        f.core.decide_accepted(presentation, &reading(), false, T0),
        allowed()
    );

    // Without a trusted cache the check API decides, each time it is asked,
    // until the presentation is released.
    f.core.on_feed_lost();
    let Acceptance::Check { presentation } = f
        .core
        .accept_presented(&dpop(&token, Some(f.proof(&token, "b"))), T0)
    else {
        panic!("not handed to the check API");
    };
    for _ in 0..2 {
        assert_eq!(
            f.core.decide_accepted(presentation, &reading(), false, T0),
            Outcome::Need {
                needs: vec![Need::Check]
            }
        );
    }
    f.core.release_accepted(presentation);
    assert_eq!(
        f.core.decide_accepted(presentation, &reading(), false, T0),
        denied(DenyReason::InvalidToken)
    );
}
