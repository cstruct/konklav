#![allow(clippy::too_many_lines)]

//! Route authority in the relying core: an accepted presentation's route
//! decision vouches for its request's later decisions, locally and through
//! the check API alike.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;
use konklav_authz::{
    Decision, DenyReason, EntitlementSet, Entitlements, Requirements, RouteAuthority, Scope,
    ScopeRequirement,
};
use konklav_core::feed::SessionChanged;
use konklav_core::{Cursor, SessionId, SubjectId, TenantId};
use konklav_relying::{
    Acceptance, Config, Outcome, PresentationId, Presented, Relying, ScopeRecord,
};
use konklav_token::{AccessClaims, Jwk, JwkSet, Signer, TokenKind};

const T0: u64 = 1_800_000_000_000;

fn seconds(now: u64) -> i64 {
    i64::try_from(now / 1000).unwrap()
}

fn set(actions: &[&str]) -> BTreeSet<String> {
    actions.iter().map(|&action| action.to_owned()).collect()
}

fn project(id: &str) -> Scope {
    Scope {
        kind: "project".into(),
        id: id.into(),
    }
}

struct Fixture {
    core: Relying,
    signer: Signer,
    subject: SubjectId,
    tenant: TenantId,
    session: SessionId,
}

impl Fixture {
    /// A member holding `user:manage_data` tenant-wide or at project p-1,
    /// which vouches for `user:write`, and `user:relay`, which vouches for
    /// `user:audit`; registered documents d-1 in p-1, d-2 in p-2, and
    /// d-x in another tenant.
    fn new(at_p1: bool) -> Self {
        let signer = Signer::new(SigningKey::from_bytes(&[9; 32]));
        let mut core = Relying::new(Config {
            issuer: "https://auth.example".into(),
            audiences: vec!["api".into()],
            ..Config::default()
        });
        core.on_feed_connected(T0);
        core.on_jwks(
            JwkSet {
                keys: vec![Jwk::from_verifying_key(&signer.verifying_key())],
            },
            T0,
        );
        let f = Self {
            core,
            signer,
            subject: SubjectId::new_v7(),
            tenant: TenantId::new_v7(),
            session: SessionId::new_v7(),
        };
        let mut f = f;
        f.core.on_session(SessionChanged {
            session: f.session,
            subject: f.subject,
            version: 1,
            revoked: false,
            expires_at: seconds(T0) + 86_400,
        });
        let mut entitlements = Entitlements {
            vouches: BTreeMap::from([
                (
                    "user:manage_data".to_owned(),
                    set(&["user:write", "user:relay"]),
                ),
                ("user:relay".to_owned(), set(&["user:audit"])),
            ]),
            ..Entitlements::default()
        };
        if at_p1 {
            entitlements
                .scoped
                .insert(project("p-1"), set(&["user:manage_data"]));
        } else {
            entitlements.tenant = set(&["user:manage_data", "user:read"]);
        }
        f.core.on_entitlements(
            EntitlementSet {
                subject_id: f.subject,
                tenant_id: Some(f.tenant),
                revision: Cursor::new(1),
                entitlements,
                restrictive_flags: BTreeSet::new(),
                registered_kinds: set(&["document"]),
                confinements: konklav_authz::Confinements::default(),
            },
            T0,
        );
        let other = TenantId::new_v7();
        for (id, tenant, container) in [
            ("d-1", f.tenant, "p-1"),
            ("d-2", f.tenant, "p-2"),
            ("d-x", other, "p-1"),
        ] {
            f.core.on_registered_scope(
                ScopeRecord {
                    kind: "document".into(),
                    id: id.into(),
                    tenant,
                    containers: vec![project(container)],
                    state: "active".into(),
                },
                T0,
            );
        }
        f
    }

    fn token(&self) -> String {
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
            cnf: None,
        })
    }

    fn accept(&mut self) -> PresentationId {
        let token = self.token();
        match self.core.accept_presented(&Presented::bearer(&token), T0) {
            Acceptance::Accepted { presentation, .. } | Acceptance::Check { presentation } => {
                presentation
            }
            other => panic!("not accepted: {other:?}"),
        }
    }

    fn decide(
        &mut self,
        presentation: PresentationId,
        requirements: &Requirements,
        route: bool,
    ) -> Decision {
        match self
            .core
            .decide_accepted(presentation, requirements, route, T0)
        {
            Outcome::Decided { decision } => decision,
            Outcome::Need { needs } => panic!("needs {needs:?}"),
        }
    }
}

fn tenant(actions: &[&str]) -> Requirements {
    Requirements {
        tenant: set(actions),
        ..Requirements::default()
    }
}

fn at(kind: &str, id: &str, actions: &[&str]) -> Requirements {
    Requirements {
        scopes: vec![ScopeRequirement {
            tenant: None,
            kind: kind.into(),
            id: id.into(),
            actions: set(actions),
        }],
        ..Requirements::default()
    }
}

fn missing(actions: &[&str]) -> Decision {
    Decision::Deny {
        reason: DenyReason::MissingActions {
            actions: set(actions),
        },
    }
}

fn invalid_token() -> Decision {
    Decision::Deny {
        reason: DenyReason::InvalidToken,
    }
}

/// The Goal's example: a route requiring `user:manage_data` lets its
/// handler's check for `user:write` pass, while a route requiring
/// `user:write` itself is still denied.
// r[verify relying.verify.route-authority]
#[test]
fn a_route_decision_vouches_for_its_requests_later_decisions() {
    let mut f = Fixture::new(false);
    let write = tenant(&["user:write"]);

    let direct = f.accept();
    assert_eq!(f.decide(direct, &write, true), missing(&["user:write"]));
    assert_eq!(
        f.decide(direct, &write, false),
        missing(&["user:write"]),
        "a denied route decision keeps nothing"
    );

    let request = f.accept();
    assert_eq!(
        f.decide(request, &write, false),
        missing(&["user:write"]),
        "before the route decision there is no route authority"
    );
    let route = f.decide(request, &tenant(&["user:manage_data"]), true);
    let Decision::Allow { vouches, .. } = &route else {
        panic!("the route decision allows: {route:?}");
    };
    assert_eq!(vouches.tenant, set(&["user:relay", "user:write"]));
    for _ in 0..2 {
        assert_eq!(
            f.decide(request, &write, false),
            Decision::allow(),
            "as often as the request needs, and vouching for nothing further"
        );
    }
    assert_eq!(
        f.decide(request, &at("document", "d-2", &["user:write"]), false),
        Decision::allow(),
        "tenant-wide route authority covers the tenant's registered scopes"
    );
    assert_eq!(
        f.decide(request, &at("document", "d-x", &["user:write"]), false),
        missing(&["user:write"]),
        "but never another tenant's scope"
    );
    assert_eq!(
        f.decide(request, &tenant(&["user:delete"]), false),
        missing(&["user:delete"]),
        "nor what it doesn't vouch for"
    );

    // Not transitive: `user:relay` is held only through route authority,
    // so its own vouch for `user:audit` counts for nothing, even when a
    // later decision requires it.
    assert_eq!(
        f.decide(request, &tenant(&["user:relay"]), false),
        Decision::allow()
    );
    assert_eq!(
        f.decide(request, &tenant(&["user:audit"]), false),
        missing(&["user:audit"])
    );

    // A later route decision replaces the route authority; a denied one
    // leaves none.
    assert_eq!(
        f.decide(request, &tenant(&["user:delete"]), true),
        missing(&["user:delete"])
    );
    assert_eq!(f.decide(request, &write, false), missing(&["user:write"]));
    assert!(matches!(
        f.decide(request, &tenant(&["user:read"]), true),
        Decision::Allow { .. }
    ));
    assert_eq!(
        f.decide(request, &write, false),
        missing(&["user:write"]),
        "an allow vouching for nothing replaces it with nothing"
    );

    // Route authority goes with the presentation.
    let released = f.accept();
    f.decide(released, &tenant(&["user:manage_data"]), true);
    assert_eq!(f.decide(released, &write, false), Decision::allow());
    f.core.release_accepted(released);
    assert_eq!(f.decide(released, &write, false), invalid_token());
    assert_eq!(f.core.route_authority(released, false, T0), None);
    let other = f.accept();
    assert_eq!(
        f.decide(other, &write, false),
        missing(&["user:write"]),
        "and no other presentation of the token has it"
    );
}

// r[verify relying.verify.route-authority]
// r[verify authz.decision.route-authority.coverage]
#[test]
fn a_scopes_route_authority_covers_the_registered_scopes_it_contains() {
    let mut f = Fixture::new(true);
    let request = f.accept();
    let route = f.decide(request, &at("project", "p-1", &["user:manage_data"]), true);
    assert!(matches!(route, Decision::Allow { .. }), "{route:?}");
    assert_eq!(
        f.decide(request, &at("document", "d-1", &["user:write"]), false),
        Decision::allow(),
        "d-1 is recorded in p-1"
    );
    assert_eq!(
        f.decide(request, &at("document", "d-2", &["user:write"]), false),
        missing(&["user:write"]),
        "d-2 is in p-2"
    );
    assert_eq!(
        f.decide(request, &at("document", "d-x", &["user:write"]), false),
        missing(&["user:write"]),
        "d-x names p-1 as its container but belongs to another tenant"
    );
    assert_eq!(
        f.decide(request, &tenant(&["user:write"]), false),
        missing(&["user:write"]),
        "a scope's route authority isn't tenant-wide"
    );
}

/// When the caches can't be trusted, the host asks the check API: with no
/// route authority for the route decision, whose allow it hands back to be
/// kept, and with the kept route authority for every other decision.
// r[verify relying.verify.route-authority]
// r[verify relying.fallback.equivalence]
#[test]
fn route_authority_goes_with_decisions_handed_to_the_check_api() {
    let mut f = Fixture::new(false);
    let request = f.accept();
    f.core.on_feed_lost();
    let write = tenant(&["user:write"]);
    let handed_off = |f: &mut Fixture, requirements: &Requirements, route: bool| {
        assert!(matches!(
            f.core.decide_accepted(request, requirements, route, T0),
            Outcome::Need { needs } if needs.contains(&konklav_relying::Need::Check)
        ));
    };

    handed_off(&mut f, &tenant(&["user:manage_data"]), true);
    assert_eq!(f.core.route_authority(request, true, T0), None);
    let vouches = RouteAuthority {
        tenant: set(&["user:write"]),
        ..RouteAuthority::default()
    };
    let checked = Decision::Allow {
        obligations: vec![],
        vouches: vouches.clone(),
    };
    assert_eq!(
        f.core.on_check_accepted(request, true, checked.clone(), T0),
        Outcome::Decided { decision: checked }
    );

    handed_off(&mut f, &write, false);
    assert_eq!(
        f.core.route_authority(request, false, T0),
        Some(vouches.clone()),
        "the check API's route decision is kept as a local one is"
    );
    assert_eq!(
        f.core
            .on_check_accepted(request, false, Decision::allow(), T0),
        Outcome::Decided {
            decision: Decision::allow()
        }
    );
    assert_eq!(
        f.core.route_authority(request, false, T0),
        Some(vouches),
        "a later decision changes nothing"
    );

    // Once trusted again, the kept route authority decides locally.
    f.core.on_feed_connected(T0);
    assert_eq!(f.decide(request, &write, false), Decision::allow());

    // A denied route decision from the check API leaves none.
    f.core.on_feed_lost();
    assert_eq!(
        f.core
            .on_check_accepted(request, true, missing(&["user:delete"]), T0),
        Outcome::Decided {
            decision: missing(&["user:delete"])
        }
    );
    assert_eq!(
        f.core.route_authority(request, false, T0),
        Some(RouteAuthority::default())
    );

    // A presentation released while the check API answered is denied.
    f.core.release_accepted(request);
    assert_eq!(
        f.core
            .on_check_accepted(request, false, Decision::allow(), T0),
        Outcome::Decided {
            decision: invalid_token()
        }
    );
}
