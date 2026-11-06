//! How a request presents its access token: the authorization scheme, a
//! DPoP proof, and the request it must name. The core reads the raw header
//! values itself, so host bindings never parse schemes or proofs
//! (`r[item.relying.raw-headers]`).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use konklav_token::{Proof, ProofRequest};
use serde::{Deserialize, Serialize};

use crate::RequestDescriptor;

/// The parts of a request that carry its access token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Presented {
    /// The `Authorization` header value, such as `Bearer <token>` or
    /// `DPoP <token>`.
    pub authorization: String,
    /// The `DPoP` header value, if the request had one.
    #[serde(default)]
    pub dpop: Option<String>,
    /// The method and the URL the client addressed: behind a reverse proxy,
    /// the public URL, not the upstream one.
    #[serde(default)]
    pub request: Option<RequestDescriptor>,
}

impl Presented {
    /// The access token, whatever its scheme: what a host sends to the
    /// check API after [`crate::Need::Check`].
    #[must_use]
    pub fn access_token(&self) -> Option<&str> {
        self.authorization
            .split_once(' ')
            .map(|(_, token)| token.trim())
    }

    /// A bearer token, as the token-string methods take it.
    #[must_use]
    pub fn bearer(token: &str) -> Self {
        Self {
            authorization: format!("Bearer {token}"),
            dpop: None,
            request: None,
        }
    }
}

/// A presentation refused before the token itself is checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    /// No usable `Authorization` header.
    Token,
    /// Refused for the DPoP proof or the authorization scheme.
    Proof,
}

/// A proof that verified, to remember once the core has answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Accepted {
    key: (String, String),
    /// Milliseconds; the proof can't pass the freshness check after this.
    until: u64,
}

/// What a DPoP check is made with.
pub(crate) struct ProofSettings {
    pub max_age_seconds: i64,
    pub leeway_seconds: i64,
}

/// Finds the access token in `presented` and checks the scheme and any
/// DPoP proof against the token's (unverified) `cnf`. The token's signature
/// is checked afterwards, locally or by the check API, so a forged `cnf`
/// still fails (`r[relying.verify.dpop-before-check]`).
// r[impl relying.verify.dpop]
// r[impl token.dpop.scheme]
// r[impl item.relying.raw-headers]
pub(crate) fn token<'a>(
    presented: &'a Presented,
    replays: &Replays,
    settings: &ProofSettings,
    now: u64,
) -> Result<(&'a str, Option<Accepted>), Refused> {
    let (scheme, token) = presented
        .authorization
        .split_once(' ')
        .ok_or(Refused::Token)?;
    let token = token.trim();
    let claims = konklav_token::decode_claims_unverified(token);
    let jkt = claims
        .as_ref()
        .and_then(|c| c.cnf.as_ref())
        .map(|c| c.jkt.as_str());
    if scheme.eq_ignore_ascii_case("Bearer") {
        // A sender-constrained token is useless without its proof.
        return match jkt {
            Some(_) => Err(Refused::Proof),
            None => Ok((token, None)),
        };
    }
    if !scheme.eq_ignore_ascii_case("DPoP") {
        return Err(Refused::Token);
    }
    let (Some(jkt), Some(proof), Some(request)) =
        (jkt, presented.dpop.as_deref(), presented.request.as_ref())
    else {
        return Err(Refused::Proof);
    };
    let now_seconds = i64::try_from(now / 1000).unwrap_or(i64::MAX);
    let checked = ProofRequest {
        method: &request.method,
        url: &request.url,
        access_token: Some(token),
        bound_to: Some(jkt),
        now: now_seconds,
        max_age: settings.max_age_seconds,
        leeway: settings.leeway_seconds,
    };
    let proof = konklav_token::verify_proof(proof, &checked).map_err(|_| Refused::Proof)?;
    let accepted = Accepted::of(&proof, settings);
    if replays.seen(&accepted) {
        return Err(Refused::Proof);
    }
    Ok((token, Some(accepted)))
}

impl Accepted {
    /// Milliseconds; when the proof can no longer pass the freshness check.
    pub(crate) fn until(&self) -> u64 {
        self.until
    }

    fn of(proof: &Proof, settings: &ProofSettings) -> Self {
        let until = proof
            .replayable_until(settings.max_age_seconds)
            .saturating_add(settings.leeway_seconds);
        Self {
            key: (proof.jkt.clone(), proof.jti.clone()),
            until: u64::try_from(until).unwrap_or(0).saturating_mul(1000),
        }
    }
}

/// The `(jkt, jti)` of proofs this core accepted, until they could no
/// longer pass the freshness check. Bounded: when full of live entries it
/// refuses new proofs rather than forgetting old ones.
// r[impl relying.verify.dpop-replay]
#[derive(Clone, Debug, Default)]
pub(crate) struct Replays {
    seen: BTreeMap<(String, String), u64>,
}

impl Replays {
    fn seen(&self, accepted: &Accepted) -> bool {
        self.seen.contains_key(&accepted.key)
    }

    /// Remembers `accepted`. Returns false if there is no room for it.
    pub(crate) fn remember(&mut self, accepted: Accepted, capacity: usize, now: u64) -> bool {
        if self.seen.len() >= capacity {
            self.seen.retain(|_, until| *until > now);
        }
        if self.seen.len() >= capacity {
            return false;
        }
        self.seen.insert(accepted.key, accepted.until);
        true
    }
}

/// Identifies a presentation the core accepted, for one decision with
/// [`crate::Relying::decide_accepted`]. It names the core that issued it, so
/// no other core in the process takes it for one of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PresentationId {
    core: u64,
    seq: u64,
}

/// Numbers each core's held presentations apart from every other core's.
static CORES: AtomicU64 = AtomicU64::new(1);

/// Presentations accepted for a decision, until they are answered or
/// their proof could no longer pass the freshness check. Bounded like
/// [`Replays`]: when full of live entries it holds no more.
// r[impl relying.verify.accepted-presentation]
#[derive(Clone, Debug)]
pub(crate) struct Held {
    core: u64,
    next: u64,
    tokens: BTreeMap<u64, (String, u64)>,
}

impl Default for Held {
    fn default() -> Self {
        Self {
            core: CORES.fetch_add(1, Ordering::Relaxed),
            next: 0,
            tokens: BTreeMap::new(),
        }
    }
}

impl Held {
    /// Holds `token` until `until`. Returns `None` if there is no room.
    pub(crate) fn hold(
        &mut self,
        token: &str,
        until: u64,
        capacity: usize,
        now: u64,
    ) -> Option<PresentationId> {
        if self.tokens.len() >= capacity {
            self.tokens.retain(|_, (_, held_until)| *held_until > now);
        }
        if self.tokens.len() >= capacity {
            return None;
        }
        self.next += 1;
        self.tokens.insert(self.next, (token.to_owned(), until));
        Some(PresentationId {
            core: self.core,
            seq: self.next,
        })
    }

    /// The token of a live presentation this core holds.
    pub(crate) fn token(&self, id: PresentationId, now: u64) -> Option<String> {
        if id.core != self.core {
            return None;
        }
        self.tokens
            .get(&id.seq)
            .filter(|(_, until)| *until > now)
            .map(|(token, _)| token.clone())
    }

    pub(crate) fn release(&mut self, id: PresentationId) {
        if id.core == self.core {
            self.tokens.remove(&id.seq);
        }
    }
}
