//! How this crate reaches the relying SDK: [`RelyingHost`], implemented for
//! [`RelyingClient`].

use std::any::Any;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use konklav_authz::{Decision, Requirements};
use konklav_relying_client::{AcceptedRequest, Error, Presented, RelyingClient, Verified};
use konklav_token::AccessClaims;

/// A boxed, sendable future, as [`RelyingHost`] returns them.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A presentation the relying host accepted: the verified claims, and the
/// host's own handle for deciding the request's requirements.
pub struct Accepted {
    claims: AccessClaims,
    handle: Box<dyn Any + Send + Sync>,
}

impl Accepted {
    /// `claims` verified, with the host's `handle` for
    /// [`RelyingHost::decide_accepted`].
    pub fn new(claims: AccessClaims, handle: impl Any + Send + Sync) -> Self {
        Self {
            claims,
            handle: Box::new(handle),
        }
    }

    /// The verified token's claims.
    #[must_use]
    pub fn claims(&self) -> &AccessClaims {
        &self.claims
    }

    /// The host's handle, if it is a `T`.
    #[must_use]
    pub fn handle<T: Any>(&self) -> Option<&T> {
        self.handle.downcast_ref()
    }
}

impl fmt::Debug for Accepted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Accepted")
            .field("claims", &self.claims)
            .finish_non_exhaustive()
    }
}

/// The relying SDK as route policies use it. Every method fails closed: an
/// error means deny.
// r[impl item.axum.relying-host]
pub trait RelyingHost: Send + Sync + 'static {
    /// Verifies a request's token, its session and any DPoP proof, once
    /// (`relying.verify.accepted-presentation`).
    fn accept_request<'a>(
        &'a self,
        presented: &'a Presented,
    ) -> BoxFuture<'a, Result<Verified<Accepted>, Error>>;

    /// Decides `requirements` for an accepted presentation, without checking
    /// its proof again.
    fn decide_accepted<'a>(
        &'a self,
        accepted: &'a Accepted,
        requirements: &'a Requirements,
    ) -> BoxFuture<'a, Result<Decision, Error>>;

    /// Verifies a request's token, its session and any DPoP proof, without
    /// a decision.
    fn verify_request<'a>(
        &'a self,
        presented: &'a Presented,
    ) -> BoxFuture<'a, Result<Verified<AccessClaims>, Error>>;

    /// Releases an accepted presentation once its request is answered, so
    /// it decides nothing more. A host that holds nothing per presentation
    /// needn't.
    fn release_accepted(&self, accepted: &Accepted) {
        let _ = accepted;
    }
}

impl RelyingHost for RelyingClient {
    fn accept_request<'a>(
        &'a self,
        presented: &'a Presented,
    ) -> BoxFuture<'a, Result<Verified<Accepted>, Error>> {
        Box::pin(async move {
            Ok(
                match RelyingClient::accept_request(self, presented).await? {
                    Verified::Valid(accepted) => {
                        Verified::Valid(Accepted::new(accepted.claims().clone(), accepted))
                    }
                    Verified::Invalid => Verified::Invalid,
                    Verified::InvalidProof => Verified::InvalidProof,
                },
            )
        })
    }

    fn decide_accepted<'a>(
        &'a self,
        accepted: &'a Accepted,
        requirements: &'a Requirements,
    ) -> BoxFuture<'a, Result<Decision, Error>> {
        Box::pin(async move {
            let Some(accepted) = accepted.handle::<AcceptedRequest>() else {
                // Not accepted by this client: never decide for it.
                return Err(Error::Exhausted);
            };
            RelyingClient::decide_accepted(self, accepted, requirements).await
        })
    }

    fn verify_request<'a>(
        &'a self,
        presented: &'a Presented,
    ) -> BoxFuture<'a, Result<Verified<AccessClaims>, Error>> {
        Box::pin(RelyingClient::verify_request(self, presented))
    }

    fn release_accepted(&self, accepted: &Accepted) {
        if let Some(accepted) = accepted.handle::<AcceptedRequest>() {
            RelyingClient::release_accepted(self, accepted);
        }
    }
}

impl<T: RelyingHost + ?Sized> RelyingHost for Arc<T> {
    fn accept_request<'a>(
        &'a self,
        presented: &'a Presented,
    ) -> BoxFuture<'a, Result<Verified<Accepted>, Error>> {
        (**self).accept_request(presented)
    }

    fn decide_accepted<'a>(
        &'a self,
        accepted: &'a Accepted,
        requirements: &'a Requirements,
    ) -> BoxFuture<'a, Result<Decision, Error>> {
        (**self).decide_accepted(accepted, requirements)
    }

    fn verify_request<'a>(
        &'a self,
        presented: &'a Presented,
    ) -> BoxFuture<'a, Result<Verified<AccessClaims>, Error>> {
        (**self).verify_request(presented)
    }

    fn release_accepted(&self, accepted: &Accepted) {
        (**self).release_accepted(accepted);
    }
}
