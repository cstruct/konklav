//! [`Konklav`]: what evaluating route policies needs from the application.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;

use axum::Extension;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use konklav_core::TenantId;
use konklav_relying::policy::ResolvedScope;
use konklav_token::AccessClaims;

use crate::client_address::{InvalidProxy, Network};
use crate::host::{BoxFuture, RelyingHost};
use crate::{Denied, RoutePolicyError};

pub(crate) type ScopeResolver = Arc<
    dyn Fn(&Parts, &AccessClaims) -> BoxFuture<'static, Result<ResolvedScope, Response>>
        + Send
        + Sync,
>;
pub(crate) type RouteTenant = Arc<
    dyn Fn(&Parts, &AccessClaims) -> BoxFuture<'static, Result<Option<TenantId>, Response>>
        + Send
        + Sync,
>;
pub(crate) type TokenHook =
    Arc<dyn Fn(&Parts, &AccessClaims) -> BoxFuture<'static, Result<(), Response>> + Send + Sync>;
type Cookie = Arc<dyn Fn(&Parts) -> Option<String> + Send + Sync>;
type PublicUrl = Arc<dyn Fn(&Parts) -> String + Send + Sync>;
type Respond = Arc<dyn Fn(Denied) -> Response + Send + Sync>;

pub(crate) struct Inner {
    pub(crate) host: Arc<dyn RelyingHost>,
    pub(crate) scope_resolvers: BTreeMap<String, ScopeResolver>,
    pub(crate) route_tenant: Option<RouteTenant>,
    pub(crate) hooks: Vec<TokenHook>,
    pub(crate) cookie: Option<Cookie>,
    pub(crate) public_url: Option<PublicUrl>,
    pub(crate) trusted_proxies: Vec<Network>,
    respond: Option<Respond>,
}

/// What evaluating route policies needs from the application. Cheap to
/// clone. Install it once on the application's router with
/// [`Konklav::layer`]:
///
/// ```no_run
/// # fn example(client: konklav_relying_client::RelyingClient, app: axum::Router) -> Result<(), Box<dyn std::error::Error>> {
/// use konklav_axum::Konklav;
///
/// let konklav = Konklav::builder(client).trusted_proxies(["10.0.0.0/8"]).build()?;
/// let app = app.layer(konklav.layer());
/// # Ok(())
/// # }
/// ```
// r[impl item.axum.configuration]
#[derive(Clone)]
pub struct Konklav {
    pub(crate) inner: Arc<Inner>,
}

impl Konklav {
    /// A configuration deciding through `host`, such as a started
    /// [`RelyingClient`](konklav_relying_client::RelyingClient).
    pub fn builder(host: impl RelyingHost) -> KonklavBuilder {
        KonklavBuilder {
            inner: Inner {
                host: Arc::new(host),
                scope_resolvers: BTreeMap::new(),
                route_tenant: None,
                hooks: Vec::new(),
                cookie: None,
                public_url: None,
                trusted_proxies: Vec::new(),
                respond: None,
            },
            proxies: Vec::new(),
        }
    }

    /// The layer that installs this configuration on a router, as a
    /// request extension. Apply it with `Router::layer`, around every
    /// route.
    pub fn layer(&self) -> Extension<Self> {
        Extension(self.clone())
    }

    /// The configuration installed on the router serving `parts`.
    pub fn of(parts: &Parts) -> Result<Self, RoutePolicyError> {
        parts
            .extensions
            .get::<Self>()
            .cloned()
            .ok_or(RoutePolicyError::NotInstalled)
    }

    /// The relying host route policies decide through.
    #[must_use]
    pub fn host(&self) -> &dyn RelyingHost {
        &*self.inner.host
    }

    /// The answer for `denied`: the application's
    /// ([`KonklavBuilder::respond_with`]), or `denied`'s own.
    #[must_use]
    pub fn respond(&self, denied: Denied) -> Response {
        match &self.inner.respond {
            Some(respond) => respond(denied),
            None => denied.into_response(),
        }
    }
}

/// Builds a [`Konklav`].
pub struct KonklavBuilder {
    inner: Inner,
    proxies: Vec<String>,
}

impl KonklavBuilder {
    /// Resolves the scope of `kind` for a request, given its verified
    /// token. A kind without a resolver takes the path parameter of its
    /// name. Read path parameters with [`path_param`](crate::path_param).
    #[must_use]
    pub fn scope_resolver<F, Fut>(mut self, kind: impl Into<String>, resolve: F) -> Self
    where
        F: Fn(&Parts, &AccessClaims) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<ResolvedScope, Response>> + Send + 'static,
    {
        let resolve: ScopeResolver = Arc::new(move |parts, token| Box::pin(resolve(parts, token)));
        self.inner.scope_resolvers.insert(kind.into(), resolve);
        self
    }

    /// Finds the tenant a request addresses on its own, such as from its
    /// path: a route tenant that isn't the token's `tid` is denied before
    /// deciding.
    #[must_use]
    pub fn route_tenant<F, Fut>(mut self, resolve: F) -> Self
    where
        F: Fn(&Parts, &AccessClaims) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Option<TenantId>, Response>> + Send + 'static,
    {
        self.inner.route_tenant = Some(Arc::new(move |parts, token| {
            Box::pin(resolve(parts, token))
        }));
        self
    }

    /// Runs `hook` on every verified token, after any added before, before
    /// handlers receive it. It refuses the token by returning a response.
    #[must_use]
    pub fn on_verified<F, Fut>(mut self, hook: F) -> Self
    where
        F: Fn(&Parts, &AccessClaims) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), Response>> + Send + 'static,
    {
        self.inner
            .hooks
            .push(Arc::new(move |parts, token| Box::pin(hook(parts, token))));
        self
    }

    /// Reads the token from a cookie, for requests without an
    /// `Authorization` header.
    #[must_use]
    pub fn cookie(
        mut self,
        read: impl Fn(&Parts) -> Option<String> + Send + Sync + 'static,
    ) -> Self {
        self.inner.cookie = Some(Arc::new(read));
        self
    }

    /// The URL the client addressed, behind a proxy: DPoP proofs are checked
    /// against it. Without it, the request's own scheme and authority, or
    /// `http://` and its `Host` header.
    #[must_use]
    pub fn public_url(mut self, url: impl Fn(&Parts) -> String + Send + Sync + 'static) -> Self {
        self.inner.public_url = Some(Arc::new(url));
        self
    }

    /// Proxies' addresses or networks, such as `10.0.0.0/8`: behind one,
    /// the client's address comes from `X-Forwarded-For`
    /// ([`Konklav::client_address`]).
    #[must_use]
    pub fn trusted_proxies<I: IntoIterator<Item = S>, S: Into<String>>(
        mut self,
        proxies: I,
    ) -> Self {
        self.proxies.extend(proxies.into_iter().map(Into::into));
        self
    }

    /// Answers every [`Denied`] with `respond` instead of its default
    /// answer.
    #[must_use]
    pub fn respond_with(
        mut self,
        respond: impl Fn(Denied) -> Response + Send + Sync + 'static,
    ) -> Self {
        self.inner.respond = Some(Arc::new(respond));
        self
    }

    /// The configuration, or the first trusted proxy that doesn't parse.
    pub fn build(mut self) -> Result<Konklav, InvalidProxy> {
        self.inner.trusted_proxies = self
            .proxies
            .iter()
            .map(|proxy| Network::parse(proxy))
            .collect::<Result<_, _>>()?;
        Ok(Konklav {
            inner: Arc::new(self.inner),
        })
    }
}
