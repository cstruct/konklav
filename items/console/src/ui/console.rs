//! The console's shared state: the operator and how calls reach Konklav.

use futures_util::FutureExt;
use futures_util::future::{LocalBoxFuture, Shared};
use leptos::prelude::*;
use leptos::task::spawn_local;
use serde::de::DeserializeOwned;

use crate::api::types::{OwnCapabilities, TokenResponse};
use crate::api::{self, ApiError, Request, endpoints};
use crate::grants::{Capability, Grants};
use crate::operator::{Operator, Retry, after_rejection};

/// Whether the console knows who the operator is yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Trying the refresh cookie from an earlier visit.
    Restoring,
    Ready,
}

type Refreshing = Shared<LocalBoxFuture<'static, bool>>;

#[derive(Clone, Copy)]
pub struct Console {
    pub operator: RwSignal<Option<Operator>>,
    pub phase: RwSignal<Phase>,
    /// Changes only when the operator's capabilities do, not on every
    /// refreshed token, so gated views keep their state.
    grants: Memo<Grants>,
    signed_in: Memo<bool>,
    /// The refresh in flight, shared by every request that needs it.
    refreshing: StoredValue<Option<Refreshing>, LocalStorage>,
}

pub fn use_console() -> Console {
    expect_context::<Console>()
}

/// Sends `request` with `token` and decodes the answer.
pub async fn send<T: DeserializeOwned>(
    request: &Request,
    token: Option<&str>,
) -> Result<T, ApiError> {
    let (status, body) = api::send(request, token).await?;
    api::decode(status, &body)
}

impl Console {
    pub fn new() -> Self {
        let operator = RwSignal::new(None::<Operator>);
        Self {
            operator,
            phase: RwSignal::new(Phase::Restoring),
            grants: Memo::new(move |_| {
                operator
                    .with(|operator| operator.as_ref().map(|o| o.grants.clone()))
                    .unwrap_or_default()
            }),
            signed_in: Memo::new(move |_| operator.with(Option::is_some)),
            refreshing: StoredValue::new_local(None),
        }
    }

    pub fn grants(self) -> Grants {
        self.grants.get()
    }

    pub fn allows(self, capability: Capability) -> bool {
        self.grants.with(|grants| grants.allows(capability))
    }

    pub fn signed_in(self) -> bool {
        self.signed_in.get()
    }

    /// The operator's own subject, unless they used the bootstrap token.
    pub fn subject(self) -> Option<String> {
        self.operator.with(|operator| {
            operator
                .as_ref()
                .and_then(|o| o.subject().map(str::to_owned))
        })
    }

    fn token(self) -> Option<String> {
        self.operator
            .with_untracked(|operator| operator.as_ref().map(|o| o.token.clone()))
    }

    /// Calls Konklav as the operator. A rejected access token is refreshed
    /// once; if that fails the operator is signed out.
    pub async fn call<T: DeserializeOwned>(self, request: Request) -> Result<T, ApiError> {
        let used = self.token();
        let error = match send(&request, used.as_deref()).await {
            Err(error) if error.ends_session() && request.authenticated => error,
            other => return other,
        };
        let now = self.operator.get_untracked();
        match after_rejection(used.as_deref(), now.as_ref()) {
            Retry::WithCurrent => send(&request, self.token().as_deref()).await,
            Retry::Refresh if self.refresh().await => send(&request, self.token().as_deref()).await,
            Retry::Refresh | Retry::SignIn => {
                self.operator.set(None);
                Err(error)
            }
        }
    }

    /// Calls Konklav in the background, reporting failure in `error` and
    /// handing success to `done`.
    pub fn act<T: DeserializeOwned + 'static>(
        self,
        request: Request,
        error: RwSignal<Option<ApiError>>,
        done: impl FnOnce(T) + 'static,
    ) {
        error.set(None);
        spawn_local(async move {
            match self.call::<T>(request).await {
                Ok(value) => done(value),
                Err(failure) => error.set(Some(failure)),
            }
        });
    }

    /// Exchanges the refresh cookie for a new access token, at most once at
    /// a time: refresh tokens rotate, and presenting a rotated one ends the
    /// session.
    pub async fn refresh(self) -> bool {
        let pending = self.refreshing.get_value();
        let refreshing = if let Some(pending) = pending {
            pending
        } else {
            let fresh = async move {
                let token = send::<TokenResponse>(&endpoints::refresh(), None).await;
                if let Ok(token) = &token {
                    self.operator.update(|operator| {
                        if let Some(operator) = operator {
                            operator.token.clone_from(&token.access_token);
                        }
                    });
                }
                self.refreshing.set_value(None);
                token.is_ok()
            }
            .boxed_local()
            .shared();
            self.refreshing.set_value(Some(fresh.clone()));
            fresh
        };
        refreshing.await
    }

    /// Signs in with a full (non-partial) access token, looking up what the
    /// operator may do.
    pub async fn complete_sign_in(self, token: TokenResponse) -> Result<(), ApiError> {
        let capabilities: OwnCapabilities =
            send(&endpoints::own_capabilities(), Some(&token.access_token)).await?;
        self.operator
            .set(Some(Operator::signed_in(&token, capabilities)));
        Ok(())
    }

    /// Picks up the session of an earlier visit from the refresh cookie.
    pub fn restore(self) {
        spawn_local(async move {
            if let Ok(token) = send::<TokenResponse>(&endpoints::refresh(), None).await {
                let _ = self.complete_sign_in(token).await;
            }
            self.phase.set(Phase::Ready);
        });
    }

    /// Ends the operator's session. Bootstrap sign-ins are just forgotten.
    pub fn sign_out(self) {
        let operator = self.operator.get_untracked();
        self.operator.set(None);
        if let Some(operator) = operator.filter(Operator::can_refresh) {
            spawn_local(async move {
                let _ =
                    send::<serde_json::Value>(&endpoints::sign_out(), Some(&operator.token)).await;
            });
        }
    }
}
