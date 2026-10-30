//! Following Konklav upstreams' peer feeds.
//!
//! For each identity provider with `peering`, the instance polls the
//! upstream's per-client feed. Each event names an upstream subject (or, for
//! catalog-wide changes, every subject). For the federated credentials of
//! those subjects here, the instance asks the upstream for the subject's
//! current claims. A subject the upstream disabled or no longer knows loses
//! its sessions and managed grants here; otherwise claim mapping is applied
//! to the fresh claims, as at a login.

use std::time::Duration;
use tracing::Instrument;

use diesel_async::AsyncConnection;
use konklav_store::credentials::{self, Credential, CredentialData, CredentialKind};
use konklav_store::sessions::{self, SessionFilter};
use konklav_store::{Connection, StoreError, peer_cursors};

use crate::AppState;
use crate::claim_mapping;
use crate::error::ApiError;
use crate::federation::{FederationError, Provider, federated_prefix};

#[derive(Debug, thiserror::Error)]
pub enum PeeringError {
    #[error(transparent)]
    Federation(#[from] FederationError),
    #[error("{0:?}")]
    Api(ApiError),
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<ApiError> for PeeringError {
    fn from(error: ApiError) -> Self {
        Self::Api(error)
    }
}

/// Applies everything new in `provider`'s peer feed. Returns how many
/// events were applied.
// r[impl federation.peer.feed]
pub async fn sync(state: &AppState, provider: &Provider) -> Result<usize, PeeringError> {
    let id = &provider.settings.id;
    let mut conn = state.pool.get().await.map_err(ApiError::from)?;
    let mut cursor = peer_cursors::get(&mut conn, id).await?;
    let mut applied = 0;
    loop {
        let page = provider.peer_events(cursor).await?;
        for event in &page.events {
            let affected = match &event.subject {
                Some(subject) => credentials::find_active(
                    &mut conn,
                    CredentialKind::Federated,
                    &credentials::federated_identifier(id, subject),
                )
                .await?
                .into_iter()
                .collect(),
                None => {
                    credentials::list_active_with_prefix(
                        &mut conn,
                        CredentialKind::Federated,
                        &federated_prefix(id),
                    )
                    .await?
                }
            };
            for credential in &affected {
                reconcile(&mut conn, provider, credential).await?;
            }
            applied += 1;
        }
        let progressed = page.next > cursor;
        cursor = page.next;
        peer_cursors::advance(&mut conn, id, cursor).await?;
        if !progressed {
            return Ok(applied);
        }
    }
}

async fn reconcile(
    conn: &mut Connection,
    provider: &Provider,
    credential: &Credential,
) -> Result<(), PeeringError> {
    let CredentialData::Federated(account) = &credential.data else {
        return Ok(());
    };
    let claims = provider.peer_subject(&account.subject).await?;
    let active = claims
        .as_ref()
        .is_some_and(|claims| claims["active"] == serde_json::Value::Bool(true));
    let desired = match (&claims, active) {
        (Some(claims), true) => claim_mapping::evaluate(&provider.settings.grants, claims),
        _ => claim_mapping::Desired::default(),
    };
    conn.transaction::<_, StoreError, _>(async |conn| {
        if !active {
            let filter = SessionFilter {
                credential: Some(credential.id),
                ..Default::default()
            };
            sessions::revoke(conn, &filter, None, "upstream_disabled").await?;
        }
        claim_mapping::apply(conn, &provider.settings.id, credential.subject_id, &desired).await
    })
    .await?;
    Ok(())
}

/// Runs [`sync`] for every peered provider, forever.
pub async fn sync_forever(state: AppState) {
    loop {
        for provider in state.auth.identity_providers.iter() {
            let span = tracing::info_span!("peer_sync", konklav.provider = %provider.settings.id);
            if provider.settings.peering
                && let Err(error) = sync(&state, provider).instrument(span).await
            {
                tracing::warn!(provider = %provider.settings.id, %error, "peering failed");
            }
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}
