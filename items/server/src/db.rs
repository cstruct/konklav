//! Where control-plane handlers get their database connection: from the
//! pool, or, for an operation in a batch, the batch's own connection, so
//! that every operation of the batch runs in its one transaction.

use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use axum::extract::{FromRef, FromRequestParts};
use axum::http::Extensions;
use axum::http::request::Parts;
use diesel_async::pooled_connection::deadpool::Object;
use konklav_store::{Connection, Pool};
use tokio::sync::{Mutex, OwnedMutexGuard};

use crate::AppState;
use crate::error::ApiError;

/// The connection a batch runs its operations on, put in each operation's
/// request extensions.
#[derive(Clone)]
pub(crate) struct Shared(pub(crate) Arc<Mutex<Object<Connection>>>);

/// A handler's source of database connections. Checking one out is
/// deferred to [`Db::get`], so a handler can validate and hash before it
/// holds a connection.
pub(crate) struct Db {
    pool: Pool,
    shared: Option<Shared>,
}

impl Db {
    pub(crate) fn new(state: &AppState, extensions: &Extensions) -> Self {
        Self {
            pool: state.pool.clone(),
            shared: extensions.get::<Shared>().cloned(),
        }
    }

    /// A pooled connection, or the batch's.
    pub(crate) async fn get(&self) -> Result<Conn, ApiError> {
        Ok(match &self.shared {
            Some(Shared(conn)) => Conn::Shared(conn.clone().lock_owned().await),
            None => Conn::Pooled(self.pool.get().await?),
        })
    }
}

impl<S> FromRequestParts<S> for Db
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Ok(Self::new(&AppState::from_ref(state), &parts.extensions)))
    }
}

/// A connection from [`Db::get`].
// Boxing the pooled one would cost an allocation per request to save a
// few hundred bytes of stack.
#[allow(clippy::large_enum_variant)]
pub(crate) enum Conn {
    Pooled(Object<Connection>),
    Shared(OwnedMutexGuard<Object<Connection>>),
}

impl Deref for Conn {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        match self {
            Self::Pooled(conn) => conn,
            Self::Shared(conn) => conn,
        }
    }
}

impl DerefMut for Conn {
    fn deref_mut(&mut self) -> &mut Connection {
        match self {
            Self::Pooled(conn) => conn,
            Self::Shared(conn) => conn,
        }
    }
}
