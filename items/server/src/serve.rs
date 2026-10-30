//! Binding listeners and running the server until shutdown.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;

use crate::AppState;
use crate::config::{Listen, ListenConfig};
use crate::error::{ApiError, ErrorCode};
use crate::surface::{self, Surface};
use crate::telemetry::metrics;

/// Bounds on what each listener accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub request_timeout: Duration,
    pub max_body_bytes: usize,
    pub max_concurrent_requests: usize,
}

impl Limits {
    pub const DEFAULT: Self = Self {
        request_timeout: Duration::from_secs(30),
        max_body_bytes: 2_097_152,
        max_concurrent_requests: 1024,
    };

    #[must_use]
    pub fn from_config(config: &ListenConfig) -> Self {
        config.limits.as_ref().map_or(Self::DEFAULT, |limits| Self {
            request_timeout: Duration::from_secs(u64::from(limits.request_timeout_seconds)),
            max_body_bytes: usize::try_from(limits.max_body_bytes).unwrap_or(usize::MAX),
            max_concurrent_requests: usize::try_from(limits.max_concurrent_requests)
                .unwrap_or(usize::MAX),
        })
    }

    /// Wraps a listener's router: request bodies are capped, and a request
    /// is refused when the listener is already serving its maximum or
    /// answered with an error once it has taken too long.
    // r[impl platform.server.limits]
    fn apply(self, router: Router) -> Router {
        let slots = Arc::new(Semaphore::new(self.max_concurrent_requests));
        router
            .layer(middleware::from_fn_with_state(
                (slots, self.request_timeout),
                bound,
            ))
            .layer(DefaultBodyLimit::max(self.max_body_bytes))
    }
}

async fn bound(
    State((slots, timeout)): State<(Arc<Semaphore>, Duration)>,
    request: Request,
    next: Next,
) -> Response {
    let refused = |reason| metrics::count(&metrics::METRICS.refused, "konklav.reason", reason);
    let Ok(_slot) = slots.try_acquire() else {
        refused("too_many");
        return ApiError::new(ErrorCode::Overloaded, "too many requests in progress")
            .into_response();
    };
    match tokio::time::timeout(timeout, next.run(request)).await {
        Ok(response) => response,
        Err(_) => {
            refused("timeout");
            ApiError::new(ErrorCode::Overloaded, "the request took too long").into_response()
        }
    }
}

/// A server whose listeners are bound but not yet accepting connections.
pub struct BoundServer {
    listeners: Vec<(TcpListener, Vec<Surface>)>,
    state: AppState,
    limits: Limits,
}

impl BoundServer {
    /// Binds one listener per distinct address in `listen`.
    // r[impl platform.server.single-binary]
    pub async fn bind(listen: &Listen, state: AppState) -> io::Result<Self> {
        let mut listeners = Vec::new();
        for (addr, surfaces) in surface::listeners(listen) {
            let listener = TcpListener::bind(addr).await.map_err(|error| {
                io::Error::new(error.kind(), format!("cannot listen on {addr}: {error}"))
            })?;
            listeners.push((listener, surfaces));
        }
        Ok(Self {
            listeners,
            state,
            limits: Limits::DEFAULT,
        })
    }

    /// Replaces the default [`Limits`].
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// The bound address of each listener and the surfaces it serves.
    pub fn local_addrs(&self) -> io::Result<Vec<(SocketAddr, Vec<Surface>)>> {
        self.listeners
            .iter()
            .map(|(listener, surfaces)| Ok((listener.local_addr()?, surfaces.clone())))
            .collect()
    }

    /// Serves every listener until `shutdown` completes, then drains in-flight
    /// requests.
    pub async fn run(self, shutdown: impl Future<Output = ()> + Send + 'static) -> io::Result<()> {
        let (stop, stopped) = watch::channel(false);
        let mut tasks = JoinSet::new();
        for (listener, surfaces) in self.listeners {
            let addr = listener.local_addr()?;
            let names = surfaces.iter().map(ToString::to_string).collect::<Vec<_>>();
            tracing::info!(%addr, surfaces = %names.join(","), "listening");
            let app = self
                .limits
                .apply(surface::router(&surfaces, self.state.clone()));
            let mut stopped = stopped.clone();
            tasks.spawn(async move {
                // Connection info gives handlers the client's address.
                let app = app.into_make_service_with_connect_info::<SocketAddr>();
                axum::serve(listener, app)
                    .with_graceful_shutdown(async move {
                        let _ = stopped.wait_for(|stop| *stop).await;
                    })
                    .await
            });
        }
        tokio::spawn(async move {
            shutdown.await;
            let _ = stop.send(true);
        });
        while let Some(result) = tasks.join_next().await {
            result.map_err(io::Error::other)??;
        }
        Ok(())
    }
}

/// Completes on Ctrl-C or, on Unix, SIGTERM.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
    tracing::info!("shutting down");
}
