//! Binding listeners and running the server until shutdown.

use std::future::Future;
use std::io;
use std::net::SocketAddr;

use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::AppState;
use crate::config::Listen;
use crate::surface::{self, Surface};

/// A server whose listeners are bound but not yet accepting connections.
pub struct BoundServer {
    listeners: Vec<(TcpListener, Vec<Surface>)>,
    state: AppState,
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
        Ok(Self { listeners, state })
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
            let app = surface::router(&surfaces, self.state.clone());
            let mut stopped = stopped.clone();
            tasks.spawn(async move {
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
