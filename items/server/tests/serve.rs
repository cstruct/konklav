mod common;

use std::net::SocketAddr;

use konklav_server::config::Listen;
use konklav_server::serve::BoundServer;
use konklav_server::surface::Surface;
use konklav_test_support::TestDatabase;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn get_status_line(addr: SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    response.lines().next().unwrap_or_default().to_owned()
}

// r[verify platform.server.single-binary]
#[tokio::test(flavor = "multi_thread")]
async fn serves_every_surface_on_its_own_listener_until_shutdown() {
    let db = TestDatabase::new().await;
    let any_port = "127.0.0.1:0".parse().unwrap();
    let listen = Listen {
        subject: any_port,
        relying: any_port,
        control: any_port,
        trusted_proxies: Vec::new(),
    };
    let server = BoundServer::bind(&listen, common::state(db.pool().clone()))
        .await
        .unwrap();
    let addrs = server.local_addrs().unwrap();
    let surfaces = addrs
        .iter()
        .flat_map(|(_, s)| s.clone())
        .collect::<Vec<_>>();
    assert_eq!(surfaces, Surface::ALL);

    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let running = tokio::spawn(server.run(async move {
        let _ = stopped.await;
    }));

    for (addr, _) in &addrs {
        assert_eq!(get_status_line(*addr, "/readyz").await, "HTTP/1.1 200 OK");
    }

    stop.send(()).unwrap();
    running.await.unwrap().unwrap();
    for (addr, _) in &addrs {
        assert!(
            TcpStream::connect(addr).await.is_err(),
            "{addr} still accepts"
        );
    }
}
