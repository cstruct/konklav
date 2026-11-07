mod common;

use std::net::SocketAddr;
use std::time::Duration;

use konklav_server::config::Listen;
use konklav_server::serve::{BoundServer, Limits};
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
// r[verify oidc.provider.jwks]
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

    for (addr, surfaces) in &addrs {
        assert_eq!(get_status_line(*addr, "/readyz").await, "HTTP/1.1 200 OK");
        // The key set is where relying systems and OpenID clients look.
        let jwks = get_status_line(*addr, "/.well-known/jwks.json").await;
        if surfaces == &[Surface::Control] {
            assert_eq!(jwks, "HTTP/1.1 404 Not Found");
        } else {
            assert_eq!(jwks, "HTTP/1.1 200 OK", "{surfaces:?}");
        }
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

async fn post_login(addr: SocketAddr, body: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "POST /v1/login/password HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    response
}

// r[verify platform.server.limits]
#[tokio::test(flavor = "multi_thread")]
async fn listeners_bound_time_size_and_concurrency() {
    let app = common::TestApp::with_pacing(konklav_server::pacing::Pacing {
        floor: Duration::from_millis(400),
        jitter: Duration::ZERO,
    })
    .await;
    let login = r#"{"identifier": "nobody@example.com", "password": "x"}"#;

    let slow = app
        .serve_with(Limits {
            request_timeout: Duration::from_millis(100),
            ..Limits::DEFAULT
        })
        .await;
    let timed_out = post_login(slow.subject, login).await;
    assert!(timed_out.starts_with("HTTP/1.1 503"), "{timed_out}");
    assert!(timed_out.contains("OVERLOADED"), "{timed_out}");

    let small = app
        .serve_with(Limits {
            max_body_bytes: 64,
            ..Limits::DEFAULT
        })
        .await;
    let padded = format!(
        r#"{{"identifier": "{}", "password": "x"}}"#,
        "a".repeat(100)
    );
    let too_big = post_login(small.subject, &padded).await;
    assert!(too_big.starts_with("HTTP/1.1 400"), "{too_big}");
    assert!(too_big.contains("length limit"), "{too_big}");

    let narrow = app
        .serve_with(Limits {
            max_concurrent_requests: 1,
            ..Limits::DEFAULT
        })
        .await;
    let (first, second) = tokio::join!(post_login(narrow.subject, login), async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        post_login(narrow.subject, login).await
    });
    assert!(first.starts_with("HTTP/1.1 401"), "{first}");
    assert!(second.starts_with("HTTP/1.1 503"), "{second}");
}

// r[verify platform.server.limits]
#[tokio::test(flavor = "multi_thread")]
async fn change_feed_streams_outlive_the_request_timeout() {
    // A stream counts against the bound until it starts, so the bound must
    // leave room for authenticating and reading the feed position on a busy
    // machine (they take up to ~100 ms there).
    const TIMEOUT: Duration = Duration::from_secs(1);
    let app = common::TestApp::new().await;
    let token = app.service_token().await;
    let running = app
        .serve_with(Limits {
            request_timeout: TIMEOUT,
            ..Limits::DEFAULT
        })
        .await;
    let mut stream = TcpStream::connect(running.relying).await.unwrap();
    let request = format!(
        "GET /v1/events HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {token}\r\n\r\n",
        running.relying
    );
    let sent = tokio::time::Instant::now();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut head = [0u8; 15];
    stream.read_exact(&mut head).await.unwrap();
    assert_eq!(&head, b"HTTP/1.1 200 OK");
    // Well past the bound, counted from the request.
    tokio::time::sleep_until(sent + TIMEOUT + Duration::from_millis(300)).await;
    let mut rest = [0u8; 1024];
    let read = tokio::time::timeout(Duration::from_millis(200), stream.read(&mut rest)).await;
    assert!(
        !matches!(read, Ok(Ok(0))),
        "the stream was closed when the timeout passed"
    );
}
