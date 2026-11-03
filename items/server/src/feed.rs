//! The change feed: Server-Sent Events and a paged JSON variant over the
//! outbox, woken by Postgres notifications.

use std::collections::{BTreeSet, VecDeque};
use std::convert::Infallible;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::get;
use axum::{Json, Router};
use futures_util::Stream;
use konklav_core::feed::{FeedEvent, POSITION, RESET, SessionChanged};
use konklav_core::{Cursor, SessionId};
use konklav_store::{Pool, events, sessions};
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

use crate::error::{ApiError, ErrorCode};
use crate::relying_api::require_service;
use crate::{AppState, capabilities};

/// The interval between heartbeat comments on idle streams.
// r[impl feed.sse.heartbeat]
pub const HEARTBEAT: Duration = Duration::from_secs(10);
const PAGE: i64 = 200;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/events", get(stream_events))
        .route("/events/batch", get(batch_events))
        .route("/session-states/{id}", get(session_state))
}

/// Wakes streams when events are appended, and bounds how many are open.
pub struct FeedHub {
    notify: Notify,
    poll_interval: Duration,
    streams: std::sync::Arc<Semaphore>,
}

impl FeedHub {
    /// Streams open at once by default.
    pub const DEFAULT_MAX_STREAMS: usize = 1000;

    #[must_use]
    pub fn new(poll_interval: Duration) -> Self {
        Self {
            notify: Notify::new(),
            poll_interval,
            streams: std::sync::Arc::new(Semaphore::new(Self::DEFAULT_MAX_STREAMS)),
        }
    }

    /// Allows at most `max` streams open at once.
    #[must_use]
    pub fn with_max_streams(mut self, max: usize) -> Self {
        self.streams = std::sync::Arc::new(Semaphore::new(max));
        self
    }

    pub fn wake(&self) {
        self.notify.notify_waiters();
    }
}

/// Listens for `konklav_event` notifications and wakes streams, reconnecting
/// with backoff. Streams poll anyway, so this only reduces latency.
// r[impl feed.notify-hint-only]
pub async fn listen(url: String, hub: std::sync::Arc<FeedHub>) {
    use futures_util::StreamExt;
    let mut backoff = Duration::from_millis(500);
    loop {
        match tokio_postgres::connect(&url, tokio_postgres::NoTls).await {
            Ok((client, mut connection)) => {
                let hub = hub.clone();
                let messages = tokio::spawn(async move {
                    let mut stream =
                        futures_util::stream::poll_fn(move |cx| connection.poll_message(cx));
                    while let Some(message) = stream.next().await {
                        match message {
                            Ok(tokio_postgres::AsyncMessage::Notification(_)) => hub.wake(),
                            Ok(_) => {}
                            Err(_) => break,
                        }
                    }
                });
                if client.batch_execute("listen konklav_event").await.is_ok() {
                    backoff = Duration::from_millis(500);
                    let _ = messages.await;
                }
                drop(client);
                tracing::warn!("change-feed listener disconnected; retrying");
            }
            Err(error) => tracing::warn!(%error, "change-feed listener cannot connect"),
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

#[derive(Deserialize, Default)]
struct FeedQuery {
    /// Comma-separated event kinds; every kind when absent.
    kinds: Option<String>,
    /// Resume after this cursor (the SSE `Last-Event-ID` header wins).
    after: Option<i64>,
    limit: Option<i64>,
}

fn kinds(query: &FeedQuery) -> Option<BTreeSet<String>> {
    query.kinds.as_ref().map(|kinds| {
        kinds
            .split(',')
            .map(|k| k.trim().to_owned())
            .filter(|k| !k.is_empty())
            .collect()
    })
}

/// Where a consumer starts: its cursor, or a reset to the watermark when the
/// cursor can't be resumed (pruned, or ahead of the outbox).
async fn resume_point(
    conn: &mut konklav_store::Connection,
    requested: Option<Cursor>,
) -> Result<(Cursor, bool), ApiError> {
    let head = events::head(conn).await?;
    let Some(requested) = requested else {
        return Ok((head, false));
    };
    let watermark = events::pruned_through(conn).await?;
    if requested < watermark || requested > head {
        // r[impl feed.reset]
        Ok((watermark, true))
    } else {
        Ok((requested, false))
    }
}

const DELIVERY: &str = "delivery.requested";

/// Whether a consumer sees `event`: it matches the kinds filter, and delivery
/// requests only go to holders of the delivery capability.
fn visible(event: &events::Event, kinds: Option<&BTreeSet<String>>, delivery: bool) -> bool {
    kinds.is_none_or(|kinds| kinds.contains(&event.kind)) && (event.kind != DELIVERY || delivery)
}

/// Converts an outbox row, removing challenge material from delivery
/// requests whose challenge has expired, so replays reveal nothing usable.
// r[impl challenge.delivery.no-replay]
fn to_feed_event(event: events::Event) -> FeedEvent {
    let mut payload = event.payload;
    if event.kind == DELIVERY {
        let expired = payload["expires_at"]
            .as_i64()
            .is_none_or(|at| at <= chrono::Utc::now().timestamp());
        if expired && let Some(object) = payload.as_object_mut() {
            object.remove("material");
        }
    }
    FeedEvent {
        cursor: Cursor::new(event.cursor),
        kind: event.kind,
        payload,
    }
}

fn sse(event: &FeedEvent) -> Event {
    Event::default()
        .id(event.cursor.to_string())
        .event(event.kind.clone())
        .data(serde_json::to_string(event).unwrap_or_default())
}

struct StreamState {
    pool: Pool,
    hub: std::sync::Arc<FeedHub>,
    cursor: Cursor,
    kinds: Option<BTreeSet<String>>,
    /// Whether the consumer may read delivery requests.
    delivery: bool,
    buffer: VecDeque<FeedEvent>,
    /// Held until the stream ends.
    _slot: StreamSlot,
}

/// A stream's place among the open ones, counted while it's held.
struct StreamSlot(#[allow(dead_code)] OwnedSemaphorePermit);

impl StreamSlot {
    fn new(permit: OwnedSemaphorePermit) -> Self {
        crate::telemetry::metrics::METRICS.feed_streams.add(1, &[]);
        Self(permit)
    }
}

impl Drop for StreamSlot {
    fn drop(&mut self) {
        crate::telemetry::metrics::METRICS.feed_streams.add(-1, &[]);
    }
}

/// `GET /v1/events`: Server-Sent Events. Each event's `id` is its cursor;
/// reconnect with `Last-Event-ID` to resume.
// r[impl feed.sse]
// r[impl feed.sse.kinds-filter]
// r[impl feed.at-least-once]
async fn stream_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<FeedQuery>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let mut conn = state.pool.get().await?;
    // r[impl feed.authorization]
    let caller = require_service(&state, &mut conn, &headers).await?;
    // Streams outlive the request timeout, so they are bounded here.
    // r[impl platform.server.limits]
    let slot = state
        .feed
        .streams
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::new(ErrorCode::Overloaded, "too many change-feed streams"))?;
    let delivery = capabilities::holds(&mut conn, caller, capabilities::DELIVERY_READ).await?;
    let requested = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<i64>().ok())
        .or(query.after)
        .map(Cursor::new);
    let (cursor, reset) = resume_point(&mut conn, requested).await?;
    drop(conn);

    // Every stream starts by saying where it starts, so a consumer that
    // connected without a cursor knows its place on a quiet feed.
    // r[impl feed.sse.position]
    let buffer = VecDeque::from([FeedEvent {
        cursor,
        kind: if reset { RESET } else { POSITION }.into(),
        payload: serde_json::json!({}),
    }]);
    let initial = StreamState {
        pool: state.pool.clone(),
        hub: state.feed.clone(),
        cursor,
        kinds: kinds(&query),
        delivery,
        buffer,
        _slot: StreamSlot::new(slot),
    };
    let stream = futures_util::stream::unfold(initial, |mut state| async move {
        loop {
            if let Some(event) = state.buffer.pop_front() {
                return Some((Ok(sse(&event)), state));
            }
            // Register for wake-ups before reading, so nothing slips between.
            let notified = state.hub.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let mut conn = state.pool.get().await.ok()?;
            let page = events::after(&mut conn, state.cursor, PAGE).await.ok()?;
            drop(conn);
            if page.is_empty() {
                tokio::select! {
                    () = &mut notified => {}
                    () = tokio::time::sleep(state.hub.poll_interval) => {}
                }
                continue;
            }
            for event in page {
                state.cursor = Cursor::new(event.cursor);
                if visible(&event, state.kinds.as_ref(), state.delivery) {
                    state.buffer.push_back(to_feed_event(event));
                }
            }
        }
    });
    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(HEARTBEAT).text("heartbeat")))
}

#[derive(Serialize)]
struct Batch {
    events: Vec<FeedEvent>,
    /// Pass as `after` to continue.
    next: Cursor,
    /// The requested cursor couldn't be resumed: treat cached state as stale.
    reset: bool,
}

/// `GET /v1/events/batch?after=&kinds=&limit=`: the feed as paged JSON.
// r[impl feed.batch]
async fn batch_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<FeedQuery>,
) -> Result<Json<Batch>, ApiError> {
    let mut conn = state.pool.get().await?;
    let caller = require_service(&state, &mut conn, &headers).await?;
    let delivery = capabilities::holds(&mut conn, caller, capabilities::DELIVERY_READ).await?;
    let requested = Cursor::new(query.after.unwrap_or(0));
    let (cursor, reset) = resume_point(&mut conn, Some(requested)).await?;
    let limit = query.limit.unwrap_or(PAGE).clamp(1, 1000);
    let page = events::after(&mut conn, cursor, limit).await?;
    let next = page.last().map_or(cursor, |e| Cursor::new(e.cursor));
    let kinds = kinds(&query);
    Ok(Json(Batch {
        events: page
            .into_iter()
            .filter(|e| visible(e, kinds.as_ref(), delivery))
            .map(to_feed_event)
            .collect(),
        next,
        reset,
    }))
}

/// `GET /v1/session-states/{id}`: a session's state in the same shape as a
/// `session.changed` payload, for caches that haven't seen it yet.
async fn session_state(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<SessionChanged>, ApiError> {
    let id: SessionId = id
        .parse()
        .map_err(|_| ApiError::invalid_request("session id is not a valid identifier"))?;
    let mut conn = state.pool.get().await?;
    require_service(&state, &mut conn, &headers).await?;
    let session = sessions::get(&mut conn, id)
        .await
        .map_err(|_| ApiError::not_found("session"))?;
    Ok(Json(SessionChanged {
        session: session.id,
        subject: session.subject_id,
        version: session.version,
        revoked: session.revoked_at.is_some(),
        expires_at: session.expires_at.timestamp(),
    }))
}
