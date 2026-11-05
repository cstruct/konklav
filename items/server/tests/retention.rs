#![allow(clippy::too_many_lines)]

mod common;

use chrono::{Duration, Utc};
use common::TestApp;
use diesel_async::RunQueryDsl;
use konklav_server::sweeper::{self, Settings, Swept};

const PASSWORD: &str = "correct horse battery";

fn settings() -> Settings {
    Settings {
        sessions: Duration::days(30),
        events: Duration::days(7),
        interval: std::time::Duration::from_secs(300),
        // Small, so every kind takes more than one batch.
        batch: 2,
    }
}

/// Runs `sql`, one `;`-separated statement at a time.
async fn exec(app: &TestApp, sql: &str) {
    let mut conn = app.db.pool().get().await.unwrap();
    for statement in sql.split(';').filter(|s| !s.trim().is_empty()) {
        diesel::sql_query(statement)
            .execute(&mut conn)
            .await
            .unwrap();
    }
}

async fn count(app: &TestApp, sql: &str) -> i64 {
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        count: i64,
    }
    let mut conn = app.db.pool().get().await.unwrap();
    diesel::sql_query(format!("select count(*) as count from {sql}"))
        .get_result::<Count>(&mut conn)
        .await
        .unwrap()
        .count
}

async fn sweep(app: &TestApp) -> Swept {
    let mut conn = app.db.pool().get().await.unwrap();
    sweeper::sweep(&mut conn, settings(), Utc::now())
        .await
        .unwrap()
        .expect("nothing else holds the lock")
}

/// Logs in and returns the new session's id.
async fn session(app: &TestApp, email: &str) -> String {
    let reply = app.login(email, PASSWORD).await;
    let token = reply.body["access_token"].as_str().unwrap();
    app.verify(token).await.sid.to_string()
}

// r[verify retention.challenges]
// r[verify retention.login-attempts]
// r[verify retention.assertions]
#[tokio::test(flavor = "multi_thread")]
async fn expired_rows_go_once_no_window_counts_them() {
    let app = TestApp::new().await;
    let challenges = "challenge where recipient like '%@retention.example'";
    // Expired and older than the send-limit window; expired but recent
    // enough to count against sends; not yet expired.
    for (recipient, created, expires) in [
        ("old-1", "2 days", "1 day"),
        ("old-2", "3 days", "2 days"),
        ("old-3", "3 days", "2 days"),
        ("recent", "2 hours", "1 hour"),
        ("live", "1 minute", "-10 minutes"),
    ] {
        exec(
            &app,
            &format!(
                "insert into challenge (id, purpose, recipient, secret_hash, created_at, expires_at)
                 values (gen_random_uuid(), 'email_link', '{recipient}@retention.example', '\\x00',
                         now() - interval '{created}', now() - interval '{expires}')"
            ),
        )
        .await;
    }
    for (identifier, age) in [("a", "25 hours"), ("b", "2 days"), ("c", "23 hours")] {
        exec(
            &app,
            &format!(
                "insert into login_attempt (kind, identifier, succeeded, attempted_at)
                 values ('password', '{identifier}@retention.example', false, now() - interval '{age}')"
            ),
        )
        .await;
    }
    exec(
        &app,
        "insert into oidc_client (id, kind, redirect_uris, audience)
         values ('retention', 'confidential', '{https://rp.retention.example/cb}', 'rp')",
    )
    .await;
    for (jti, expires) in [("gone", "1 minute"), ("kept", "-1 minute")] {
        exec(
            &app,
            &format!(
                "insert into client_assertion (client_id, jti, expires_at)
                 values ('retention', '{jti}', now() - interval '{expires}');
                 insert into bearer_assertion (issuer, jti, expires_at)
                 values ('https://retention.example', '{jti}', now() - interval '{expires}');
                 insert into dpop_proof (jkt, jti, expires_at)
                 values ('retention', '{jti}', now() - interval '{expires}')"
            ),
        )
        .await;
    }

    let swept = sweep(&app).await;
    assert_eq!(swept.challenges, 3, "{swept:?}");
    assert_eq!(swept.login_attempts, 2, "{swept:?}");
    assert_eq!(swept.client_assertions, 1);
    assert_eq!(swept.bearer_assertions, 1);
    assert_eq!(swept.dpop_proofs, 1);
    assert_eq!(count(&app, challenges).await, 2);
    assert_eq!(
        count(
            &app,
            "login_attempt where identifier = 'c@retention.example'"
        )
        .await,
        1
    );
    assert_eq!(count(&app, "client_assertion where jti = 'kept'").await, 1);
    assert_eq!(count(&app, "bearer_assertion where jti = 'kept'").await, 1);
    assert_eq!(
        sweep(&app).await,
        Swept::default(),
        "a second sweep finds nothing"
    );
}

// r[verify retention.sessions]
#[tokio::test(flavor = "multi_thread")]
async fn ended_sessions_go_after_retention_unless_something_needs_them() {
    let app = TestApp::new().await;
    app.human("ada@retention.example", PASSWORD).await;
    let revoked_long_ago = session(&app, "ada@retention.example").await;
    let expired_long_ago = session(&app, "ada@retention.example").await;
    let revoked_recently = session(&app, "ada@retention.example").await;
    let active = session(&app, "ada@retention.example").await;
    let pending_logout = session(&app, "ada@retention.example").await;
    let parent = session(&app, "ada@retention.example").await;
    let child = session(&app, "ada@retention.example").await;
    exec(
        &app,
        &format!(
            "update session set revoked_at = now() - interval '31 days', revoked_reason = 'signed_out'
               where id in ('{revoked_long_ago}', '{pending_logout}', '{parent}');
             update session set expires_at = now() - interval '40 days'
               where id = '{expired_long_ago}';
             update session set revoked_at = now() - interval '29 days', revoked_reason = 'signed_out'
               where id = '{revoked_recently}';
             update session set parent_session_id = '{parent}' where id = '{child}';
             insert into session_previous_refresh (session_id, refresh_hash, rotated_at)
               values ('{revoked_long_ago}', '\\x01', now() - interval '32 days');
             insert into challenge (id, purpose, session_id, recipient, secret_hash, expires_at)
               values (gen_random_uuid(), 'mfa_email_code', '{expired_long_ago}', 'ada@retention.example', '\\x02',
                       now() + interval '10 minutes');
             insert into oidc_client (id, kind, redirect_uris, audience)
               values ('retention', 'confidential', '{{https://rp.retention.example/cb}}', 'rp');
             insert into backchannel_logout (id, client_id, session_id, subject_id, attempts,
                                             next_attempt_at, created_at)
               select gen_random_uuid(), 'retention', id, subject_id, 0, now(), now()
               from session where id = '{pending_logout}'"
        ),
    )
    .await;

    let swept = sweep(&app).await;
    assert_eq!(swept.sessions, 2, "{swept:?}");
    let kept = |id: &str| format!("session where id = '{id}'");
    assert_eq!(count(&app, &kept(&revoked_long_ago)).await, 0);
    assert_eq!(count(&app, &kept(&expired_long_ago)).await, 0);
    assert_eq!(
        count(
            &app,
            &format!("session_previous_refresh where session_id = '{revoked_long_ago}'")
        )
        .await,
        0,
        "refresh history goes with its session"
    );
    assert_eq!(
        count(
            &app,
            &format!("challenge where session_id = '{expired_long_ago}'")
        )
        .await,
        0,
        "and so do its challenges"
    );
    for id in [&revoked_recently, &active, &pending_logout, &parent, &child] {
        assert_eq!(count(&app, &kept(id)).await, 1, "{id} is kept");
    }

    // Once the impersonation session has ended and gone too, its parent
    // follows.
    exec(
        &app,
        &format!("update session set revoked_at = now() - interval '31 days', revoked_reason = 'signed_out'
             where id = '{child}'"),
    )
    .await;
    assert_eq!(sweep(&app).await.sessions, 1);
    assert_eq!(count(&app, &kept(&child)).await, 0);
    assert_eq!(sweep(&app).await.sessions, 1);
    assert_eq!(count(&app, &kept(&parent)).await, 0);
}

// r[verify retention.delivery-material]
#[tokio::test(flavor = "multi_thread")]
async fn delivery_material_is_erased_once_its_challenge_expires() {
    let app = TestApp::new().await;
    for (recipient, expires) in [("expired", -60), ("live", 600)] {
        exec(
            &app,
            &format!(
                "insert into event (kind, payload) values ('delivery.requested', jsonb_build_object(
                     'channel', 'email', 'recipient', '{recipient}@retention.example',
                     'purpose', 'email_link', 'material', jsonb_build_object('token', 'secret'),
                     'expires_at', extract(epoch from now())::bigint + {expires}))"
            ),
        )
        .await;
    }
    assert_eq!(sweep(&app).await.delivery_material, 1);
    let with_material = |recipient: &str| {
        format!(
            "event where kind = 'delivery.requested' and payload ? 'material'
               and payload ->> 'recipient' = '{recipient}@retention.example'"
        )
    };
    assert_eq!(count(&app, &with_material("expired")).await, 0);
    assert_eq!(count(&app, &with_material("live")).await, 1);
    assert_eq!(
        count(
            &app,
            "event where payload ->> 'recipient' = 'expired@retention.example'"
        )
        .await,
        1,
        "the event itself stays for the feed"
    );
}

// r[verify retention.sweep]
#[tokio::test(flavor = "multi_thread")]
async fn one_sweeper_runs_at_a_time() {
    let app = TestApp::new().await;
    let mut holder = app.db.pool().get().await.unwrap();
    assert!(konklav_store::sweep::try_lock(&mut holder).await.unwrap());
    let mut conn = app.db.pool().get().await.unwrap();
    assert_eq!(
        sweeper::sweep(&mut conn, settings(), Utc::now())
            .await
            .unwrap(),
        None
    );
    konklav_store::sweep::unlock(&mut holder).await.unwrap();
    assert!(
        sweeper::sweep(&mut conn, settings(), Utc::now())
            .await
            .unwrap()
            .is_some()
    );
}

// r[verify retention.identity-claims]
#[tokio::test(flavor = "multi_thread")]
async fn passed_claims_are_erased_once_the_session_ends() {
    let app = TestApp::new().await;
    app.human("ada@retention.example", PASSWORD).await;
    let live = session(&app, "ada@retention.example").await;
    let expired = session(&app, "ada@retention.example").await;
    let revoked = session(&app, "ada@retention.example").await;
    exec(
        &app,
        &format!(
            "update session set identity_claims = '{{\"profile\": {{\"name\": \"Ada\"}}}}';
             update session set expires_at = now() - interval '1 minute' where id = '{expired}';
             update session set revoked_at = now(), revoked_reason = 'logout' where id = '{revoked}'"
        ),
    )
    .await;
    assert_eq!(sweep(&app).await.identity_claims, 2);
    assert_eq!(
        count(&app, "session where identity_claims is not null").await,
        1
    );
    assert_eq!(
        count(
            &app,
            &format!("session where id = '{live}' and identity_claims is not null")
        )
        .await,
        1
    );
    assert_eq!(
        count(&app, "session").await,
        3,
        "the sessions themselves stay"
    );
}
