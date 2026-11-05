use chrono::{Duration, Utc};
use diesel_async::RunQueryDsl;
use konklav_core::{CredentialId, Cursor, SessionId, SubjectId};
use konklav_store::credentials::{
    self, CredentialData, CredentialKind, FederatedData, NewCredential, PUBLIC_KEY_STATE_VERSION,
    PasswordData, PublicKeyData, SecretKeyData, SecretSlot, SecretSlotData,
};
use konklav_store::sessions::{self, ClientKind, NewSession, Rotation, SessionFilter, Stage};
use konklav_store::subjects::{self, SubjectKind, SubjectState};
use konklav_store::{Connection, StoreError, dpop_proofs, events, signing_keys};
use konklav_test_support::TestDatabase;

const HASH: &str = "$argon2id$v=19$m=8,t=1,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNo";

async fn subject(conn: &mut Connection) -> SubjectId {
    let id = SubjectId::new_v7();
    subjects::create(conn, id, SubjectKind::Human)
        .await
        .unwrap();
    id
}

async fn password(conn: &mut Connection, subject: SubjectId, email: &str) -> CredentialId {
    credentials::insert(
        conn,
        NewCredential {
            id: CredentialId::new_v7(),
            subject_id: subject,
            identifier: email.into(),
            data: CredentialData::Password(PasswordData { hash: HASH.into() }),
            mfa_factors_required: 0,
            replaces: None,
        },
    )
    .await
    .unwrap()
    .id
}

async fn session(
    conn: &mut Connection,
    subject: SubjectId,
    credential: CredentialId,
    refresh: &[u8],
) -> SessionId {
    let id = SessionId::new_v7();
    sessions::insert(
        conn,
        NewSession {
            dpop_jkt: None,
            id,
            subject_id: subject,
            credential_id: credential,
            stage: Stage::Identity,
            client_kind: ClientKind::Native,
            amr: vec!["pwd".into()],
            auth_time: Utc::now(),
            flags: vec![],
            impersonator_subject_id: None,
            parent_session_id: None,
            refresh_hash: refresh.to_vec(),
            expires_at: Utc::now() + Duration::days(1),
        },
    )
    .await
    .unwrap();
    id
}

async fn event_kinds(conn: &mut Connection) -> Vec<String> {
    events::after(conn, Cursor::START, 1000)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.kind)
        .collect()
}

// r[verify platform.idempotency.client-ids]
#[tokio::test(flavor = "multi_thread")]
async fn creating_a_subject_is_idempotent_on_its_id() {
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    let id = SubjectId::new_v7();
    let (_, created) = subjects::create(&mut conn, id, SubjectKind::Service)
        .await
        .unwrap();
    assert!(created);
    let (again, created) = subjects::create(&mut conn, id, SubjectKind::Service)
        .await
        .unwrap();
    assert!(!created);
    assert_eq!(again.kind, SubjectKind::Service);
    assert!(matches!(
        subjects::create(&mut conn, id, SubjectKind::Human).await,
        Err(StoreError::Conflict(_))
    ));
    assert_eq!(
        subjects::set_state(&mut conn, id, SubjectState::Disabled)
            .await
            .unwrap(),
        SubjectState::Active
    );
}

// r[verify item.store.typed-data]
#[tokio::test(flavor = "multi_thread")]
async fn the_database_rejects_credential_data_that_violates_its_schema() {
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    let subject = subject(&mut conn).await;
    for (kind, data) in [
        ("password", r#"{"hash": "plaintext"}"#),
        ("password", r#"{"hash": "$argon2id$x", "extra": 1}"#),
        ("password", r"{}"),
        ("secret_key", r"{}"),
        (
            "secret_key",
            r#"{"a": {"hash": "$argon2id$x", "created_at": "2026-01-01T00:00:00Z"}}"#,
        ),
        (
            "secret_key",
            r#"{"slots": {"a": {"hash": "$argon2id$x", "created_at": "2026-01-01T00:00:00Z"}}}"#,
        ),
        (
            "secret_key",
            r#"{"c": {"hash": "$argon2id$x", "created_at": "2026-01-01T00:00:00Z"}}"#,
        ),
        ("federated", r#"{"provider": "ops"}"#),
        ("federated", r#"{"provider": "ops", "subject": ""}"#),
        ("public_key", r"{}"),
        (
            "public_key",
            r#"{"label": "", "attestation_format": "none", "state_version": 1, "state": {}}"#,
        ),
        (
            "public_key",
            r#"{"label": "Phone", "attestation_format": "none", "state_version": 2, "state": {}}"#,
        ),
        (
            "public_key",
            r#"{"label": "Phone", "attestation_format": "none", "state_version": 1, "state": "key"}"#,
        ),
        ("telepathy", r"{}"),
    ] {
        let result = diesel::sql_query(format!(
            "insert into credential (id, subject_id, kind, identifier, data) \
             values (gen_random_uuid(), '{subject}', '{kind}', 'x', '{data}')"
        ))
        .execute(&mut conn)
        .await;
        assert!(result.is_err(), "accepted {kind} {data}");
    }
}

// r[verify item.store.typed-data]
#[tokio::test(flavor = "multi_thread")]
async fn the_database_rejects_mfa_factor_data_that_violates_its_schema() {
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    let subject = subject(&mut conn).await;
    let insert = |kind: &str, data: &str| {
        diesel::sql_query(format!(
            "insert into mfa_factor (id, subject_id, kind, data) \
             values (gen_random_uuid(), '{subject}', '{kind}', '{data}')"
        ))
    };
    for (kind, data) in [
        (
            "totp",
            r#"{"key_id": "k", "nonce": "n", "ciphertext": "c"}"#,
        ),
        ("email_code", r#"{"email": "ada@acme.example"}"#),
    ] {
        insert(kind, data).execute(&mut conn).await.unwrap();
    }
    for (kind, data) in [
        ("totp", r"{}"),
        ("totp", r#"{"key_id": "k", "nonce": "n"}"#),
        (
            "totp",
            r#"{"key_id": "k", "nonce": "n", "ciphertext": "c", "secret": "s"}"#,
        ),
        (
            "totp",
            r#"{"key_id": "k", "nonce": "n", "ciphertext": "c", "last_step": "1"}"#,
        ),
        ("email_code", r"{}"),
        ("email_code", r#"{"email": "a@"}"#),
        ("email_code", r#"{"email": "ada@acme.example", "extra": 1}"#),
        ("sms", r#"{"phone": "+15550100"}"#),
    ] {
        let result = insert(kind, data).execute(&mut conn).await;
        assert!(result.is_err(), "accepted {kind} {data}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn secret_keys_round_trip_through_the_schema() {
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    let subject = subject(&mut conn).await;
    let slot = |hash: &str| SecretSlotData {
        hash: hash.into(),
        created_at: Utc::now(),
        expires_at: None,
    };
    let mut data = SecretKeyData {
        a: slot(HASH),
        b: slot(HASH),
    };
    let rotated = format!("{HASH}x");
    data.set(SecretSlot::B, slot(&rotated));
    assert_eq!(data.slot(SecretSlot::A).hash, HASH);
    assert_eq!(data.slot(SecretSlot::B).hash, rotated);
    let data = CredentialData::SecretKey(data);
    let id = CredentialId::new_v7();
    let stored = credentials::insert(
        &mut conn,
        NewCredential {
            id,
            subject_id: subject,
            identifier: id.to_string(),
            data: data.clone(),
            mfa_factors_required: 0,
            replaces: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(credentials::get(&mut conn, id).await.unwrap(), stored);
}

// r[verify credential.public-key.stored]
#[tokio::test(flavor = "multi_thread")]
async fn passkeys_are_found_by_their_exact_credential_id() {
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    let subject = subject(&mut conn).await;
    let id = CredentialId::new_v7();
    let stored = credentials::insert(
        &mut conn,
        NewCredential {
            id,
            subject_id: subject,
            identifier: "AbC-_x".into(),
            data: CredentialData::PublicKey(PublicKeyData {
                label: "Laptop".into(),
                attestation_format: "none".into(),
                last_used_at: None,
                state_version: PUBLIC_KEY_STATE_VERSION,
                state: serde_json::json!({"cred": {"counter": 0}}),
            }),
            mfa_factors_required: 0,
            replaces: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(stored.identifier, "AbC-_x");
    assert_eq!(credentials::get(&mut conn, id).await.unwrap(), stored);
    let found = credentials::find_active(&mut conn, CredentialKind::PublicKey, "AbC-_x")
        .await
        .unwrap();
    assert_eq!(found.map(|credential| credential.id), Some(id));
    let other_case = credentials::find_active(&mut conn, CredentialKind::PublicKey, "abc-_x")
        .await
        .unwrap();
    assert_eq!(other_case, None);
}

// r[verify federation.credential]
#[tokio::test(flavor = "multi_thread")]
async fn federated_credentials_are_found_by_provider_and_case_sensitive_subject() {
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    let subject = subject(&mut conn).await;
    let account = |sub: &str| {
        CredentialData::Federated(FederatedData {
            provider: "ops".into(),
            subject: sub.into(),
            email: Some("ada@example.com".into()),
            email_verified: Some(true),
        })
    };
    let id = CredentialId::new_v7();
    let stored = credentials::insert(
        &mut conn,
        NewCredential {
            id,
            subject_id: subject,
            identifier: credentials::federated_identifier("ops", "AbC"),
            data: account("AbC"),
            mfa_factors_required: 0,
            replaces: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(credentials::get(&mut conn, id).await.unwrap(), stored);
    let found = credentials::find_active(
        &mut conn,
        CredentialKind::Federated,
        &credentials::federated_identifier("ops", "AbC"),
    )
    .await
    .unwrap();
    assert_eq!(found.map(|c| c.id), Some(id));
    let other_case = credentials::find_active(
        &mut conn,
        CredentialKind::Federated,
        &credentials::federated_identifier("ops", "abc"),
    )
    .await
    .unwrap();
    assert_eq!(
        other_case, None,
        "subjects that differ in case are different accounts"
    );
}

// r[verify credential.identifier.unique]
// r[verify credential.history]
#[tokio::test(flavor = "multi_thread")]
async fn identifiers_are_unique_among_active_credentials() {
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    let a = subject(&mut conn).await;
    let b = subject(&mut conn).await;
    let first = password(&mut conn, a, "Ada@Example.com").await;
    let taken = credentials::insert(
        &mut conn,
        NewCredential {
            id: CredentialId::new_v7(),
            subject_id: b,
            identifier: " ada@example.COM ".into(),
            data: CredentialData::Password(PasswordData { hash: HASH.into() }),
            mfa_factors_required: 0,
            replaces: None,
        },
    )
    .await;
    assert!(matches!(taken, Err(StoreError::Conflict(_))));

    assert!(
        credentials::revoke(&mut conn, first, "replaced")
            .await
            .unwrap()
    );
    assert!(
        !credentials::revoke(&mut conn, first, "again")
            .await
            .unwrap()
    );
    let second = password(&mut conn, b, "ada@example.com").await;
    let found = credentials::find_active(
        &mut conn,
        credentials::CredentialKind::Password,
        "ADA@example.com",
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(found.id, second);
    let old = credentials::get(&mut conn, first).await.unwrap();
    assert_eq!(
        old.revoked_reason.as_deref(),
        Some("replaced"),
        "history is kept"
    );
}

// r[verify session.refresh.rotation]
#[tokio::test(flavor = "multi_thread")]
async fn rotating_refresh_tokens_detects_reuse() {
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    let subject = subject(&mut conn).await;
    let credential = password(&mut conn, subject, "a@x").await;
    let id = session(&mut conn, subject, credential, b"r1").await;
    let now = Utc::now();

    let Rotation::Rotated(rotated, _) = sessions::rotate_refresh(&mut conn, id, b"r1", b"r2", now)
        .await
        .unwrap()
    else {
        panic!("expected rotation");
    };
    assert_eq!(rotated.version, 2);
    assert_eq!(
        sessions::rotate_refresh(&mut conn, id, b"guess", b"r3", now)
            .await
            .unwrap(),
        Rotation::Invalid
    );
    let Rotation::Reused(revoked, _) = sessions::rotate_refresh(&mut conn, id, b"r1", b"r3", now)
        .await
        .unwrap()
    else {
        panic!("expected reuse detection");
    };
    assert_eq!(
        revoked.revoked_reason.as_deref(),
        Some("refresh_token_reused")
    );
    assert!(matches!(
        sessions::rotate_refresh(&mut conn, id, b"r2", b"r3", now)
            .await
            .unwrap(),
        Rotation::Ended(_)
    ));
    assert_eq!(
        sessions::rotate_refresh(&mut conn, SessionId::new_v7(), b"r2", b"r3", now)
            .await
            .unwrap(),
        Rotation::Invalid
    );
}

// r[verify token.dpop.binding]
#[tokio::test(flavor = "multi_thread")]
async fn a_sessions_dpop_binding_survives_rotation_and_revocation() {
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    let subject = subject(&mut conn).await;
    let credential = password(&mut conn, subject, "a@x").await;
    let id = SessionId::new_v7();
    let (inserted, _) = sessions::insert(
        &mut conn,
        NewSession {
            dpop_jkt: Some("jkt".into()),
            id,
            subject_id: subject,
            credential_id: credential,
            stage: Stage::Identity,
            client_kind: ClientKind::Native,
            amr: vec!["pwd".into()],
            auth_time: Utc::now(),
            flags: vec![],
            impersonator_subject_id: None,
            parent_session_id: None,
            refresh_hash: b"r1".to_vec(),
            expires_at: Utc::now() + Duration::days(1),
        },
    )
    .await
    .unwrap();
    assert_eq!(inserted.dpop_jkt.as_deref(), Some("jkt"));
    let Rotation::Rotated(rotated, _) =
        sessions::rotate_refresh(&mut conn, id, b"r1", b"r2", Utc::now())
            .await
            .unwrap()
    else {
        panic!("expected rotation");
    };
    assert_eq!(rotated.dpop_jkt.as_deref(), Some("jkt"));
    let filter = SessionFilter {
        session: Some(id),
        ..Default::default()
    };
    sessions::revoke(&mut conn, &filter, None, "signed_out")
        .await
        .unwrap();
    let revoked = sessions::get(&mut conn, id).await.unwrap();
    assert_eq!(revoked.dpop_jkt.as_deref(), Some("jkt"));
    let unbound = session(&mut conn, subject, credential, b"u1").await;
    assert_eq!(
        sessions::get(&mut conn, unbound).await.unwrap().dpop_jkt,
        None
    );
}

// r[verify token.dpop.replay]
#[tokio::test(flavor = "multi_thread")]
async fn a_dpop_proof_id_is_accepted_once_per_key() {
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    let until = Utc::now() + Duration::minutes(1);
    assert!(
        dpop_proofs::record(&mut conn, "k1", "a", until)
            .await
            .unwrap()
    );
    assert!(
        !dpop_proofs::record(&mut conn, "k1", "a", until)
            .await
            .unwrap()
    );
    assert!(
        dpop_proofs::record(&mut conn, "k2", "a", until)
            .await
            .unwrap()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn expired_sessions_do_not_rotate() {
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    let subject = subject(&mut conn).await;
    let credential = password(&mut conn, subject, "a@x").await;
    let id = session(&mut conn, subject, credential, b"r1").await;
    let later = Utc::now() + Duration::days(2);
    assert!(matches!(
        sessions::rotate_refresh(&mut conn, id, b"r1", b"r2", later)
            .await
            .unwrap(),
        Rotation::Ended(_)
    ));
}

// r[verify session.revocation.targets]
// r[verify session.history]
// r[verify feed.outbox]
// r[verify feed.self-contained-session]
// r[verify platform.storage.transactional-events]
// r[verify session.revocation.event]
#[tokio::test(flavor = "multi_thread")]
async fn revokes_by_filter_keeping_one_session_and_emits_events() {
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    let subject_a = subject(&mut conn).await;
    let subject_b = subject(&mut conn).await;
    let cred_a = password(&mut conn, subject_a, "a@x").await;
    let cred_b = password(&mut conn, subject_b, "b@x").await;
    let keep = session(&mut conn, subject_a, cred_a, b"1").await;
    let other = session(&mut conn, subject_a, cred_a, b"2").await;
    let unrelated = session(&mut conn, subject_b, cred_b, b"3").await;

    let none = sessions::revoke(&mut conn, &SessionFilter::default(), None, "x")
        .await
        .unwrap();
    assert_eq!(none.len(), 0, "an empty filter matches nothing");

    let filter = SessionFilter {
        subject: Some(subject_a),
        ..Default::default()
    };
    let revoked = sessions::revoke(&mut conn, &filter, Some(keep), "sign_out_others")
        .await
        .unwrap();
    assert_eq!(
        revoked.iter().map(|(s, _)| s.id).collect::<Vec<_>>(),
        vec![other]
    );
    assert_eq!(revoked[0].0.version, 2, "revocation bumps the version");

    assert!(
        sessions::get(&mut conn, keep)
            .await
            .unwrap()
            .revoked_at
            .is_none()
    );
    assert!(
        sessions::get(&mut conn, unrelated)
            .await
            .unwrap()
            .revoked_at
            .is_none()
    );

    let events = events::after(&mut conn, Cursor::START, 1000).await.unwrap();
    assert!(events.windows(2).all(|w| w[0].cursor < w[1].cursor));
    let last = events.last().unwrap();
    assert_eq!(last.payload["session"], serde_json::json!(other));
    assert_eq!(last.payload["version"], 2);
    assert_eq!(last.payload["revoked"], true);
    let kinds = event_kinds(&mut conn).await;
    assert_eq!(
        kinds.iter().filter(|k| *k == "session.changed").count(),
        4,
        "3 created + 1 revoked"
    );

    let active = sessions::list(&mut conn, &filter, Some(Utc::now()), None, 10)
        .await
        .unwrap();
    assert_eq!(active.iter().map(|s| s.id).collect::<Vec<_>>(), vec![keep]);
    let all = sessions::list(&mut conn, &filter, None, None, 10)
        .await
        .unwrap();
    assert_eq!(all.len(), 2, "revoked sessions stay listable");
}

// r[verify token.keys.rotation-overlap]
// r[verify token.keys.break-glass]
#[tokio::test(flavor = "multi_thread")]
async fn configured_keys_rotate_and_can_be_revoked() {
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    let k1 = ("k1".to_string(), vec![1u8; 32]);
    let k2 = ("k2".to_string(), vec![2u8; 32]);

    let keys = signing_keys::sync_configured(&mut conn, std::slice::from_ref(&k1), "k1")
        .await
        .unwrap();
    assert!(keys[0].is_active());

    // Publish k2 ahead of activating it.
    let keys = signing_keys::sync_configured(&mut conn, &[k1.clone(), k2.clone()], "k1")
        .await
        .unwrap();
    assert!(
        keys.iter()
            .find(|k| k.kid == "k2")
            .unwrap()
            .activated_at
            .is_none()
    );

    // Activate k2: k1 retires but stays published.
    let keys = signing_keys::sync_configured(&mut conn, std::slice::from_ref(&k2), "k2")
        .await
        .unwrap();
    let k1_row = keys.iter().find(|k| k.kid == "k1").unwrap();
    assert!(k1_row.retired_at.is_some() && k1_row.revoked_at.is_none());
    assert!(keys.iter().find(|k| k.kid == "k2").unwrap().is_active());

    assert!(signing_keys::revoke(&mut conn, "k2").await.unwrap());
    assert!(!signing_keys::revoke(&mut conn, "k2").await.unwrap());
    assert!(matches!(
        signing_keys::revoke(&mut conn, "nope").await,
        Err(StoreError::NotFound)
    ));
    // A revoked key is never reactivated by configuration.
    let keys = signing_keys::sync_configured(&mut conn, &[k2], "k2")
        .await
        .unwrap();
    assert!(!keys.iter().find(|k| k.kid == "k2").unwrap().is_active());

    let kinds = event_kinds(&mut conn).await;
    assert_eq!(
        kinds
            .iter()
            .filter(|k| *k == "signing_keys.changed")
            .count(),
        4,
        "publish k1, publish k2, rotate, revoke; the no-op sync emits nothing"
    );
}
