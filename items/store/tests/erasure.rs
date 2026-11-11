#![allow(clippy::too_many_lines)]

use chrono::{Duration, Utc};
use diesel::sql_types::{BigInt, Text};
use diesel_async::{AsyncConnection, RunQueryDsl};
use konklav_core::{CredentialId, MembershipId, SessionId, SubjectId, TenantId};
use konklav_store::challenges::{self, NewChallenge, Purpose};
use konklav_store::credentials::{
    self, CredentialData, CredentialKind, FederatedData, NewCredential, PasswordData,
};
use konklav_store::mfa::{self, EmailCodeData, FactorData};
use konklav_store::roles::{self, AssignmentTarget, RoleDefinition};
use konklav_store::sessions::{self, ClientKind, NewSession, SessionFilter, Stage};
use konklav_store::subjects::{self, SubjectKind, SubjectState};
use konklav_store::tenants::{self, ROOT};
use konklav_store::{
    Connection, StoreError, batch_results, events, history, login_attempts, memberships,
    oidc_clients,
};
use konklav_test_support::TestDatabase;
use serde_json::json;

const HASH: &str = "$argon2id$v=19$m=8,t=1,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNo";

/// Everything one seeded person is known by. Each value is unique to the
/// person, so finding it anywhere means their data is there.
struct Person {
    id: SubjectId,
    email: String,
    provider_subject: String,
    provider_email: String,
    factor_email: String,
    phone: String,
    fact: String,
    earlier_fact: String,
    claim: String,
    thumbprint: String,
    credential: CredentialId,
    membership: MembershipId,
}

impl Person {
    fn needles(&self) -> [&str; 8] {
        [
            &self.email,
            &self.provider_subject,
            &self.provider_email,
            &self.factor_email,
            &self.phone,
            &self.fact,
            &self.earlier_fact,
            &self.thumbprint,
        ]
    }
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

fn new_session(subject: SubjectId, credential: CredentialId, thumbprint: &str) -> NewSession {
    NewSession {
        id: SessionId::new_v7(),
        subject_id: subject,
        credential_id: credential,
        stage: Stage::Identity,
        client_kind: ClientKind::Native,
        amr: vec!["pwd".into()],
        auth_time: Utc::now(),
        flags: vec![],
        impersonator_subject_id: None,
        parent_session_id: None,
        refresh_hash: thumbprint.as_bytes().to_vec(),
        expires_at: Utc::now() + Duration::hours(1),
        dpop_jkt: Some(thumbprint.into()),
    }
}

fn challenge(subject: Option<SubjectId>, recipient: &str) -> NewChallenge {
    NewChallenge {
        id: uuid::Uuid::now_v7(),
        purpose: Purpose::EmailLink,
        subject_id: subject,
        credential_id: None,
        mfa_factor_id: None,
        session_id: None,
        recipient: recipient.into(),
        secret_hash: vec![1, 2, 3],
        details: json!({}),
        expires_at: Utc::now() + Duration::minutes(10),
    }
}

async fn delivery(conn: &mut Connection, subject: Option<SubjectId>, recipient: &str) {
    events::append(
        conn,
        "delivery.requested",
        json!({
            "channel": "email",
            "recipient": recipient,
            "purpose": "email_link",
            "subject": subject,
            "material": {"code": "123456"},
            "expires_at": (Utc::now() + Duration::minutes(10)).timestamp(),
        }),
    )
    .await
    .unwrap();
}

/// Seeds a person with one of everything Konklav can hold about a subject.
async fn person(conn: &mut Connection, tenant: TenantId, name: &str) -> Person {
    let id = SubjectId::new_v7();
    subjects::create(conn, id, SubjectKind::Human)
        .await
        .unwrap();
    let mut person = Person {
        id,
        email: format!("{name}@login.example"),
        provider_subject: format!("{name}-at-the-provider"),
        provider_email: format!("{name}@provider.example"),
        factor_email: format!("{name}@factor.example"),
        phone: format!("+4670{:07}", name.len() * 1_234_567 % 10_000_000),
        fact: format!("{name}-current-fact"),
        earlier_fact: format!("{name}-earlier-fact"),
        claim: format!("{name} Lovelace"),
        thumbprint: format!("{name}-key-thumbprint"),
        credential: CredentialId::new_v7(),
        membership: MembershipId::new_v7(),
    };

    person.credential = password(conn, id, &person.email).await;
    credentials::insert(
        conn,
        NewCredential {
            id: CredentialId::new_v7(),
            subject_id: id,
            identifier: credentials::federated_identifier("corp", &person.provider_subject),
            data: CredentialData::Federated(FederatedData {
                provider: "corp".into(),
                subject: person.provider_subject.clone(),
                email: Some(person.provider_email.clone()),
                email_verified: Some(true),
            }),
            mfa_factors_required: 0,
            replaces: None,
        },
    )
    .await
    .unwrap();
    credentials::insert(
        conn,
        NewCredential {
            id: CredentialId::new_v7(),
            subject_id: id,
            identifier: person.phone.clone(),
            data: CredentialData::PhoneOtp,
            mfa_factors_required: 0,
            replaces: None,
        },
    )
    .await
    .unwrap();
    let factor = mfa::create(
        conn,
        id,
        &FactorData::EmailCode(EmailCodeData {
            email: person.factor_email.clone(),
        }),
    )
    .await
    .unwrap();

    // The earlier fact only lives on in history once it is replaced.
    memberships::create(
        conn,
        person.membership,
        id,
        tenant,
        &json!({"note": person.earlier_fact}),
    )
    .await
    .unwrap();
    memberships::set_facts(conn, person.membership, &json!({"note": person.fact}))
        .await
        .unwrap();
    let global = roles::put(conn, ROOT, "auditor", &RoleDefinition::default())
        .await
        .unwrap();
    roles::assign(conn, global.id, AssignmentTarget::Subject(id), None)
        .await
        .unwrap();
    let member = roles::put(conn, tenant, "member", &RoleDefinition::default())
        .await
        .unwrap();
    roles::assign(
        conn,
        member.id,
        AssignmentTarget::Membership(person.membership),
        None,
    )
    .await
    .unwrap();

    let (session, _) =
        sessions::insert(conn, new_session(id, person.credential, &person.thumbprint))
            .await
            .unwrap();
    diesel::sql_query("update session set identity_claims = $1::jsonb where id = $2::uuid")
        .bind::<Text, _>(json!({"profile": {"name": person.claim}}).to_string())
        .bind::<Text, _>(session.id.to_string())
        .execute(conn)
        .await
        .unwrap();

    let mut for_factor = challenge(Some(id), &person.factor_email);
    for_factor.mfa_factor_id = Some(factor.id);
    for_factor.session_id = Some(session.id);
    challenges::create(conn, for_factor).await.unwrap();
    // Sent before anyone knew whose address it was, such as an invite.
    challenges::create(conn, challenge(None, &person.email))
        .await
        .unwrap();
    delivery(conn, Some(id), &person.factor_email).await;
    delivery(conn, None, &person.email).await;

    login_attempts::begin(conn, CredentialKind::Password, &person.email, None)
        .await
        .unwrap();
    login_attempts::record_totp(conn, factor.id, false)
        .await
        .unwrap();
    let now = Utc::now();
    batch_results::remember(
        conn,
        "bootstrap",
        &format!("created-{name}"),
        &batch_results::Remembered {
            request_hash: vec![7],
            answer: json!({"results": [{"status": 201, "body": {"identifier": person.email}}]}),
        },
        now,
        now + Duration::hours(1),
    )
    .await
    .unwrap();
    person
}

/// How many rows, in any table, hold `needle` in any column.
async fn rows_holding(conn: &mut Connection, needle: &str) -> Vec<(String, i64)> {
    #[derive(diesel::QueryableByName)]
    struct Table {
        #[diesel(sql_type = Text)]
        name: String,
    }
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = BigInt)]
        rows: i64,
    }
    let tables = diesel::sql_query(
        "select table_name::text as name from information_schema.tables
         where table_schema = 'public' and table_type = 'BASE TABLE' order by 1",
    )
    .get_results::<Table>(conn)
    .await
    .unwrap();
    let mut found = Vec::new();
    for table in tables {
        // Bytes are compared as text too, since a session's refresh hash
        // is seeded from the thumbprint.
        let count = diesel::sql_query(format!(
            "select count(*) as rows from \"{0}\" t
             where strpos(to_jsonb(t)::text, to_jsonb($1::text)::text) > 0
                or strpos(to_jsonb(t)::text, trim(both '\"' from to_jsonb($1::text)::text)) > 0",
            table.name
        ))
        .bind::<Text, _>(needle)
        .get_result::<Count>(conn)
        .await
        .unwrap();
        if count.rows > 0 {
            found.push((table.name, count.rows));
        }
    }
    found
}

async fn seeded(db: &TestDatabase, with_history: bool) -> (Person, Person) {
    let mut conn = db.pool().get().await.unwrap();
    if with_history {
        history::configure(&mut conn, Some(Duration::days(30)))
            .await
            .unwrap();
    }
    let tenant = TenantId::new_v7();
    tenants::create(&mut conn, tenant, ROOT, &json!({}))
        .await
        .unwrap();
    let ada = person(&mut conn, tenant, "ada").await;
    let grace = person(&mut conn, tenant, "grace").await;
    (ada, grace)
}

// r[verify subject.erasure.removes]
// r[verify subject.erasure.history]
// r[verify subject.erasure.tombstone]
#[tokio::test(flavor = "multi_thread")]
async fn erasure_leaves_no_personal_data_and_touches_no_one_else() {
    let db = TestDatabase::new().await;
    let (ada, grace) = seeded(&db, true).await;
    let mut conn = db.pool().get().await.unwrap();

    // The scan sees what it is meant to find.
    for needle in ada.needles() {
        assert!(
            !rows_holding(&mut conn, needle).await.is_empty(),
            "{needle} should be stored before erasure"
        );
    }
    assert!(
        rows_holding(&mut conn, &ada.earlier_fact)
            .await
            .iter()
            .all(|(table, _)| table == "row_version"),
        "the replaced fact is only in history"
    );

    let erasure = subjects::erase(&mut conn, ada.id).await.unwrap();

    for needle in ada.needles().into_iter().chain([ada.claim.as_str()]) {
        assert_eq!(
            rows_holding(&mut conn, needle).await,
            vec![],
            "{needle} is still stored after erasure"
        );
    }
    for needle in grace.needles().into_iter().chain([grace.claim.as_str()]) {
        assert!(
            !rows_holding(&mut conn, needle).await.is_empty(),
            "{needle} belongs to someone else and should be untouched"
        );
    }

    let erased = subjects::get(&mut conn, ada.id).await.unwrap();
    assert_eq!(erased, erasure.subject);
    assert_eq!(erased.state, SubjectState::Erased);
    assert_eq!(erased.kind, SubjectKind::Human);
    assert!(erased.erased_at.is_some());

    let kept = sessions::list(
        &mut conn,
        &SessionFilter {
            subject: Some(ada.id),
            ..SessionFilter::default()
        },
        None,
        None,
        100,
    )
    .await
    .unwrap();
    assert_eq!(kept.len(), 1, "the ended session is kept for retention");
    assert_eq!(kept[0].revoked_reason.as_deref(), Some("subject_erased"));
    assert_eq!(kept[0].credential_id, None);
    assert_eq!(kept[0].identity_claims, None);
    assert_eq!(kept[0].dpop_jkt, None);

    let membership = memberships::get(&mut conn, ada.membership).await.unwrap();
    assert!(!membership.is_active());
    assert_eq!(membership.facts, json!({}));
    assert_eq!(
        roles::assignments_of_membership(&mut conn, ada.membership)
            .await
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        roles::global_assignments_of(&mut conn, ada.id)
            .await
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        credentials::list_for_subject(&mut conn, ada.id)
            .await
            .unwrap()
            .len(),
        0
    );
    assert_eq!(mfa::list(&mut conn, ada.id).await.unwrap().len(), 0);

    assert!(
        memberships::get(&mut conn, grace.membership)
            .await
            .unwrap()
            .is_active()
    );
    assert_eq!(
        credentials::list_for_subject(&mut conn, grace.id)
            .await
            .unwrap()
            .len(),
        3
    );
}

// r[verify subject.erasure.removes]
#[tokio::test(flavor = "multi_thread")]
async fn erasure_works_with_history_disabled() {
    let db = TestDatabase::new().await;
    let (ada, _) = seeded(&db, false).await;
    let mut conn = db.pool().get().await.unwrap();
    subjects::erase(&mut conn, ada.id).await.unwrap();
    for needle in ada.needles() {
        assert_eq!(rows_holding(&mut conn, needle).await, vec![], "{needle}");
    }
}

// r[verify subject.erasure.event]
// r[verify feed.subject-erased]
#[tokio::test(flavor = "multi_thread")]
async fn erasure_ends_with_one_event_that_names_only_the_subject() {
    let db = TestDatabase::new().await;
    let (ada, _) = seeded(&db, false).await;
    let mut conn = db.pool().get().await.unwrap();
    let before = events::head(&mut conn).await.unwrap();

    let erasure = subjects::erase(&mut conn, ada.id).await.unwrap();

    let written = events::after(&mut conn, before, 1000).await.unwrap();
    let last = written.last().unwrap();
    assert_eq!(last.kind, "subject.erased");
    assert_eq!(
        Some(last.cursor),
        erasure.cursor.map(konklav_core::Cursor::get)
    );
    assert_eq!(
        last.payload,
        json!({
            "subject": ada.id,
            "erased_at": erasure.subject.erased_at.unwrap().timestamp(),
        })
    );
    let kinds = written.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>();
    assert_eq!(kinds.iter().filter(|k| **k == "subject.erased").count(), 1);
    assert!(kinds.contains(&"session.changed"));
    assert!(kinds.contains(&"entitlements.changed"));
}

// r[verify subject.erasure.idempotent]
#[tokio::test(flavor = "multi_thread")]
async fn erasing_an_erased_subject_changes_nothing() {
    let db = TestDatabase::new().await;
    let (ada, _) = seeded(&db, false).await;
    let mut conn = db.pool().get().await.unwrap();
    let first = subjects::erase(&mut conn, ada.id).await.unwrap();
    let head = events::head(&mut conn).await.unwrap();

    let second = subjects::erase(&mut conn, ada.id).await.unwrap();

    assert_eq!(second.subject, first.subject);
    assert_eq!(second.cursor, None);
    assert_eq!(events::head(&mut conn).await.unwrap(), head);
    assert!(matches!(
        subjects::erase(&mut conn, SubjectId::new_v7()).await,
        Err(StoreError::NotFound)
    ));
}

// r[verify subject.erasure.atomic]
#[tokio::test(flavor = "multi_thread")]
async fn an_erasure_that_is_rolled_back_changes_nothing() {
    let db = TestDatabase::new().await;
    let (ada, _) = seeded(&db, true).await;
    let mut conn = db.pool().get().await.unwrap();
    let head = events::head(&mut conn).await.unwrap();

    let result = conn
        .transaction::<(), StoreError, _>(async |conn| {
            subjects::erase(conn, ada.id).await?;
            Err(StoreError::Conflict("the caller changed its mind".into()))
        })
        .await;

    assert!(matches!(result, Err(StoreError::Conflict(_))));
    assert_eq!(
        subjects::get(&mut conn, ada.id).await.unwrap().state,
        SubjectState::Active
    );
    assert_eq!(events::head(&mut conn).await.unwrap(), head);
    for needle in ada.needles() {
        assert!(
            !rows_holding(&mut conn, needle).await.is_empty(),
            "{needle}"
        );
    }
}

#[track_caller]
fn refused_as_erased<T: std::fmt::Debug>(what: &str, result: &Result<T, StoreError>) {
    assert!(
        matches!(result, Err(StoreError::SubjectErased)),
        "{what}: {result:?}"
    );
}

// r[verify subject.erasure.blocks-writes]
// r[verify subject.erasure.tombstone]
// r[verify subject.state]
#[tokio::test(flavor = "multi_thread")]
async fn nothing_can_be_attached_to_an_erased_subject() {
    let db = TestDatabase::new().await;
    let (ada, grace) = seeded(&db, false).await;
    let mut conn = db.pool().get().await.unwrap();
    subjects::erase(&mut conn, ada.id).await.unwrap();

    refused_as_erased(
        "creating the subject again",
        &subjects::create(&mut conn, ada.id, SubjectKind::Human).await,
    );
    refused_as_erased(
        "creating it as another kind",
        &subjects::create(&mut conn, ada.id, SubjectKind::Service).await,
    );
    for state in [SubjectState::Active, SubjectState::Disabled] {
        refused_as_erased(
            "setting its state",
            &subjects::set_state(&mut conn, ada.id, state).await,
        );
    }
    refused_as_erased(
        "a credential",
        &credentials::insert(
            &mut conn,
            NewCredential {
                id: CredentialId::new_v7(),
                subject_id: ada.id,
                identifier: "again@login.example".into(),
                data: CredentialData::Password(PasswordData { hash: HASH.into() }),
                mfa_factors_required: 0,
                replaces: None,
            },
        )
        .await,
    );
    refused_as_erased(
        "an MFA factor",
        &mfa::create(
            &mut conn,
            ada.id,
            &FactorData::EmailCode(EmailCodeData {
                email: "again@factor.example".into(),
            }),
        )
        .await,
    );
    let tenant = memberships::get(&mut conn, grace.membership)
        .await
        .unwrap()
        .tenant_id;
    refused_as_erased(
        "a new membership",
        &memberships::create(
            &mut conn,
            MembershipId::new_v7(),
            ada.id,
            tenant,
            &json!({}),
        )
        .await,
    );
    refused_as_erased(
        "facts on its ended membership",
        &memberships::set_facts(&mut conn, ada.membership, &json!({"note": "back"})).await,
    );
    let global = roles::get(&mut conn, ROOT, "auditor").await.unwrap();
    refused_as_erased(
        "a global role assignment",
        &roles::assign(
            &mut conn,
            global.id,
            AssignmentTarget::Subject(ada.id),
            None,
        )
        .await,
    );
    let member = roles::get(&mut conn, tenant, "member").await.unwrap();
    refused_as_erased(
        "a role assignment at its ended membership",
        &roles::assign(
            &mut conn,
            member.id,
            AssignmentTarget::Membership(ada.membership),
            None,
        )
        .await,
    );
    refused_as_erased(
        "a challenge",
        &challenges::create(&mut conn, challenge(Some(ada.id), "again@login.example")).await,
    );
    refused_as_erased(
        "a session",
        &sessions::insert(&mut conn, new_session(ada.id, grace.credential, "again")).await,
    );
    let mut impersonation = new_session(grace.id, grace.credential, "again-as-grace");
    impersonation.impersonator_subject_id = Some(ada.id);
    refused_as_erased(
        "a session it impersonates someone in",
        &sessions::insert(&mut conn, impersonation).await,
    );

    // A statement over the whole tenant still passes: the erased subject's
    // membership stays ended and without facts.
    diesel::sql_query("update membership set updated_at = now()")
        .execute(&mut conn)
        .await
        .unwrap();
}

// r[verify subject.erasure.identifier-released]
#[tokio::test(flavor = "multi_thread")]
async fn an_erased_subjects_login_identifier_is_unknown_and_free() {
    let db = TestDatabase::new().await;
    let (ada, _) = seeded(&db, false).await;
    let mut conn = db.pool().get().await.unwrap();
    subjects::erase(&mut conn, ada.id).await.unwrap();

    assert_eq!(
        credentials::find_active(&mut conn, CredentialKind::Password, &ada.email)
            .await
            .unwrap(),
        None
    );

    let newcomer = SubjectId::new_v7();
    subjects::create(&mut conn, newcomer, SubjectKind::Human)
        .await
        .unwrap();
    password(&mut conn, newcomer, &ada.email).await;
    assert_eq!(
        credentials::find_active(&mut conn, CredentialKind::Password, &ada.email)
            .await
            .unwrap()
            .unwrap()
            .subject_id,
        newcomer
    );
}

// r[verify subject.erasure.removes]
#[tokio::test(flavor = "multi_thread")]
async fn erasing_an_impersonator_ends_the_sessions_it_started() {
    let db = TestDatabase::new().await;
    let (ada, grace) = seeded(&db, false).await;
    let mut conn = db.pool().get().await.unwrap();
    let mut as_grace = new_session(grace.id, ada.credential, "ada-acting-as-grace");
    as_grace.impersonator_subject_id = Some(ada.id);
    let (impersonation, _) = sessions::insert(&mut conn, as_grace).await.unwrap();

    subjects::erase(&mut conn, ada.id).await.unwrap();

    let ended = sessions::get(&mut conn, impersonation.id).await.unwrap();
    assert_eq!(ended.revoked_reason.as_deref(), Some("subject_erased"));
    assert_eq!(ended.credential_id, None, "it was Ada's credential");
    let graces = sessions::list(
        &mut conn,
        &SessionFilter {
            subject: Some(grace.id),
            ..SessionFilter::default()
        },
        None,
        None,
        100,
    )
    .await
    .unwrap();
    assert!(
        graces
            .iter()
            .any(|s| s.revoked_at.is_none() && s.dpop_jkt.is_some()),
        "Grace's own session goes on"
    );
}

// r[verify subject.erasure.bound-client]
#[tokio::test(flavor = "multi_thread")]
async fn a_service_principal_with_a_client_is_not_erased_until_the_client_is_disabled() {
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    let service = SubjectId::new_v7();
    subjects::create(&mut conn, service, SubjectKind::Service)
        .await
        .unwrap();
    let definition: oidc_clients::ClientDefinition = serde_json::from_value(json!({
        "kind": "confidential",
        "audience": "reports",
        "redirect_uris": ["https://reports.example/callback"],
        "service_subject": service,
    }))
    .unwrap();
    oidc_clients::put(&mut conn, "reports", &definition)
        .await
        .unwrap();

    assert!(matches!(
        subjects::erase(&mut conn, service).await,
        Err(StoreError::Conflict(_))
    ));
    assert_eq!(
        subjects::get(&mut conn, service).await.unwrap().state,
        SubjectState::Active
    );

    oidc_clients::disable(&mut conn, "reports").await.unwrap();
    subjects::erase(&mut conn, service).await.unwrap();

    // Registering the client again would enable it for an erased subject.
    assert!(matches!(
        oidc_clients::put(&mut conn, "reports", &definition).await,
        Err(StoreError::SubjectErased)
    ));
}
