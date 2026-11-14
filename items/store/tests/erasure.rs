#![allow(clippy::too_many_lines)]

use chrono::{Duration, Utc};
use diesel::sql_types::{BigInt, Text};
use diesel_async::{AsyncConnection, RunQueryDsl};
use konklav_core::{CredentialId, MembershipId, SessionId, SubjectId, TenantId};
use konklav_store::challenges::{self, NewChallenge, Purpose};
use konklav_store::credentials::{
    self, CredentialData, CredentialKind, FederatedData, NewCredential, PasswordData,
};
use konklav_store::metadata::{self, Object};
use konklav_store::mfa::{self, EmailCodeData, FactorData};
use konklav_store::personal_data::PersonalData;
use konklav_store::roles::{self, AssignmentTarget, RoleDefinition};
use konklav_store::sessions::{self, ClientKind, NewSession, SessionFilter, Stage};
use konklav_store::subjects::{self, SubjectKind, SubjectState};
use konklav_store::tenants::{self, ROOT};
use konklav_store::{
    Connection, StoreError, batch_results, events, history, login_attempts, memberships,
    oidc_clients, personal_data,
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
    metadata: String,
    earlier_metadata: String,
    invite_metadata: String,
    credential: CredentialId,
    membership: MembershipId,
}

impl Person {
    fn needles(&self) -> [&str; 11] {
        [
            &self.email,
            &self.provider_subject,
            &self.provider_email,
            &self.factor_email,
            &self.phone,
            &self.fact,
            &self.earlier_fact,
            &self.thumbprint,
            &self.metadata,
            &self.earlier_metadata,
            &self.invite_metadata,
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
            metadata: metadata::empty(),
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
        metadata: format!("{name}-current-metadata"),
        earlier_metadata: format!("{name}-earlier-metadata"),
        invite_metadata: format!("{name}-invite-metadata"),
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
            metadata: metadata::empty(),
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
            metadata: metadata::empty(),
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

    // Metadata on the subject, a credential and the membership, written
    // twice: the earlier value lives on in history and in stored events.
    for (object, object_id) in [
        (Object::Subject, id.to_string()),
        (Object::Credential, person.credential.to_string()),
        (Object::Membership, person.membership.to_string()),
    ] {
        for value in [&person.earlier_metadata, &person.metadata] {
            metadata::write(conn, object, &object_id, &json!({"note": value}))
                .await
                .unwrap();
        }
    }
    // A link-only invite the person redeemed: nothing on the challenge
    // names them, only the event does.
    let mut invite = challenge(None, "");
    invite.purpose = Purpose::Invite;
    let invite_metadata = json!({"for": person.invite_metadata});
    let invite = challenges::create_with_metadata(conn, invite, &invite_metadata)
        .await
        .unwrap();
    events::append(
        conn,
        "invite.redeemed",
        json!({
            "invite": invite.id,
            "subject": id,
            "tenant": tenant,
            "membership": person.membership,
            "metadata": invite_metadata,
        }),
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

    assert_eq!(erased.metadata, json!({}));

    let membership = memberships::get(&mut conn, ada.membership).await.unwrap();
    assert!(!membership.is_active());
    assert_eq!(membership.facts, json!({}));
    assert_eq!(membership.metadata, json!({}));
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
                metadata: metadata::empty(),
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

/// How many rows of each kind a personal data read holds.
fn amounts(held: &PersonalData) -> [usize; 7] {
    [
        held.credentials.len(),
        held.mfa_factors.len(),
        held.memberships.len(),
        held.role_assignments.len(),
        held.sessions.len(),
        held.challenges.len(),
        held.login_attempts.len(),
    ]
}

// r[verify subject.report.contents]
// r[verify subject.report.erased]
#[tokio::test(flavor = "multi_thread")]
async fn the_personal_data_read_finds_what_erasure_removes_and_no_one_elses() {
    let db = TestDatabase::new().await;
    let (ada, grace) = seeded(&db, true).await;
    let mut conn = db.pool().get().await.unwrap();

    let held = personal_data::of(&mut conn, ada.id).await.unwrap();
    assert_eq!(held.subject.id, ada.id);
    let text = format!("{held:?}");
    // Facts and metadata from earlier are in history and stored events
    // only, which the read leaves out.
    for needle in ada.needles() {
        assert_eq!(
            text.contains(needle),
            needle != ada.earlier_fact && needle != ada.earlier_metadata,
            "{needle} in the personal data"
        );
    }
    for needle in grace.needles() {
        assert!(!text.contains(needle), "{needle} is someone else's");
    }
    assert!(
        amounts(&held).iter().all(|held| *held > 0),
        "{:?}",
        amounts(&held)
    );

    // A removed factor is still held, so it is still read.
    let factor = held.mfa_factors[0].id;
    assert!(mfa::remove(&mut conn, ada.id, factor).await.unwrap());
    let held = personal_data::of(&mut conn, ada.id).await.unwrap();
    assert!(held.mfa_factors[0].removed_at.is_some());

    subjects::erase(&mut conn, ada.id).await.unwrap();
    let held = personal_data::of(&mut conn, ada.id).await.unwrap();
    assert_eq!(held.subject.state, SubjectState::Erased);
    assert!(held.subject.erased_at.is_some());
    assert_eq!(amounts(&held), [0; 7]);

    let unknown = personal_data::of(&mut conn, SubjectId::new_v7()).await;
    assert!(matches!(unknown, Err(StoreError::NotFound)));
}

/// What was decided for every column of one table, for erasure and for the
/// personal data report together.
struct Table {
    name: &'static str,
    /// No personal data: identifiers Konklav made, times, states, settings
    /// and catalog data. Erasure may leave these, and the report may show
    /// them.
    plain: &'static [&'static str],
    /// Personal data. Erasure removes it and the report shows it.
    personal: &'static [&'static str],
    /// Personal data or a secret that erasure removes and the report leaves
    /// out, each with the reason.
    unreported: &'static [(&'static str, &'static str)],
}

/// A decision for every column of the database. Adding a column fails
/// [`every_column_has_a_decision_for_erasure_and_the_report`] until it is
/// listed here, which is the moment to decide whether `subjects::erase`
/// and `personal_data::of` must handle it.
const DECISIONS: &[Table] = &[
    Table {
        name: "__diesel_schema_migrations",
        plain: &["version", "run_on"],
        personal: &[],
        unreported: &[],
    },
    Table {
        name: "backchannel_logout",
        plain: &[
            "id",
            "client_id",
            "session_id",
            "subject_id",
            "attempts",
            "next_attempt_at",
            "last_error",
            "created_at",
        ],
        personal: &[],
        unreported: &[],
    },
    // `caller` is `subject:<id>`, an identifier.
    Table {
        name: "batch_result",
        plain: &["caller", "key", "request_hash", "created_at", "expires_at"],
        personal: &[],
        unreported: &[(
            "answer",
            "a remembered copy of an answer the caller already got, kept for a short time",
        )],
    },
    Table {
        name: "bearer_assertion",
        plain: &["issuer", "jti", "expires_at"],
        personal: &[],
        unreported: &[],
    },
    Table {
        name: "catalog_action",
        plain: &["name", "description", "group_definition", "builtin"],
        personal: &[],
        unreported: &[],
    },
    Table {
        name: "catalog_fact",
        plain: &["key", "target", "value_type", "portable", "description"],
        personal: &[],
        unreported: &[],
    },
    Table {
        name: "catalog_scope_kind",
        plain: &["name", "description", "registered"],
        personal: &[],
        unreported: &[],
    },
    Table {
        name: "catalog_session_flag",
        plain: &["name", "kind", "requestable", "description", "confine"],
        personal: &[],
        unreported: &[],
    },
    Table {
        name: "catalog_vouch",
        plain: &["action", "vouched"],
        personal: &[],
        unreported: &[],
    },
    Table {
        name: "challenge",
        plain: &[
            "id",
            "purpose",
            "subject_id",
            "credential_id",
            "mfa_factor_id",
            "session_id",
            "attempts",
            "max_attempts",
            "created_at",
            "expires_at",
            "consumed_at",
            "revoked_at",
        ],
        personal: &["recipient", "metadata"],
        unreported: &[
            ("secret_hash", "a secret"),
            (
                "details",
                "challenge material, such as a PKCE challenge or a nonce",
            ),
        ],
    },
    Table {
        name: "client_assertion",
        plain: &["client_id", "jti", "expires_at"],
        personal: &[],
        unreported: &[],
    },
    // `data` is reported in part: a federated identity and a passkey's label,
    // never a hash or key material.
    Table {
        name: "credential",
        plain: &[
            "id",
            "subject_id",
            "kind",
            "mfa_factors_required",
            "replaces",
            "created_at",
            "updated_at",
            "revoked_at",
            "revoked_reason",
            "break_glass",
            "session_flags",
        ],
        personal: &["identifier", "data", "metadata"],
        unreported: &[],
    },
    Table {
        name: "dpop_proof",
        plain: &["jkt", "jti", "expires_at"],
        personal: &[],
        unreported: &[],
    },
    // Payloads of other kinds hold identifiers only.
    Table {
        name: "event",
        plain: &["cursor", "kind", "created_at"],
        personal: &[],
        unreported: &[(
            "payload",
            "a `delivery.requested` payload repeats a challenge's recipient, which the report shows, with its material; `metadata.changed` and `invite.redeemed` payloads hold metadata the report shows where it still holds",
        )],
    },
    Table {
        name: "feed_watermark",
        plain: &["singleton", "pruned_through"],
        personal: &[],
        unreported: &[],
    },
    Table {
        name: "history_setting",
        plain: &["only_row", "enabled_at", "retention"],
        personal: &[],
        unreported: &[],
    },
    Table {
        name: "history_table",
        plain: &["relation", "key_columns"],
        personal: &[],
        unreported: &[],
    },
    // Attempts by address alone can't be tied to a subject and stay until
    // the rate-limit window passes.
    Table {
        name: "login_attempt",
        plain: &["id", "kind", "succeeded", "attempted_at"],
        personal: &["identifier", "address"],
        unreported: &[],
    },
    Table {
        name: "membership",
        plain: &[
            "id",
            "subject_id",
            "tenant_id",
            "state",
            "created_at",
            "updated_at",
            "managed_by",
        ],
        personal: &["facts", "metadata"],
        unreported: &[],
    },
    // `data` is reported in part: an email factor's address, never a seed.
    Table {
        name: "mfa_factor",
        plain: &[
            "id",
            "subject_id",
            "kind",
            "active",
            "created_at",
            "updated_at",
            "removed_at",
        ],
        personal: &["data"],
        unreported: &[],
    },
    Table {
        name: "oidc_client",
        plain: &[
            "id",
            "kind",
            "secret_hash",
            "redirect_uris",
            "scopes",
            "audience",
            "visible_groups",
            "login_url",
            "id_token_alg",
            "refresh",
            "disabled_at",
            "created_at",
            "updated_at",
            "service_subject_id",
            "jwks",
            "post_logout_redirect_uris",
            "backchannel_logout_uri",
            "require_pkce",
            "require_dpop",
            "metadata",
        ],
        personal: &[],
        unreported: &[],
    },
    Table {
        name: "peer_cursor",
        plain: &["provider", "cursor", "updated_at"],
        personal: &[],
        unreported: &[],
    },
    Table {
        name: "registered_scope",
        plain: &[
            "kind",
            "id",
            "tenant_id",
            "containers",
            "state",
            "created_at",
            "updated_at",
            "kind_registered",
        ],
        personal: &[],
        unreported: &[],
    },
    Table {
        name: "role",
        plain: &[
            "id",
            "tenant_id",
            "key",
            "template_id",
            "priority",
            "metadata",
            "created_at",
            "updated_at",
            "builtin",
        ],
        personal: &[],
        unreported: &[],
    },
    Table {
        name: "role_assignment",
        plain: &[
            "id",
            "role_id",
            "membership_id",
            "subject_id",
            "scope_kind",
            "scope_id",
            "created_at",
            "managed_by",
            "scope_kind_registered",
        ],
        personal: &[],
        unreported: &[],
    },
    Table {
        name: "role_policy",
        plain: &["role_id", "action", "effect", "scope_bound"],
        personal: &[],
        unreported: &[],
    },
    // Memberships' versions hold facts and metadata, subjects' metadata.
    Table {
        name: "row_version",
        plain: &["id", "relation", "key", "valid_from", "valid_until"],
        personal: &[],
        unreported: &[(
            "data",
            "facts and metadata from earlier; the report shows what holds now",
        )],
    },
    // Erasure revokes the sessions and clears the two personal columns; the
    // rows go when session retention allows.
    Table {
        name: "session",
        plain: &[
            "id",
            "subject_id",
            "credential_id",
            "tenant_id",
            "membership_id",
            "stage",
            "client_kind",
            "amr",
            "auth_time",
            "flags",
            "impersonator_subject_id",
            "version",
            "refresh_hash",
            "created_at",
            "updated_at",
            "expires_at",
            "revoked_at",
            "revoked_reason",
            "mfa_factors",
            "parent_session_id",
            "oidc_client_id",
            "oidc_scopes",
            "oidc_userinfo_claims",
            "oidc_id_token_claims",
        ],
        personal: &["identity_claims", "dpop_jkt"],
        unreported: &[],
    },
    Table {
        name: "session_previous_refresh",
        plain: &["session_id", "refresh_hash", "rotated_at"],
        personal: &[],
        unreported: &[],
    },
    Table {
        name: "share",
        plain: &[
            "id",
            "owner_tenant_id",
            "scope_kind",
            "scope_id",
            "recipient_tenant_id",
            "recipient_scope_kind",
            "recipient_scope_id",
            "attributes",
            "valid_from",
            "valid_until",
            "state",
            "accepted_at",
            "revoked_at",
            "revoked_by",
            "created_at",
            "updated_at",
            "metadata",
        ],
        personal: &[],
        unreported: &[],
    },
    Table {
        name: "share_action",
        plain: &["share_id", "action"],
        personal: &[],
        unreported: &[],
    },
    Table {
        name: "signing_key",
        plain: &[
            "kid",
            "algorithm",
            "public_key",
            "published_at",
            "activated_at",
            "retired_at",
            "revoked_at",
        ],
        personal: &[],
        unreported: &[],
    },
    Table {
        name: "subject",
        plain: &[
            "id",
            "kind",
            "state",
            "created_at",
            "updated_at",
            "erased_at",
        ],
        personal: &["metadata"],
        unreported: &[],
    },
    Table {
        name: "template",
        plain: &[
            "id",
            "key",
            "description",
            "metadata",
            "created_at",
            "updated_at",
        ],
        personal: &[],
        unreported: &[],
    },
    Table {
        name: "template_policy",
        plain: &["template_id", "action", "effect", "scope_bound"],
        personal: &[],
        unreported: &[],
    },
    // Tenant facts and metadata describe a tenant, not a subject
    // (`subject.erasure.removes`).
    Table {
        name: "tenant",
        plain: &[
            "id",
            "parent_id",
            "state",
            "facts",
            "created_at",
            "updated_at",
            "metadata",
        ],
        personal: &[],
        unreported: &[],
    },
];

// r[verify subject.report.complete]
#[tokio::test(flavor = "multi_thread")]
async fn every_column_has_a_decision_for_erasure_and_the_report() {
    #[derive(diesel::QueryableByName)]
    struct Found {
        #[diesel(sql_type = Text)]
        table_name: String,
        #[diesel(sql_type = Text)]
        column_name: String,
    }
    let db = TestDatabase::new().await;
    let mut conn = db.pool().get().await.unwrap();
    let found: Vec<(String, String)> = diesel::sql_query(
        "select c.table_name::text, c.column_name::text
         from information_schema.columns c
         join information_schema.tables t using (table_schema, table_name)
         where c.table_schema = 'public' and t.table_type = 'BASE TABLE'
         order by 1, c.ordinal_position",
    )
    .get_results::<Found>(&mut conn)
    .await
    .unwrap()
    .into_iter()
    .map(|found| (found.table_name, found.column_name))
    .collect();
    let decided: Vec<(String, String)> = DECISIONS
        .iter()
        .flat_map(|table| {
            let unreported = table.unreported.iter().map(|(column, _)| column);
            table
                .plain
                .iter()
                .chain(table.personal)
                .chain(unreported)
                .map(|column| (table.name.to_owned(), (*column).to_owned()))
        })
        .collect();

    let undecided: Vec<_> = found.iter().filter(|c| !decided.contains(c)).collect();
    assert!(
        undecided.is_empty(),
        "columns without a decision in DECISIONS; decide whether erasure must remove \
         them and whether the personal data report must show them: {undecided:?}"
    );
    let gone: Vec<_> = decided.iter().filter(|c| !found.contains(c)).collect();
    assert!(
        gone.is_empty(),
        "DECISIONS lists columns that don't exist: {gone:?}"
    );

    let mut twice = decided.clone();
    twice.sort();
    twice.dedup();
    assert_eq!(twice.len(), decided.len(), "a column is listed twice");
    for table in DECISIONS {
        for (column, reason) in table.unreported {
            assert!(
                !reason.is_empty(),
                "{}.{column} needs its reason",
                table.name
            );
        }
    }
}
