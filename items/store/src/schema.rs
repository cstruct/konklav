// @generated automatically by Diesel CLI.

diesel::table! {
    credential (id) {
        id -> Uuid,
        subject_id -> Uuid,
        kind -> Text,
        identifier -> Text,
        data -> Jsonb,
        mfa_factors_required -> Int2,
        replaces -> Nullable<Uuid>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        revoked_at -> Nullable<Timestamptz>,
        revoked_reason -> Nullable<Text>,
    }
}

diesel::table! {
    event (cursor) {
        cursor -> Int8,
        kind -> Text,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    login_attempt (id) {
        id -> Int8,
        kind -> Text,
        identifier -> Text,
        succeeded -> Bool,
        attempted_at -> Timestamptz,
    }
}

diesel::table! {
    session (id) {
        id -> Uuid,
        subject_id -> Uuid,
        credential_id -> Uuid,
        tenant_id -> Nullable<Uuid>,
        membership_id -> Nullable<Uuid>,
        stage -> Text,
        client_kind -> Text,
        amr -> Array<Nullable<Text>>,
        auth_time -> Timestamptz,
        flags -> Array<Nullable<Text>>,
        impersonator_subject_id -> Nullable<Uuid>,
        version -> Int8,
        refresh_hash -> Bytea,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        expires_at -> Timestamptz,
        revoked_at -> Nullable<Timestamptz>,
        revoked_reason -> Nullable<Text>,
    }
}

diesel::table! {
    session_previous_refresh (session_id, refresh_hash) {
        session_id -> Uuid,
        refresh_hash -> Bytea,
        rotated_at -> Timestamptz,
    }
}

diesel::table! {
    signing_key (kid) {
        kid -> Text,
        algorithm -> Text,
        public_key -> Bytea,
        published_at -> Timestamptz,
        activated_at -> Nullable<Timestamptz>,
        retired_at -> Nullable<Timestamptz>,
        revoked_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    subject (id) {
        id -> Uuid,
        kind -> Text,
        state -> Text,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::joinable!(credential -> subject (subject_id));
diesel::joinable!(session -> credential (credential_id));
diesel::joinable!(session_previous_refresh -> session (session_id));

diesel::allow_tables_to_appear_in_same_query!(
    credential,
    event,
    login_attempt,
    session,
    session_previous_refresh,
    signing_key,
    subject,
);
