// @generated automatically by Diesel CLI.

diesel::table! {
    catalog_action (name) {
        name -> Text,
        description -> Text,
        group_definition -> Nullable<Jsonb>,
    }
}

diesel::table! {
    catalog_fact (target, key) {
        key -> Text,
        target -> Text,
        value_type -> Text,
        portable -> Bool,
        description -> Text,
    }
}

diesel::table! {
    catalog_scope_kind (name) {
        name -> Text,
        description -> Text,
    }
}

diesel::table! {
    catalog_session_flag (name) {
        name -> Text,
        kind -> Text,
        requestable -> Bool,
        description -> Text,
    }
}

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
    feed_watermark (singleton) {
        singleton -> Bool,
        pruned_through -> Int8,
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
    membership (id) {
        id -> Uuid,
        subject_id -> Uuid,
        tenant_id -> Uuid,
        state -> Text,
        facts -> Jsonb,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    role (id) {
        id -> Uuid,
        tenant_id -> Uuid,
        key -> Text,
        template_id -> Nullable<Uuid>,
        priority -> Int4,
        metadata -> Jsonb,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    role_assignment (id) {
        id -> Uuid,
        role_id -> Uuid,
        membership_id -> Nullable<Uuid>,
        subject_id -> Nullable<Uuid>,
        scope_kind -> Nullable<Text>,
        scope_id -> Nullable<Text>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    role_policy (role_id, action) {
        role_id -> Uuid,
        action -> Text,
        effect -> Text,
        scope_bound -> Bool,
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

diesel::table! {
    template (id) {
        id -> Uuid,
        key -> Text,
        description -> Text,
        metadata -> Jsonb,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    template_policy (template_id, action) {
        template_id -> Uuid,
        action -> Text,
        effect -> Text,
        scope_bound -> Bool,
    }
}

diesel::table! {
    tenant (id) {
        id -> Uuid,
        parent_id -> Nullable<Uuid>,
        state -> Text,
        facts -> Jsonb,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::joinable!(credential -> subject (subject_id));
diesel::joinable!(membership -> subject (subject_id));
diesel::joinable!(membership -> tenant (tenant_id));
diesel::joinable!(role -> template (template_id));
diesel::joinable!(role -> tenant (tenant_id));
diesel::joinable!(role_assignment -> catalog_scope_kind (scope_kind));
diesel::joinable!(role_assignment -> membership (membership_id));
diesel::joinable!(role_assignment -> role (role_id));
diesel::joinable!(role_assignment -> subject (subject_id));
diesel::joinable!(role_policy -> catalog_action (action));
diesel::joinable!(role_policy -> role (role_id));
diesel::joinable!(session -> credential (credential_id));
diesel::joinable!(session -> membership (membership_id));
diesel::joinable!(session -> tenant (tenant_id));
diesel::joinable!(session_previous_refresh -> session (session_id));
diesel::joinable!(template_policy -> catalog_action (action));
diesel::joinable!(template_policy -> template (template_id));

diesel::allow_tables_to_appear_in_same_query!(
    catalog_action,
    catalog_fact,
    catalog_scope_kind,
    catalog_session_flag,
    credential,
    event,
    feed_watermark,
    login_attempt,
    membership,
    role,
    role_assignment,
    role_policy,
    session,
    session_previous_refresh,
    signing_key,
    subject,
    template,
    template_policy,
    tenant,
);
