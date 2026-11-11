// @generated automatically by Diesel CLI.

diesel::table! {
    backchannel_logout (id) {
        id -> Uuid,
        client_id -> Text,
        session_id -> Uuid,
        subject_id -> Uuid,
        attempts -> Int4,
        next_attempt_at -> Timestamptz,
        last_error -> Nullable<Text>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    batch_result (caller, key) {
        caller -> Text,
        key -> Text,
        request_hash -> Bytea,
        answer -> Jsonb,
        created_at -> Timestamptz,
        expires_at -> Timestamptz,
    }
}

diesel::table! {
    bearer_assertion (issuer, jti) {
        issuer -> Text,
        jti -> Text,
        expires_at -> Timestamptz,
    }
}

diesel::table! {
    catalog_action (name) {
        name -> Text,
        description -> Text,
        group_definition -> Nullable<Jsonb>,
        builtin -> Bool,
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
        registered -> Bool,
    }
}

diesel::table! {
    catalog_session_flag (name) {
        name -> Text,
        kind -> Text,
        requestable -> Bool,
        description -> Text,
        confine -> Nullable<Jsonb>,
    }
}

diesel::table! {
    challenge (id) {
        id -> Uuid,
        purpose -> Text,
        subject_id -> Nullable<Uuid>,
        credential_id -> Nullable<Uuid>,
        mfa_factor_id -> Nullable<Uuid>,
        session_id -> Nullable<Uuid>,
        recipient -> Text,
        secret_hash -> Bytea,
        attempts -> Int4,
        max_attempts -> Int4,
        details -> Jsonb,
        created_at -> Timestamptz,
        expires_at -> Timestamptz,
        consumed_at -> Nullable<Timestamptz>,
        revoked_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    client_assertion (client_id, jti) {
        client_id -> Text,
        jti -> Text,
        expires_at -> Timestamptz,
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
        break_glass -> Bool,
        session_flags -> Array<Text>,
    }
}

diesel::table! {
    dpop_proof (jkt, jti) {
        jkt -> Text,
        jti -> Text,
        expires_at -> Timestamptz,
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
        address -> Nullable<Text>,
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
        managed_by -> Nullable<Text>,
    }
}

diesel::table! {
    mfa_factor (id) {
        id -> Uuid,
        subject_id -> Uuid,
        kind -> Text,
        data -> Jsonb,
        active -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        removed_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    oidc_client (id) {
        id -> Text,
        kind -> Text,
        secret_hash -> Nullable<Bytea>,
        redirect_uris -> Array<Nullable<Text>>,
        scopes -> Array<Nullable<Text>>,
        audience -> Text,
        visible_groups -> Array<Nullable<Text>>,
        login_url -> Nullable<Text>,
        id_token_alg -> Text,
        refresh -> Bool,
        disabled_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        service_subject_id -> Nullable<Uuid>,
        jwks -> Nullable<Jsonb>,
        post_logout_redirect_uris -> Array<Nullable<Text>>,
        backchannel_logout_uri -> Nullable<Text>,
        require_pkce -> Bool,
        require_dpop -> Bool,
    }
}

diesel::table! {
    peer_cursor (provider) {
        provider -> Text,
        cursor -> Int8,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    registered_scope (kind, id) {
        kind -> Text,
        id -> Text,
        tenant_id -> Uuid,
        containers -> Jsonb,
        state -> Text,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        kind_registered -> Bool,
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
        builtin -> Bool,
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
        managed_by -> Nullable<Text>,
        scope_kind_registered -> Bool,
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
        credential_id -> Nullable<Uuid>,
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
        mfa_factors -> Array<Nullable<Text>>,
        parent_session_id -> Nullable<Uuid>,
        oidc_client_id -> Nullable<Text>,
        oidc_scopes -> Array<Nullable<Text>>,
        oidc_userinfo_claims -> Array<Nullable<Text>>,
        oidc_id_token_claims -> Array<Nullable<Text>>,
        identity_claims -> Nullable<Jsonb>,
        dpop_jkt -> Nullable<Text>,
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
    share (id) {
        id -> Uuid,
        owner_tenant_id -> Uuid,
        scope_kind -> Text,
        scope_id -> Text,
        recipient_tenant_id -> Uuid,
        recipient_scope_kind -> Nullable<Text>,
        recipient_scope_id -> Nullable<Text>,
        attributes -> Jsonb,
        valid_from -> Nullable<Timestamptz>,
        valid_until -> Nullable<Timestamptz>,
        state -> Text,
        accepted_at -> Nullable<Timestamptz>,
        revoked_at -> Nullable<Timestamptz>,
        revoked_by -> Nullable<Text>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    share_action (share_id, action) {
        share_id -> Uuid,
        action -> Text,
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
        erased_at -> Nullable<Timestamptz>,
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

diesel::joinable!(backchannel_logout -> oidc_client (client_id));
diesel::joinable!(backchannel_logout -> session (session_id));
diesel::joinable!(backchannel_logout -> subject (subject_id));
diesel::joinable!(challenge -> credential (credential_id));
diesel::joinable!(challenge -> mfa_factor (mfa_factor_id));
diesel::joinable!(challenge -> session (session_id));
diesel::joinable!(challenge -> subject (subject_id));
diesel::joinable!(client_assertion -> oidc_client (client_id));
diesel::joinable!(credential -> subject (subject_id));
diesel::joinable!(membership -> subject (subject_id));
diesel::joinable!(membership -> tenant (tenant_id));
diesel::joinable!(mfa_factor -> subject (subject_id));
diesel::joinable!(oidc_client -> subject (service_subject_id));
diesel::joinable!(registered_scope -> tenant (tenant_id));
diesel::joinable!(role -> template (template_id));
diesel::joinable!(role -> tenant (tenant_id));
diesel::joinable!(role_assignment -> membership (membership_id));
diesel::joinable!(role_assignment -> role (role_id));
diesel::joinable!(role_assignment -> subject (subject_id));
diesel::joinable!(role_policy -> catalog_action (action));
diesel::joinable!(role_policy -> role (role_id));
diesel::joinable!(session -> credential (credential_id));
diesel::joinable!(session -> membership (membership_id));
diesel::joinable!(session -> oidc_client (oidc_client_id));
diesel::joinable!(session -> tenant (tenant_id));
diesel::joinable!(session_previous_refresh -> session (session_id));
diesel::joinable!(share_action -> catalog_action (action));
diesel::joinable!(share_action -> share (share_id));
diesel::joinable!(template_policy -> catalog_action (action));
diesel::joinable!(template_policy -> template (template_id));

diesel::allow_tables_to_appear_in_same_query!(
    backchannel_logout,
    batch_result,
    bearer_assertion,
    catalog_action,
    catalog_fact,
    catalog_scope_kind,
    catalog_session_flag,
    challenge,
    client_assertion,
    credential,
    dpop_proof,
    event,
    feed_watermark,
    login_attempt,
    membership,
    mfa_factor,
    oidc_client,
    peer_cursor,
    registered_scope,
    role,
    role_assignment,
    role_policy,
    session,
    session_previous_refresh,
    share,
    share_action,
    signing_key,
    subject,
    template,
    template_policy,
    tenant,
);
