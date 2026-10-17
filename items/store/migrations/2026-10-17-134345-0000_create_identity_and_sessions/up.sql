-- Subjects, credentials, sessions and signing keys.

-- Validates credential data against per-kind JSON Schemas. Creating it needs
-- elevated privileges, so production databases should have it installed
-- before migrations run; then this is a no-op.
create extension if not exists pg_jsonschema;

create table subject (
    id uuid primary key,
    kind text not null check (kind in ('human', 'service')),
    state text not null default 'active' check (state in ('active', 'disabled')),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

-- The JSON Schema for each credential kind's `data`. Kinds without a schema
-- are rejected by the `kind` check on `credential`, so a NULL here never
-- lets unvalidated data through.
create function credential_data_schema(kind text) returns json
language sql immutable parallel safe
as $$
    select case kind
        when 'password' then '{
            "type": "object",
            "additionalProperties": false,
            "required": ["hash"],
            "properties": {
                "hash": {"type": "string", "pattern": "^\\$argon2(id|i|d)\\$"}
            }
        }'::json
        when 'secret_key' then '{
            "type": "object",
            "additionalProperties": false,
            "required": ["a", "b"],
            "properties": {
                "a": {"$ref": "#/$defs/slot"},
                "b": {"$ref": "#/$defs/slot"}
            },
            "$defs": {
                "slot": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["hash", "created_at"],
                    "properties": {
                        "hash": {"type": "string", "pattern": "^\\$argon2(id|i|d)\\$"},
                        "created_at": {"type": "string", "format": "date-time"},
                        "expires_at": {"type": ["string", "null"], "format": "date-time"}
                    }
                }
            }
        }'::json
    end
$$;

-- One table for every kind of credential. Kind-specific data lives in
-- `data`, validated by `credential_data_schema`. Credentials are never
-- overwritten: replacing one inserts a new row that points back at the old
-- one, and the old row is revoked.
create table credential (
    id uuid primary key,
    subject_id uuid not null references subject (id),
    kind text not null check (kind in ('password', 'secret_key')),
    -- The normalized login identifier: an email address for passwords, the
    -- credential id for secret keys.
    identifier text not null,
    data jsonb not null,
    mfa_factors_required smallint not null default 0 check (mfa_factors_required >= 0),
    replaces uuid references credential (id),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    revoked_at timestamptz,
    revoked_reason text,
    constraint credential_data_matches_schema
        check (jsonb_matches_schema(credential_data_schema(kind), data)),
    constraint credential_revocation_complete
        check ((revoked_at is null) = (revoked_reason is null))
);

create unique index credential_active_identifier_idx
    on credential (kind, identifier) where revoked_at is null;
create index credential_subject_idx on credential (subject_id);

create table session (
    id uuid primary key,
    subject_id uuid not null references subject (id),
    credential_id uuid not null references credential (id),
    -- Set once a tenant is selected (from M3).
    tenant_id uuid,
    membership_id uuid,
    stage text not null check (stage in ('partial', 'identity', 'tenant')),
    client_kind text not null check (client_kind in ('browser', 'native')),
    amr text[] not null,
    auth_time timestamptz not null,
    flags text[] not null default '{}',
    impersonator_subject_id uuid references subject (id),
    version bigint not null default 1,
    -- SHA-256 of the current refresh token.
    refresh_hash bytea not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    expires_at timestamptz not null,
    revoked_at timestamptz,
    revoked_reason text,
    constraint session_revocation_complete
        check ((revoked_at is null) = (revoked_reason is null))
);

create index session_active_subject_idx on session (subject_id) where revoked_at is null;
create index session_active_credential_idx on session (credential_id) where revoked_at is null;
create index session_expires_at_idx on session (expires_at);

-- Refresh tokens a session has rotated away from. Presenting one of these
-- means a token leaked or was replayed, so the session is revoked.
create table session_previous_refresh (
    session_id uuid not null references session (id) on delete cascade,
    refresh_hash bytea not null,
    rotated_at timestamptz not null default now(),
    primary key (session_id, refresh_hash)
);

-- Public keys of every signing key Conclave has published. Private keys
-- never reach the database.
create table signing_key (
    kid text primary key,
    algorithm text not null check (algorithm = 'EdDSA'),
    public_key bytea not null check (length(public_key) = 32),
    published_at timestamptz not null default now(),
    activated_at timestamptz,
    retired_at timestamptz,
    revoked_at timestamptz
);

-- At most one key signs at a time.
create unique index signing_key_single_active_idx
    on signing_key ((true)) where activated_at is not null and retired_at is null and revoked_at is null;

-- Login attempts per credential kind and login identifier, for rate
-- limiting. Attempts against unknown identifiers are recorded too, so
-- limits don't reveal which identifiers exist.
create table login_attempt (
    id bigint generated always as identity primary key,
    kind text not null,
    identifier text not null,
    succeeded boolean not null,
    attempted_at timestamptz not null default now()
);

create index login_attempt_lookup_idx on login_attempt (kind, identifier, attempted_at);
