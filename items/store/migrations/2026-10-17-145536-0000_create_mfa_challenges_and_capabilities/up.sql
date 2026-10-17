-- Passwordless credential kinds, MFA factors, challenges, impersonation
-- sessions and built-in control-plane capabilities.

-- Credentials ---------------------------------------------------------------

-- Email-link and phone-code credentials only name where to send a challenge;
-- the login identifier (an email address or E.164 number) is all they need.
create or replace function credential_data_schema(kind text) returns json
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
        when 'email_link' then '{"type": "object", "additionalProperties": false}'::json
        when 'phone_otp' then '{"type": "object", "additionalProperties": false}'::json
    end
$$;

alter table credential drop constraint credential_kind_check;
alter table credential add constraint credential_kind_check
    check (kind in ('password', 'secret_key', 'email_link', 'phone_otp'));

-- MFA factors ---------------------------------------------------------------

-- A subject's second factors. TOTP secrets are stored encrypted with a key
-- from secret configuration, named by `key_id` so keys can rotate.
create table mfa_factor (
    id uuid primary key,
    subject_id uuid not null references subject (id),
    kind text not null check (kind in ('totp', 'email_code')),
    data jsonb not null,
    active boolean not null default false,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    removed_at timestamptz,
    constraint mfa_factor_data_matches_schema check (jsonb_matches_schema(
        case kind
            when 'totp' then '{
                "type": "object",
                "additionalProperties": false,
                "required": ["key_id", "nonce", "ciphertext"],
                "properties": {
                    "key_id": {"type": "string"},
                    "nonce": {"type": "string"},
                    "ciphertext": {"type": "string"},
                    "last_step": {"type": "integer"}
                }
            }'::json
            when 'email_code' then '{
                "type": "object",
                "additionalProperties": false,
                "required": ["email"],
                "properties": {"email": {"type": "string", "minLength": 3}}
            }'::json
        end,
        data
    ))
);

create index mfa_factor_subject_idx on mfa_factor (subject_id) where removed_at is null;

-- Challenges ----------------------------------------------------------------

-- Short-lived, single-use secrets proven back to Conclave: one-time codes,
-- magic links, invites and password resets. Only hashes are stored.
create table challenge (
    id uuid primary key,
    purpose text not null check (purpose in (
        'email_link', 'phone_code', 'mfa_email_code', 'invite', 'reset_password'
    )),
    subject_id uuid references subject (id),
    credential_id uuid references credential (id),
    mfa_factor_id uuid references mfa_factor (id),
    session_id uuid references session (id),
    -- Where the challenge was delivered (email address or phone number).
    recipient text not null,
    secret_hash bytea not null,
    attempts integer not null default 0,
    max_attempts integer not null default 5,
    -- Purpose-specific details, such as an invite's tenant and roles.
    details jsonb not null default '{}' check (jsonb_typeof(details) = 'object'),
    created_at timestamptz not null default now(),
    expires_at timestamptz not null,
    consumed_at timestamptz
);

create index challenge_recipient_idx on challenge (purpose, recipient, created_at);

-- Sessions ------------------------------------------------------------------

-- MFA factors verified in this session, and the session an impersonation or
-- assumption session was started from (ending the parent ends the child).
alter table session
    add column mfa_factors text[] not null default '{}',
    add column parent_session_id uuid references session (id);

create index session_active_parent_idx on session (parent_session_id) where revoked_at is null;

-- Built-in capabilities -------------------------------------------------------

-- Control-plane capabilities live in the catalog so roles can grant them,
-- but only Conclave defines them: catalog documents can neither declare nor
-- remove them.
alter table catalog_action add column builtin boolean not null default false;
alter table catalog_action drop constraint catalog_action_reserved;
alter table catalog_action add constraint catalog_action_reserved
    check ((name like 'conclave:%') = builtin);

insert into catalog_action (name, description, builtin) values
    ('conclave:subject:impersonate', 'Start sessions as other subjects', true),
    ('conclave:delivery:read', 'Read delivery requests (challenge material) from the change feed', true),
    ('conclave:control:all', 'Every control-plane operation', true);
