-- Applications and instances that sign subjects in through Konklav as an
-- OpenID provider. Ids are chosen by the caller (they're the OAuth
-- `client_id`); confidential clients authenticate with a secret Konklav
-- generates, stored as SHA-256.
create table oidc_client (
    id text primary key check (id ~ '^[A-Za-z0-9._:-]{1,128}$'),
    kind text not null check (kind in ('confidential', 'public')),
    secret_hash bytea,
    redirect_uris text[] not null check (cardinality(redirect_uris) > 0),
    scopes text[] not null default '{openid}',
    -- The `aud` of access tokens issued to the client.
    audience text not null,
    -- Global role keys the client may see in `groups`: exact keys, or
    -- prefixes ending in `*`.
    visible_groups text[] not null default '{}',
    login_url text,
    id_token_alg text not null default 'ES256' check (id_token_alg in ('ES256', 'EdDSA')),
    refresh boolean not null default true,
    -- Disabled clients can't start or refresh sessions; their sessions were
    -- revoked when they were disabled.
    disabled_at timestamptz,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

-- Sessions started for a client: their tokens carry the client's audience,
-- and they keep the scopes granted to it.
alter table session
    add column oidc_client_id text references oidc_client (id),
    add column oidc_scopes text[] not null default '{}';

alter table challenge drop constraint challenge_purpose_check;
alter table challenge add constraint challenge_purpose_check check (purpose in (
    'email_link', 'phone_code', 'mfa_email_code', 'invite', 'reset_password',
    'oidc_login', 'oidc_link', 'oidc_authorize', 'oidc_code'
));

insert into catalog_action (name, description, builtin) values
    ('konklav:clients:manage', 'Register and change OIDC clients', true);
