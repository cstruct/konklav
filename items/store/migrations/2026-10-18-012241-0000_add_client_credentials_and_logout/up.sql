-- OIDC clients bound to a service principal get tokens for it with the
-- client credentials grant. The binding is a `client` credential of that
-- principal, identified by the client id, so its sessions name a
-- credential like any other.
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
        when 'client' then '{"type": "object", "additionalProperties": false}'::json
        when 'federated' then '{
            "type": "object",
            "additionalProperties": false,
            "required": ["provider", "subject"],
            "properties": {
                "provider": {"type": "string", "minLength": 1},
                "subject": {"type": "string", "minLength": 1},
                "email": {"type": ["string", "null"]},
                "email_verified": {"type": ["boolean", "null"]}
            }
        }'::json
    end
$$;

alter table credential drop constraint credential_kind_check;
alter table credential add constraint credential_kind_check
    check (kind in ('password', 'secret_key', 'email_link', 'phone_otp', 'federated', 'client'));

alter table oidc_client
    add column service_subject_id uuid references subject (id),
    -- Public keys for `private_key_jwt` client authentication.
    add column jwks jsonb check (jwks is null or jsonb_typeof(jwks -> 'keys') = 'array'),
    add column post_logout_redirect_uris text[] not null default '{}',
    add column backchannel_logout_uri text;

-- `jti`s of client assertions already used, until they expire.
create table client_assertion (
    client_id text not null references oidc_client (id),
    jti text not null,
    expires_at timestamptz not null,
    primary key (client_id, jti)
);

-- Back-channel logout tokens to deliver. A trigger queues one in the
-- transaction that revokes a client session, so none is lost; a worker
-- delivers them with retries.
create table backchannel_logout (
    id uuid primary key default gen_random_uuid(),
    client_id text not null references oidc_client (id),
    session_id uuid not null references session (id),
    subject_id uuid not null references subject (id),
    attempts integer not null default 0,
    next_attempt_at timestamptz not null default now(),
    last_error text,
    created_at timestamptz not null default now()
);

create index backchannel_logout_due_idx on backchannel_logout (next_attempt_at);

create function queue_backchannel_logout() returns trigger
language plpgsql
as $$
begin
    if old.revoked_at is null and new.revoked_at is not null and new.oidc_client_id is not null
        and exists (
            select 1 from oidc_client
            where id = new.oidc_client_id and backchannel_logout_uri is not null
        )
    then
        insert into backchannel_logout (client_id, session_id, subject_id)
        values (new.oidc_client_id, new.id, new.subject_id);
    end if;
    return null;
end
$$;

create trigger session_backchannel_logout
after update of revoked_at on session
for each row execute function queue_backchannel_logout();
