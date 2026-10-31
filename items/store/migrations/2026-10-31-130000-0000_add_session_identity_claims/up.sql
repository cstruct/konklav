-- Claims an identity provider reported, kept to pass on to OIDC clients,
-- by the scope they are served under: {"profile": {"name": "Ada"}}. A copy
-- for the session's lifetime only; the sweeper erases it once the session
-- has ended.
alter table session
    add column identity_claims jsonb,
    add constraint session_identity_claims_object
        check (identity_claims is null or jsonb_typeof(identity_claims) = 'object');

create index session_identity_claims_ended on session (expires_at)
    where identity_claims is not null;
