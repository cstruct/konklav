-- Single claims an OIDC client asked for with the `claims` request
-- parameter, for userinfo and for the ID token, beyond its scopes' claims.
alter table session
    add column oidc_userinfo_claims text[] not null default '{}',
    add column oidc_id_token_claims text[] not null default '{}';
