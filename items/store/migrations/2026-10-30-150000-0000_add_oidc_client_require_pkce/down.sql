alter table oidc_client
    drop constraint oidc_client_public_pkce,
    drop column require_pkce;
