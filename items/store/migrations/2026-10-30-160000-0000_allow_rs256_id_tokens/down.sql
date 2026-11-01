alter table oidc_client
    drop constraint oidc_client_id_token_alg_check,
    add constraint oidc_client_id_token_alg_check
        check (id_token_alg in ('ES256', 'EdDSA'));
