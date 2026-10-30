-- Whether a client must use PKCE. Public clients always must; a confidential
-- client may be registered without it, for relying parties that can't.
alter table oidc_client
    add column require_pkce boolean not null default true,
    add constraint oidc_client_public_pkce check (require_pkce or kind = 'confidential');
