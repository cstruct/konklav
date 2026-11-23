-- A tenant capability: granted through tenant roles, it lets a service
-- principal make link-only invites into that tenant on the relying surface.
insert into catalog_action (name, description, builtin) values
    ('konklav:tenant:invite', 'Make, list and revoke link-only invites into the tenant on the relying surface', true);
