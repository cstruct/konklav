-- Control-plane capabilities per area. `konklav:control:all` (added
-- earlier) still grants every area.
insert into catalog_action (name, description, builtin) values
    ('konklav:subjects:manage', 'Manage subjects and their credentials', true),
    ('konklav:tenants:manage', 'Manage tenants and memberships', true),
    ('konklav:authz:manage', 'Manage the catalog, templates, roles and role assignments', true),
    ('konklav:sessions:manage', 'List, inspect and revoke sessions', true),
    ('konklav:keys:manage', 'List and revoke signing keys', true),
    ('konklav:invites:manage', 'Send invites', true);

create index subject_created_idx on subject (id);
create index tenant_parent_idx on tenant (parent_id);
