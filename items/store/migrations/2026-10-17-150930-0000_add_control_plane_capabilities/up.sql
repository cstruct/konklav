-- Control-plane capabilities per area. `conclave:control:all` (added
-- earlier) still grants every area.
insert into catalog_action (name, description, builtin) values
    ('conclave:subjects:manage', 'Manage subjects and their credentials', true),
    ('conclave:tenants:manage', 'Manage tenants and memberships', true),
    ('conclave:authz:manage', 'Manage the catalog, templates, roles and role assignments', true),
    ('conclave:sessions:manage', 'List, inspect and revoke sessions', true),
    ('conclave:keys:manage', 'List and revoke signing keys', true),
    ('conclave:invites:manage', 'Send invites', true);

create index subject_created_idx on subject (id);
create index tenant_parent_idx on tenant (parent_id);
