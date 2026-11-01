-- Built-in roles: global roles that Konklav defines, under the reserved
-- `konklav.` key prefix. The store refuses to write them; changing one
-- takes a migration.
do $$
declare
    taken record;
begin
    select tenant_id, key into taken from role where key like 'konklav.%' limit 1;
    if found then
        raise exception 'role key % in tenant % uses the reserved prefix `konklav.`; rename it, then migrate again',
            taken.key, taken.tenant_id;
    end if;
end
$$;

alter table role add column builtin boolean not null default false;
alter table role add constraint role_reserved_key check ((key like 'konklav.%') = builtin);
alter table role add constraint role_builtin_global
    check (not builtin or tenant_id = '00000000-0000-0000-0000-000000000000');

insert into role (id, tenant_id, key, builtin) values
    ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000000', 'konklav.admin', true),
    ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000000', 'konklav.delivery', true);

insert into role_policy (role_id, action, effect) values
    ('00000000-0000-0000-0000-000000000001', 'konklav:control:all', 'allow'),
    ('00000000-0000-0000-0000-000000000002', 'konklav:delivery:read', 'allow');
