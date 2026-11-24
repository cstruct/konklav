-- Tenant keys: an optional, human-readable name for a tenant, unique among
-- all tenants, usable wherever a tenant is named instead of its UUID.
-- Lowercase words joined by hyphens, so a key never parses as a UUID and
-- isn't `root`.
alter table tenant
    add column key text,
    add constraint tenant_key_format check (
        key ~ '^[a-z]+(-[a-z]+)*$' and length(key) <= 63 and key <> 'root'
    );

create unique index tenant_key_idx on tenant (key);

-- A key is set once: it never changes and is never removed, so a reference
-- by key names the same tenant for good and no other tenant can take it.
create function tenant_key_stays() returns trigger
language plpgsql
as $$
begin
    raise exception 'tenant % already has the key %; a tenant''s key never changes', old.id, old.key
        using errcode = 'check_violation', constraint = 'tenant_key_set_once';
end
$$;

create trigger tenant_key_stays
before update of key on tenant
for each row when (old.key is not null and new.key is distinct from old.key)
execute function tenant_key_stays();

-- `tenant.changed` carries the key, and setting one emits it.
create or replace function tenant_changed() returns trigger
language plpgsql
as $$
begin
    perform konklav_emit('tenant.changed', jsonb_build_object(
        'tenant', new.id,
        'parent', new.parent_id,
        'state', new.state,
        'key', new.key,
        'created', tg_op = 'INSERT'
    ));
    if tg_op = 'UPDATE' and new.state is distinct from old.state then
        perform konklav_emit('entitlements.changed', jsonb_build_object('all', true, 'tenant', new.id));
    end if;
    return null;
end
$$;

drop trigger tenant_changed on tenant;
create trigger tenant_changed
after insert or update of state, parent_id, key on tenant
for each row execute function tenant_changed();
