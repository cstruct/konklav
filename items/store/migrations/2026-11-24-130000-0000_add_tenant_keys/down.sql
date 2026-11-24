drop trigger tenant_changed on tenant;
create or replace function tenant_changed() returns trigger
language plpgsql
as $$
begin
    perform konklav_emit('tenant.changed', jsonb_build_object(
        'tenant', new.id,
        'parent', new.parent_id,
        'state', new.state,
        'created', tg_op = 'INSERT'
    ));
    if tg_op = 'UPDATE' and new.state is distinct from old.state then
        perform konklav_emit('entitlements.changed', jsonb_build_object('all', true, 'tenant', new.id));
    end if;
    return null;
end
$$;
create trigger tenant_changed
after insert or update of state, parent_id on tenant
for each row execute function tenant_changed();
drop trigger tenant_key_stays on tenant;
drop function tenant_key_stays();
alter table tenant drop column key;
