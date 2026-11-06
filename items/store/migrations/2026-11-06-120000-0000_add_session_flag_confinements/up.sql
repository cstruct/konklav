-- Confinements: a restrictive flag may confine sessions carrying it to the
-- tenants whose portable facts match. The server validates the shape
-- against the catalog's facts; the database only keeps it to restrictive
-- flags.
alter table catalog_session_flag add column confine jsonb
    check (confine is null or jsonb_typeof(confine) = 'object');
alter table catalog_session_flag add constraint catalog_session_flag_confine
    check (confine is null or kind = 'restrictive');

-- Entitlement sets carry the tenant facts confinements name, so a change of
-- a tenant's facts invalidates every set for the tenant.
create function tenant_facts_changed() returns trigger
language plpgsql
as $$
begin
    perform konklav_emit('entitlements.changed', jsonb_build_object('all', true, 'tenant', new.id));
    return null;
end
$$;

create trigger tenant_facts_changed
after update of facts on tenant
for each row when (new.facts is distinct from old.facts)
execute function tenant_facts_changed();
