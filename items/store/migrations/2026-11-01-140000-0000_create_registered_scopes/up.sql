-- Registered scopes: scopes of a catalog-declared registered kind whose
-- owner tenant and containing scopes Konklav records, so requirements can
-- name the scope alone and Konklav enforces its tenant.

alter table catalog_scope_kind
    add column registered boolean not null default false,
    add constraint catalog_scope_kind_registered_key unique (name, registered);

create table registered_scope (
    kind text not null,
    -- Opaque, like every scope id.
    id text not null,
    tenant_id uuid not null references tenant (id),
    -- `[{"kind": ..., "id": ...}]`, scopes of kinds that aren't registered.
    containers jsonb not null default '[]',
    state text not null default 'active' check (state in ('active', 'removed')),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    primary key (kind, id),
    -- The kind must stay registered while any scope of it is recorded,
    -- removed ones included, since they keep their tenant.
    kind_registered boolean not null default true check (kind_registered),
    foreign key (kind, kind_registered) references catalog_scope_kind (name, registered),
    constraint registered_scope_containers_array check (jsonb_typeof(containers) = 'array')
);

create index registered_scope_containers_idx on registered_scope using gin (containers jsonb_path_ops);

-- Role assignments can't be made at a registered scope.
alter table role_assignment
    add column scope_kind_registered boolean not null default false check (not scope_kind_registered),
    add foreign key (scope_kind, scope_kind_registered) references catalog_scope_kind (name, registered);

-- A registered scope's tenant never changes, and its containers are
-- complete scopes of declared kinds that aren't registered.
create function registered_scope_check() returns trigger
language plpgsql
as $$
declare
    container jsonb;
begin
    if tg_op = 'UPDATE' and new.tenant_id <> old.tenant_id then
        raise exception 'a registered scope''s tenant can''t change'
            using errcode = 'check_violation';
    end if;
    for container in select * from jsonb_array_elements(new.containers) loop
        if jsonb_typeof(container) <> 'object'
            or jsonb_typeof(container -> 'kind') <> 'string'
            or jsonb_typeof(container -> 'id') <> 'string'
            or (select count(*) from jsonb_object_keys(container)) <> 2
        then
            raise exception 'a containing scope needs exactly a kind and an id'
                using errcode = 'check_violation';
        end if;
        if not exists (
            select from catalog_scope_kind
            where name = container ->> 'kind' and not registered
        ) then
            raise exception 'containing scope kind % isn''t a declared kind that isn''t registered',
                container ->> 'kind'
                using errcode = 'check_violation';
        end if;
    end loop;
    return new;
end
$$;

create trigger registered_scope_check
before insert or update on registered_scope
for each row execute function registered_scope_check();

-- A kind used by containing scopes can't become registered or go away.
create function catalog_scope_kind_containers_check() returns trigger
language plpgsql
as $$
begin
    if (tg_op = 'DELETE' or new.registered) and not old.registered and exists (
        select from registered_scope
        where containers @> jsonb_build_array(jsonb_build_object('kind', old.name))
    ) then
        raise exception 'scope kind % contains registered scopes', old.name
            using errcode = 'check_violation';
    end if;
    return coalesce(new, old);
end
$$;

create trigger catalog_scope_kind_containers_check
before update or delete on catalog_scope_kind
for each row execute function catalog_scope_kind_containers_check();

-- One `scope.changed` event per transaction, however many statements write
-- registered scopes: the first statement writes the event, and later ones
-- add their scopes to it. A transaction-local setting remembers the
-- event's cursor; like `konklav.last_event`, it is undone with rolled-back
-- savepoints, together with the event row.
create function registered_scope_changed() returns trigger
language plpgsql
as $$
declare
    scopes jsonb;
    pending bigint := nullif(current_setting('konklav.scope_event', true), '')::bigint;
begin
    select coalesce(jsonb_agg(jsonb_build_object(
        'kind', kind, 'id', id, 'tenant', tenant_id, 'state', state
    ) order by kind, id), '[]')
    into scopes
    from changed;
    if scopes = '[]' then
        return null;
    end if;
    if pending is not null then
        update event
        set payload = jsonb_set(payload, '{scopes}', payload -> 'scopes' || scopes)
        where cursor = pending;
        if found then
            return null;
        end if;
    end if;
    perform konklav_emit('scope.changed', jsonb_build_object('scopes', scopes));
    perform set_config('konklav.scope_event', current_setting('konklav.last_event'), true);
    return null;
end
$$;

create trigger registered_scope_inserted
after insert on registered_scope
referencing new table as changed
for each statement execute function registered_scope_changed();

create trigger registered_scope_updated
after update on registered_scope
referencing new table as changed
for each statement execute function registered_scope_changed();

insert into catalog_action (name, description, builtin) values
    ('konklav:scopes:register', 'Record and remove registered scopes', true);
