-- Tenants, memberships, the action catalog, templates, roles and role
-- assignments, plus the triggers that keep the change feed informed.

-- Appends a change-feed event. Triggers use it so that no write path,
-- including bulk SQL from importers, can skip invalidation.
create function konklav_emit(kind text, payload jsonb) returns void
language sql
as $$
    insert into event (kind, payload) values (kind, payload);
$$;

-- Tenants -------------------------------------------------------------------

create table tenant (
    id uuid primary key,
    parent_id uuid references tenant (id),
    state text not null default 'active' check (state in ('active', 'suspended', 'deleted')),
    facts jsonb not null default '{}' check (jsonb_typeof(facts) = 'object'),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    -- Only the root has no parent, and it is its own namespace.
    constraint tenant_parent_required check ((parent_id is null) = (id = '00000000-0000-0000-0000-000000000000'))
);

-- The root tenant always exists; its id is the nil UUID, addressed as `root`.
insert into tenant (id) values ('00000000-0000-0000-0000-000000000000');

create function tenant_changed() returns trigger
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

-- Memberships ---------------------------------------------------------------

create table membership (
    id uuid primary key,
    subject_id uuid not null references subject (id),
    tenant_id uuid not null references tenant (id),
    state text not null default 'active' check (state in ('active', 'ended')),
    facts jsonb not null default '{}' check (jsonb_typeof(facts) = 'object'),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create unique index membership_active_idx on membership (subject_id, tenant_id) where state = 'active';
create index membership_tenant_idx on membership (tenant_id);

create function membership_changed() returns trigger
language plpgsql
as $$
declare
    row membership := coalesce(new, old);
begin
    perform konklav_emit('entitlements.changed', jsonb_build_object(
        'subjects', jsonb_build_array(row.subject_id),
        'tenant', row.tenant_id
    ));
    return null;
end
$$;

create trigger membership_changed
after insert or update or delete on membership
for each row execute function membership_changed();

alter table session
    add constraint session_tenant_fk foreign key (tenant_id) references tenant (id),
    add constraint session_membership_fk foreign key (membership_id) references membership (id);
create index session_active_tenant_idx on session (tenant_id) where revoked_at is null;
create index session_active_membership_idx on session (membership_id) where revoked_at is null;

-- Disabling or re-enabling a subject changes what it is entitled to.
create function subject_state_changed() returns trigger
language plpgsql
as $$
begin
    perform konklav_emit('entitlements.changed', jsonb_build_object('subjects', jsonb_build_array(new.id)));
    return null;
end
$$;

create trigger subject_state_changed
after update of state on subject
for each row when (new.state is distinct from old.state)
execute function subject_state_changed();

-- Catalog -------------------------------------------------------------------

-- Actions and action groups share one namespace, so a policy can name either.
-- Groups carry their definition; plain actions don't.
create table catalog_action (
    name text primary key check (name ~ '^[a-z0-9_]+(:[a-z0-9_*]+)*$'),
    description text not null default '',
    group_definition jsonb,
    constraint catalog_action_reserved check (name not like 'konklav:%'),
    constraint catalog_action_group_matches_schema check (
        group_definition is null or jsonb_matches_schema('{
            "type": "object",
            "additionalProperties": false,
            "oneOf": [
                {"required": ["actions"]},
                {"required": ["all_except_prefixes"]}
            ],
            "properties": {
                "actions": {"type": "array", "items": {"type": "string"}, "uniqueItems": true},
                "all_except_prefixes": {"type": "array", "items": {"type": "string"}, "uniqueItems": true}
            }
        }', group_definition)
    )
);

create table catalog_scope_kind (
    name text primary key check (name ~ '^[a-z0-9_]+$'),
    description text not null default ''
);

create table catalog_fact (
    key text not null check (key ~ '^[a-z0-9_]+$'),
    target text not null check (target in ('tenant', 'membership')),
    value_type text not null check (value_type in ('string', 'integer', 'boolean', 'string_list')),
    portable boolean not null default false,
    description text not null default '',
    primary key (target, key)
);

create table catalog_session_flag (
    name text primary key check (name ~ '^[a-z0-9_]+$'),
    kind text not null check (kind in ('restrictive', 'assertive')),
    -- Only restrictive flags can be asked for at login: they can only take
    -- access away, so a client asking for one cannot gain anything.
    requestable boolean not null default false,
    description text not null default '',
    constraint catalog_session_flag_requestable check (not requestable or kind = 'restrictive')
);

-- Templates and roles -------------------------------------------------------

create table template (
    id uuid primary key,
    key text not null unique check (key ~ '^[A-Za-z0-9_.-]+$'),
    description text not null default '',
    -- Opaque to Konklav; for relying systems' own labels.
    metadata jsonb not null default '{}' check (jsonb_typeof(metadata) = 'object'),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create table template_policy (
    template_id uuid not null references template (id) on delete cascade,
    action text not null references catalog_action (name),
    effect text not null check (effect in ('allow', 'deny')),
    scope_bound boolean not null default false,
    primary key (template_id, action)
);

create table role (
    id uuid primary key,
    tenant_id uuid not null references tenant (id),
    key text not null check (key ~ '^[A-Za-z0-9_.-]+$'),
    template_id uuid references template (id),
    priority integer not null default 0,
    metadata jsonb not null default '{}' check (jsonb_typeof(metadata) = 'object'),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (tenant_id, key)
);

-- A role's own policies, which override its template's per action.
create table role_policy (
    role_id uuid not null references role (id) on delete cascade,
    action text not null references catalog_action (name),
    effect text not null check (effect in ('allow', 'deny')),
    scope_bound boolean not null default false,
    primary key (role_id, action)
);

-- Assignments ---------------------------------------------------------------

-- A tenant role assigned to a membership (tenant-wide or at one scope), or a
-- global role (owned by the root tenant) assigned directly to a subject.
create table role_assignment (
    id uuid primary key,
    role_id uuid not null references role (id) on delete cascade,
    membership_id uuid references membership (id) on delete cascade,
    subject_id uuid references subject (id),
    scope_kind text references catalog_scope_kind (name),
    scope_id text,
    created_at timestamptz not null default now(),
    constraint role_assignment_target check ((membership_id is null) <> (subject_id is null)),
    constraint role_assignment_scope_complete check ((scope_kind is null) = (scope_id is null)),
    constraint role_assignment_global_unscoped check (subject_id is null or scope_kind is null)
);

create unique index role_assignment_unique_idx
    on role_assignment (role_id, membership_id, subject_id, scope_kind, scope_id) nulls not distinct;
create index role_assignment_membership_idx on role_assignment (membership_id);
create index role_assignment_subject_idx on role_assignment (subject_id);

-- Membership roles must belong to the membership's tenant; subject roles must
-- be global (root-owned).
create function role_assignment_check() returns trigger
language plpgsql
as $$
declare
    role_tenant uuid := (select tenant_id from role where id = new.role_id);
begin
    if new.membership_id is not null
        and role_tenant is distinct from (select tenant_id from membership where id = new.membership_id) then
        raise exception 'role % belongs to another tenant than membership %', new.role_id, new.membership_id
            using errcode = 'check_violation';
    end if;
    if new.subject_id is not null and role_tenant <> '00000000-0000-0000-0000-000000000000' then
        raise exception 'only global roles can be assigned to subjects directly'
            using errcode = 'check_violation';
    end if;
    return new;
end
$$;

create trigger role_assignment_check
before insert or update on role_assignment
for each row execute function role_assignment_check();

create function role_assignment_changed() returns trigger
language plpgsql
as $$
declare
    row role_assignment := coalesce(new, old);
    subject uuid := coalesce(row.subject_id, (select subject_id from membership where id = row.membership_id));
begin
    perform konklav_emit('entitlements.changed', jsonb_build_object(
        'subjects', jsonb_build_array(subject),
        'tenant', (select tenant_id from membership where id = row.membership_id)
    ));
    return null;
end
$$;

create trigger role_assignment_changed
after insert or update or delete on role_assignment
for each row execute function role_assignment_changed();

-- Definitions ---------------------------------------------------------------

-- Changing a definition can affect any number of subjects, so it invalidates
-- everything once per statement, like a catalog change.
create function definitions_changed() returns trigger
language plpgsql
as $$
begin
    perform konklav_emit('entitlements.changed', jsonb_build_object('all', true));
    return null;
end
$$;

create trigger catalog_action_changed after insert or update or delete on catalog_action
for each statement execute function definitions_changed();
create trigger template_changed after insert or update or delete on template
for each statement execute function definitions_changed();
create trigger template_policy_changed after insert or update or delete on template_policy
for each statement execute function definitions_changed();
create trigger role_changed after insert or update or delete on role
for each statement execute function definitions_changed();
create trigger role_policy_changed after insert or update or delete on role_policy
for each statement execute function definitions_changed();
