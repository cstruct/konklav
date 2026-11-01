-- Shares: one tenant's scope made available to another tenant, tenant-wide
-- or at one of the recipient's scopes. Offered first, effective once
-- accepted, and final once revoked.

-- Share attributes are catalog facts with target `share`, and a fact can
-- be a date range.
alter table catalog_fact
    drop constraint catalog_fact_target_check,
    add constraint catalog_fact_target_check check (target in ('tenant', 'membership', 'share')),
    drop constraint catalog_fact_value_type_check,
    add constraint catalog_fact_value_type_check
        check (value_type in ('string', 'integer', 'boolean', 'string_list', 'date_range')),
    add constraint catalog_fact_share_not_portable check (target <> 'share' or not portable);

create table share (
    id uuid primary key,
    owner_tenant_id uuid not null references tenant (id),
    scope_kind text not null references catalog_scope_kind (name),
    -- Opaque, like every scope id: the relying system's own identifier.
    scope_id text not null,
    recipient_tenant_id uuid not null references tenant (id),
    recipient_scope_kind text references catalog_scope_kind (name),
    recipient_scope_id text,
    attributes jsonb not null default '{}' check (jsonb_typeof(attributes) = 'object'),
    valid_from timestamptz,
    valid_until timestamptz,
    state text not null default 'offered' check (state in ('offered', 'accepted', 'revoked')),
    accepted_at timestamptz,
    revoked_at timestamptz,
    revoked_by text check (revoked_by in ('owner', 'recipient')),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint share_other_tenant check (owner_tenant_id <> recipient_tenant_id),
    constraint share_recipient_scope_complete
        check ((recipient_scope_kind is null) = (recipient_scope_id is null)),
    constraint share_validity_ordered
        check (valid_from is null or valid_until is null or valid_from < valid_until),
    -- A revoked share keeps when it was accepted, if it was.
    constraint share_accepted_at check (state <> 'accepted' or accepted_at is not null),
    constraint share_revoked
        check ((state = 'revoked') = (revoked_at is not null and revoked_by is not null))
);

-- One live share per owner scope and recipient.
create unique index share_live_idx
    on share (owner_tenant_id, scope_kind, scope_id, recipient_tenant_id, recipient_scope_kind, recipient_scope_id)
    nulls not distinct
    where state <> 'revoked';
create index share_recipient_idx on share (recipient_tenant_id) where state = 'accepted';
create index share_owner_idx on share (owner_tenant_id);

-- The actions a share allows. Catalog entries a share uses can't be
-- removed, as with policies.
create table share_action (
    share_id uuid not null references share (id) on delete cascade,
    action text not null references catalog_action (name),
    primary key (share_id, action),
    constraint share_action_not_capability check (action not like 'konklav:%')
);

create function share_changed() returns trigger
language plpgsql
as $$
begin
    perform konklav_emit('share.changed', jsonb_build_object(
        'share', new.id,
        'owner', new.owner_tenant_id,
        'recipient', new.recipient_tenant_id,
        'state', new.state
    ));
    perform konklav_emit('entitlements.changed', jsonb_build_object('all', true, 'tenant', new.recipient_tenant_id));
    return null;
end
$$;

create trigger share_changed
after insert or update on share
for each row execute function share_changed();

-- Actions written outside a share's own update still invalidate the
-- recipient tenant.
create function share_action_changed() returns trigger
language plpgsql
as $$
declare
    row share_action := coalesce(new, old);
begin
    perform konklav_emit('entitlements.changed', jsonb_build_object(
        'all', true,
        'tenant', (select recipient_tenant_id from share where id = row.share_id)
    ));
    return null;
end
$$;

create trigger share_action_changed
after insert or update or delete on share_action
for each row execute function share_action_changed();
