-- Metadata: an opaque JSON object a relying system stores on an object
-- through the control plane. Konklav never reads it, so writing only
-- metadata emits `metadata.changed` and nothing about entitlements.
-- Templates and roles already have the column.

alter table subject add column metadata jsonb not null default '{}'
    check (jsonb_typeof(metadata) = 'object');
alter table credential add column metadata jsonb not null default '{}'
    check (jsonb_typeof(metadata) = 'object');
-- Only invites use it among challenges.
alter table challenge add column metadata jsonb not null default '{}'
    check (jsonb_typeof(metadata) = 'object');
alter table tenant add column metadata jsonb not null default '{}'
    check (jsonb_typeof(metadata) = 'object');
alter table membership add column metadata jsonb not null default '{}'
    check (jsonb_typeof(metadata) = 'object');
alter table share add column metadata jsonb not null default '{}'
    check (jsonb_typeof(metadata) = 'object');
alter table oidc_client add column metadata jsonb not null default '{}'
    check (jsonb_typeof(metadata) = 'object');

-- Recorded versions of history's tables decode only with every non-null
-- column, so earlier versions get the empty metadata they had.
update row_version set data = data || '{"metadata": {}}'
where relation in ('subject'::regclass, 'tenant'::regclass, 'membership'::regclass, 'share'::regclass)
  and not data ? 'metadata';

-- List filters match top-level keys with `@>`; the lists that grow with
-- people and tenants answer them from an index.
create index subject_metadata_idx on subject using gin (metadata jsonb_path_ops);
create index tenant_metadata_idx on tenant using gin (metadata jsonb_path_ops);
create index membership_metadata_idx on membership using gin (metadata jsonb_path_ops);
create index challenge_invite_idx on challenge (id) where purpose = 'invite';
create index challenge_invite_metadata_idx on challenge using gin (metadata jsonb_path_ops)
    where purpose = 'invite';

-- Announces a change of a row's metadata: its kind (the trigger's
-- argument), its id and its new metadata, `null` once deleted. Rows created
-- with empty metadata, and challenges other than invites, announce nothing.
create function metadata_changed() returns trigger
language plpgsql
as $$
declare
    row jsonb := to_jsonb(coalesce(new, old));
    metadata jsonb := case when tg_op = 'DELETE' then 'null'::jsonb else to_jsonb(new) -> 'metadata' end;
begin
    if tg_table_name = 'challenge' and row ->> 'purpose' <> 'invite' then
        return null;
    end if;
    if tg_op = 'INSERT' and metadata = '{}'::jsonb then
        return null;
    end if;
    if tg_op = 'UPDATE' and new.metadata is not distinct from old.metadata then
        return null;
    end if;
    if tg_op = 'DELETE' and old.metadata = '{}'::jsonb then
        return null;
    end if;
    perform konklav_emit('metadata.changed', jsonb_build_object(
        'object', tg_argv[0],
        'id', row -> 'id',
        'metadata', metadata
    ));
    return null;
end
$$;

create trigger subject_metadata_changed after insert or update of metadata or delete on subject
for each row execute function metadata_changed('subject');
create trigger credential_metadata_changed after insert or update of metadata or delete on credential
for each row execute function metadata_changed('credential');
create trigger challenge_metadata_changed after insert or update of metadata or delete on challenge
for each row execute function metadata_changed('invite');
create trigger tenant_metadata_changed after insert or update of metadata or delete on tenant
for each row execute function metadata_changed('tenant');
create trigger membership_metadata_changed after insert or update of metadata or delete on membership
for each row execute function metadata_changed('membership');
create trigger share_metadata_changed after insert or update of metadata or delete on share
for each row execute function metadata_changed('share');
create trigger oidc_client_metadata_changed after insert or update of metadata or delete on oidc_client
for each row execute function metadata_changed('oidc_client');
create trigger template_metadata_changed after insert or update of metadata or delete on template
for each row execute function metadata_changed('template');
create trigger role_metadata_changed after insert or update of metadata or delete on role
for each row execute function metadata_changed('role');

-- Writing only metadata (and the time of the write) changes no one's
-- entitlements, so these triggers no longer fire for it.
drop trigger membership_changed on membership;
create trigger membership_changed
after insert or delete or update of subject_id, tenant_id, state, facts, managed_by on membership
for each row execute function membership_changed();

drop trigger share_changed on share;
create trigger share_changed
after insert or update of owner_tenant_id, scope_kind, scope_id, recipient_tenant_id,
    recipient_scope_kind, recipient_scope_id, attributes, valid_from, valid_until, state,
    accepted_at, revoked_at, revoked_by on share
for each row execute function share_changed();

drop trigger template_changed on template;
create trigger template_changed
after insert or delete or update of key, description on template
for each statement execute function definitions_changed();

drop trigger role_changed on role;
create trigger role_changed
after insert or delete or update of tenant_id, key, template_id, priority, builtin on role
for each statement execute function definitions_changed();
