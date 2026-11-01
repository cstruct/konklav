-- History: past versions of the rows compilation and decision explanations
-- read, kept while history is enabled, so a decision can be explained as of
-- a past time.
--
-- Triggers record every version, so no write path (bulk SQL from importers
-- included) can skip it. A migration that adds a non-null column to a
-- tracked table must also add it to that table's versions in
-- `row_version.data`, or older versions no longer decode.

-- Whether history is enabled, since when, and how long a version is kept
-- after it stopped being current. One row; the server writes it at startup.
create table history_setting (
    only_row boolean primary key default true check (only_row),
    enabled_at timestamptz,
    retention interval,
    constraint history_setting_retention check ((enabled_at is null) = (retention is null))
);

insert into history_setting default values;

-- The tables history versions, with their primary-key columns.
create table history_table (
    relation regclass primary key,
    key_columns text[] not null
);

insert into history_table (relation, key_columns) values
    ('subject', '{id}'),
    ('tenant', '{id}'),
    ('membership', '{id}'),
    ('catalog_action', '{name}'),
    ('catalog_scope_kind', '{name}'),
    ('catalog_fact', '{target,key}'),
    ('catalog_session_flag', '{name}'),
    ('template', '{id}'),
    ('template_policy', '{template_id,action}'),
    ('role', '{id}'),
    ('role_policy', '{role_id,action}'),
    ('role_assignment', '{id}'),
    ('share', '{id}'),
    ('share_action', '{share_id,action}');

-- One version of one row: its content while it was current, from
-- `valid_from` until `valid_until` (null while it still is).
create table row_version (
    id bigserial primary key,
    relation regclass not null references history_table (relation),
    key jsonb not null,
    data jsonb not null,
    valid_from timestamptz not null,
    valid_until timestamptz,
    constraint row_version_ordered check (valid_until is null or valid_from < valid_until)
);

-- At most one current version per row.
create unique index row_version_current_idx on row_version (relation, key) where valid_until is null;
create index row_version_as_of_idx on row_version (relation, valid_from);
create index row_version_ended_idx on row_version (valid_until) where valid_until is not null;

-- Writers take this lock shared and `history_configure` exclusively, so no
-- write slips between enabling history and copying the current rows.
create function history_lock_key() returns bigint
language sql immutable
as $$ select 7741527692065469300::bigint $$; -- "konkhist"

-- The primary key of `record`, as an object of the columns in `columns`.
create function history_key(record jsonb, columns text[]) returns jsonb
language sql immutable
as $$
    select jsonb_object_agg(c, record -> c) from unnest(columns) c;
$$;

-- Ends the current version of the changed row and records the new one.
-- Versions are timed by their transaction, never earlier than the version
-- they replace; one replaced within the transaction that wrote it is
-- dropped, since no one else ever saw it.
create function history_record() returns trigger
language plpgsql
as $$
declare
    stamp timestamptz := now();
    replaced row_version;
begin
    perform pg_advisory_xact_lock_shared(history_lock_key());
    if not exists (select 1 from history_setting where enabled_at is not null) then
        return null;
    end if;
    if tg_op <> 'INSERT' then
        select * into replaced from row_version
        where relation = tg_relid and key = history_key(to_jsonb(old), tg_argv) and valid_until is null;
        if found then
            stamp := greatest(stamp, replaced.valid_from);
            if replaced.valid_from = stamp then
                delete from row_version where id = replaced.id;
            else
                update row_version set valid_until = stamp where id = replaced.id;
            end if;
        end if;
    end if;
    if tg_op <> 'DELETE' then
        insert into row_version (relation, key, data, valid_from)
        values (tg_relid, history_key(to_jsonb(new), tg_argv), to_jsonb(new), stamp);
    end if;
    return null;
end
$$;

do $$
declare
    tracked history_table;
begin
    for tracked in select * from history_table loop
        execute format(
            'create trigger history_record after insert or update or delete on %s
             for each row execute function history_record(%s)',
            tracked.relation,
            (select string_agg(quote_literal(c), ', ') from unnest(tracked.key_columns) c)
        );
    end loop;
end
$$;

-- Enables history with `keep` as its retention, or disables it when `keep`
-- is null. Enabling copies every tracked row as its current version, so
-- history starts now; disabling discards what was recorded, which could no
-- longer be trusted once writes go unrecorded.
create function history_configure(keep interval) returns void
language plpgsql
as $$
declare
    tracked history_table;
    enabled timestamptz;
begin
    perform pg_advisory_xact_lock(history_lock_key());
    enabled := (select enabled_at from history_setting);
    if keep is null then
        if enabled is not null then
            truncate row_version;
        end if;
        update history_setting set enabled_at = null, retention = null;
        return;
    end if;
    if enabled is null then
        enabled := now();
        for tracked in select * from history_table loop
            execute format(
                'insert into row_version (relation, key, data, valid_from)
                 select %s, history_key(to_jsonb(r), $1), to_jsonb(r), $2 from %s r',
                quote_literal(tracked.relation::oid) || '::oid', tracked.relation
            ) using tracked.key_columns, enabled;
        end loop;
    end if;
    update history_setting set enabled_at = enabled, retention = keep;
end
$$;

-- Replaces, for the rest of the current transaction, every tracked table
-- with a temporary table of the same name holding its rows as of `at`, so
-- ordinary queries read the past. Temporary tables come first in the search
-- path.
create function history_shadow(at timestamptz) returns void
language plpgsql
as $$
declare
    tracked history_table;
begin
    for tracked in select * from history_table loop
        execute format(
            'create temporary table %I on commit drop as
             select r.* from row_version v cross join lateral jsonb_populate_record(null::%s, v.data) r
             where v.relation = %s and v.valid_from <= $1 and (v.valid_until is null or v.valid_until > $1)',
            (select relname from pg_class where oid = tracked.relation),
            tracked.relation,
            quote_literal(tracked.relation::oid) || '::oid'
        ) using at;
    end loop;
end
$$;
