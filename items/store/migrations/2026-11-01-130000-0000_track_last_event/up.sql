-- The newest event cursor written in the current transaction, so writes can
-- report it. Matching events by `xmin` misses events written inside
-- savepoints (nested transactions), whose rows carry a subtransaction id.
-- A transaction-local setting survives released savepoints and is undone
-- with rolled-back ones.
create function event_written() returns trigger
language plpgsql
as $$
begin
    perform set_config(
        'konklav.last_event',
        greatest(coalesce(nullif(current_setting('konklav.last_event', true), '')::bigint, 0), new.cursor)::text,
        true
    );
    return null;
end
$$;

create trigger event_written
after insert on event
for each row execute function event_written();
