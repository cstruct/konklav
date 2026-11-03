-- Event cursors are allocated in commit order, so a reader that resumes
-- from the last cursor it read never passes an event that commits later.
-- An identity value is drawn when a row is formed, long before commit, so
-- two transactions could commit their events out of cursor order. Instead,
-- each transaction's first event takes a transaction-scoped advisory lock,
-- held until commit or rollback, and cursors are drawn under it. This
-- serializes event-writing transactions from their first event to their
-- end, so keep work after the first event short. The values the identity
-- draws first are discarded; gaps in cursors are harmless.
create function event_lock_key() returns bigint
language sql immutable
as $$ select 7741527692031649124::bigint $$; -- "konkfeed"

create function event_cursor() returns trigger
language plpgsql
as $$
begin
    perform pg_advisory_xact_lock(event_lock_key());
    new.cursor := nextval(pg_get_serial_sequence('event', 'cursor'));
    return new;
end
$$;

create trigger event_cursor
before insert on event
for each row execute function event_cursor();
