-- Wakes change-feed streams when events are appended. Streams always read
-- the outbox, so a missed notification only delays delivery.
create function event_appended() returns trigger
language plpgsql
as $$
begin
    perform pg_notify('conclave_event', '');
    return null;
end
$$;

create trigger event_appended
after insert on event
for each statement execute function event_appended();

-- How far retention has pruned the outbox. A consumer resuming from an
-- older cursor has missed events and must reset.
create table feed_watermark (
    singleton boolean primary key default true check (singleton),
    pruned_through bigint not null default 0
);

insert into feed_watermark default values;
