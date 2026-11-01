-- The change-feed outbox. Every state change appends its events here in
-- the same transaction, and the change feed reads them back in cursor
-- order. Cursors are only ever compared and resumed from, so gaps left by
-- rolled-back transactions are harmless.
create table event (
    cursor bigint generated always as identity primary key,
    kind text not null,
    payload jsonb not null,
    created_at timestamptz not null default now()
);

-- Retention pruning deletes by age.
create index event_created_at_idx on event (created_at);
