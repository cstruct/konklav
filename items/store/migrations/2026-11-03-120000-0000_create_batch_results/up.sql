-- The answers of committed batches that carried an idempotency key, so a
-- repeat gets the first answer instead of applying the batch again
-- (platform.batch.idempotency-key). Secrets the answer showed are not kept.
create table batch_result (
    caller text not null,
    key text not null,
    request_hash bytea not null,
    answer jsonb not null,
    created_at timestamptz not null default now(),
    expires_at timestamptz not null,
    primary key (caller, key)
);

create index batch_result_expires_idx on batch_result (expires_at);
