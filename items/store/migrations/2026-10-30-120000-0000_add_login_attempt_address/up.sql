-- The client address of each login attempt, so attempts can also be
-- limited per address across identifiers. Null when unknown.
alter table login_attempt add column address text;

create index login_attempt_address_idx on login_attempt (address, attempted_at)
    where address is not null;
