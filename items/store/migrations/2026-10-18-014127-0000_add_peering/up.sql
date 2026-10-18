-- Subjects disabled or re-enabled also announce it as `subject.changed`, so
-- instances federating through this one can end those subjects' sessions.
create or replace function subject_state_changed() returns trigger
language plpgsql
as $$
begin
    perform konklav_emit('entitlements.changed', jsonb_build_object('subjects', jsonb_build_array(new.id)));
    perform konklav_emit('subject.changed', jsonb_build_object('subject', new.id, 'state', new.state));
    return null;
end
$$;

-- Where this instance is in each peered identity provider's feed.
create table peer_cursor (
    provider text primary key,
    cursor bigint not null default 0,
    updated_at timestamptz not null default now()
);
