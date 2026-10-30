-- Indexes for the sweeper, which deletes what retention allows in batches.

create index challenge_expires_at_idx on challenge (expires_at);
create index challenge_session_idx on challenge (session_id) where session_id is not null;
create index login_attempt_attempted_at_idx on login_attempt (attempted_at);
create index client_assertion_expires_at_idx on client_assertion (expires_at);
create index bearer_assertion_expires_at_idx on bearer_assertion (expires_at);
create index session_revoked_at_idx on session (revoked_at) where revoked_at is not null;
create index session_parent_idx on session (parent_session_id) where parent_session_id is not null;
create index backchannel_logout_session_idx on backchannel_logout (session_id);

-- Delivery requests whose challenge material hasn't been erased yet.
create index event_delivery_material_idx on event (cursor)
    where kind = 'delivery.requested' and payload ? 'material';
