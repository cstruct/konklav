-- Access requests: a signed-in subject asks for a membership in a tenant,
-- and an operator approves (creating the membership) or denies it. A
-- request holds ids, a state and times, nothing that describes the person.
create table access_request (
    id uuid primary key,
    subject_id uuid not null references subject (id),
    tenant_id uuid not null references tenant (id),
    state text not null default 'pending'
        check (state in ('pending', 'approved', 'denied', 'withdrawn')),
    -- The membership an approval created or found.
    membership_id uuid references membership (id),
    created_at timestamptz not null default now(),
    decided_at timestamptz,
    -- Who approved, denied or withdrew it; none for the bootstrap token or
    -- erasure.
    decided_by uuid references subject (id),
    constraint access_request_decided check ((state = 'pending') = (decided_at is null)),
    constraint access_request_approved check ((state = 'approved') = (membership_id is not null))
);

-- At most one pending request per subject and tenant.
create unique index access_request_pending_idx on access_request (subject_id, tenant_id)
    where state = 'pending';
-- Listings, newest first, by tenant and by subject.
create index access_request_tenant_idx on access_request (tenant_id, id);
create index access_request_subject_idx on access_request (subject_id, id);

-- Nothing is asked for an erased subject.
create trigger access_request_subject_not_erased before insert on access_request
for each row execute function subject_not_erased('subject_id');

-- A tenant capability: granted through tenant roles, it lets a member decide
-- the access requests to that tenant on the subject-facing surface.
insert into catalog_action (name, description, builtin) values
    ('konklav:tenant:admit', 'List, approve and deny access requests to the tenant on the subject-facing surface', true);
