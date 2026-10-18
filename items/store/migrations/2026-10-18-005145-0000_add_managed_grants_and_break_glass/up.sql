-- Grants an identity provider's claim mapping created, so that later logins
-- can remove exactly those (and never grants made any other way).
alter table membership add column managed_by text;
alter table role_assignment add column managed_by text;

create index membership_managed_idx on membership (subject_id, managed_by)
    where managed_by is not null;
create index role_assignment_managed_idx on role_assignment (managed_by)
    where managed_by is not null;

-- Local operator credentials for when every upstream is unavailable. Each
-- login with one appends `break_glass.used`.
alter table credential add column break_glass boolean not null default false;
