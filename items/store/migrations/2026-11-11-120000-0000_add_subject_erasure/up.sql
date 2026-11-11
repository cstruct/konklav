-- Erasure: removing the personal data Konklav holds about one subject
-- (`subject.erasure.*`). `subjects::erase` does the removing; this adds the
-- `erased` state, lets an ended session outlive its credential, and makes
-- the database refuse to attach anything to an erased subject.

-- Erasing can't be undone, so it has a capability of its own.
-- `konklav:control:all` grants it like every other.
insert into catalog_action (name, description, builtin) values
    ('konklav:subjects:erase', 'Erase subjects and all personal data held about them', true);

-- An erased subject keeps its row: the id, kind and state, with the time.
alter table subject
    drop constraint subject_state_check,
    add constraint subject_state_check check (state in ('active', 'disabled', 'erased')),
    add column erased_at timestamptz,
    add constraint subject_erased_at check ((state = 'erased') = (erased_at is not null));

-- For reading the erased subjects in the order they were erased.
create index subject_erased_idx on subject (erased_at, id) where erased_at is not null;

-- Erased is final.
create function subject_stays_erased() returns trigger
language plpgsql
as $$
begin
    raise exception 'subject % is erased', old.id
        using errcode = 'check_violation', constraint = 'subject_erased';
end
$$;

create trigger subject_stays_erased
before update or delete on subject
for each row when (old.state = 'erased')
execute function subject_stays_erased();

-- Erasure deletes credentials at once, while ended sessions are kept for
-- their retention. So an ended session may have no credential.
alter table session
    alter column credential_id drop not null,
    drop constraint session_credential_id_fkey,
    add constraint session_credential_id_fkey
        foreign key (credential_id) references credential (id) on delete set null,
    add constraint session_credential_until_ended
        check (credential_id is not null or revoked_at is not null);

-- Refuses a row that names an erased subject in the column given as the
-- trigger's argument. As a trigger, no write path can skip it, bulk SQL
-- from importers included. It locks the subject row like a foreign-key
-- check does, so it waits for an erasure in progress and then sees it.
create function subject_not_erased() returns trigger
language plpgsql
as $$
declare
    target uuid := (to_jsonb(new) ->> tg_argv[0])::uuid;
begin
    if target is not null
        and exists (select 1 from subject where id = target and state = 'erased' for key share)
    then
        raise exception 'subject % is erased', target
            using errcode = 'check_violation', constraint = 'subject_erased';
    end if;
    return new;
end
$$;

create trigger credential_subject_not_erased before insert on credential
for each row execute function subject_not_erased('subject_id');
create trigger mfa_factor_subject_not_erased before insert on mfa_factor
for each row execute function subject_not_erased('subject_id');
create trigger challenge_subject_not_erased before insert on challenge
for each row execute function subject_not_erased('subject_id');
create trigger session_subject_not_erased before insert on session
for each row execute function subject_not_erased('subject_id');
create trigger session_impersonator_not_erased before insert on session
for each row execute function subject_not_erased('impersonator_subject_id');
create trigger membership_subject_not_erased before insert on membership
for each row execute function subject_not_erased('subject_id');
-- An erased subject's memberships are ended and hold no facts. Updates that
-- keep them so, such as a statement over a whole tenant, pass.
create trigger membership_subject_stays_erased before update on membership
for each row when (new.state = 'active' or new.facts <> '{}'::jsonb)
execute function subject_not_erased('subject_id');
create trigger role_assignment_subject_not_erased before insert or update on role_assignment
for each row execute function subject_not_erased('subject_id');
create trigger oidc_client_subject_not_erased
before insert or update of service_subject_id on oidc_client
for each row execute function subject_not_erased('service_subject_id');

-- Role assignments at a membership name the subject through it. Their own
-- trigger has already checked the membership exists.
create function role_assignment_member_not_erased() returns trigger
language plpgsql
as $$
declare
    target uuid := (select subject_id from membership where id = new.membership_id);
begin
    if exists (select 1 from subject where id = target and state = 'erased' for key share) then
        raise exception 'subject % is erased', target
            using errcode = 'check_violation', constraint = 'subject_erased';
    end if;
    return new;
end
$$;

create trigger role_assignment_member_not_erased
before insert or update on role_assignment
for each row when (new.membership_id is not null)
execute function role_assignment_member_not_erased();

-- Erasure finds a membership's row versions by key, and stored delivery
-- requests by kind.
create index row_version_key_idx on row_version (relation, key);
create index event_delivery_idx on event (cursor) where kind = 'delivery.requested';
