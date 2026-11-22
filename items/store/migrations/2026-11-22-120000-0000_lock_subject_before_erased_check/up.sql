-- `subject_not_erased` and `role_assignment_member_not_erased` looked for an
-- erased subject with `where ... state = 'erased' for key share`. A row is
-- only locked when it passes the `where`, and while an erasure is still
-- uncommitted the subject doesn't, so the triggers didn't wait for it. The
-- write then committed after the erasure's deletes and survived it.
--
-- They now lock the subject row first, whatever its state, and look at the
-- state after. Under READ COMMITTED the lock waits for an erasure in
-- progress and returns the row as the erasure left it.
create or replace function subject_not_erased() returns trigger
language plpgsql
as $$
declare
    target uuid := (to_jsonb(new) ->> tg_argv[0])::uuid;
    found text;
begin
    if target is not null then
        select state into found from subject where id = target for key share;
        if found = 'erased' then
            raise exception 'subject % is erased', target
                using errcode = 'check_violation', constraint = 'subject_erased';
        end if;
    end if;
    return new;
end
$$;

create or replace function role_assignment_member_not_erased() returns trigger
language plpgsql
as $$
declare
    target uuid := (select subject_id from membership where id = new.membership_id);
    found text;
begin
    select state into found from subject where id = target for key share;
    if found = 'erased' then
        raise exception 'subject % is erased', target
            using errcode = 'check_violation', constraint = 'subject_erased';
    end if;
    return new;
end
$$;
