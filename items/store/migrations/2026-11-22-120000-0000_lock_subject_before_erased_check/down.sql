create or replace function subject_not_erased() returns trigger
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

create or replace function role_assignment_member_not_erased() returns trigger
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
