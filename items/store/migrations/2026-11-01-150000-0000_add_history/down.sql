do $$
declare
    tracked regclass;
begin
    for tracked in select relation from history_table loop
        execute format('drop trigger history_record on %s', tracked);
    end loop;
end
$$;
drop function history_shadow;
drop function history_configure;
drop function history_record;
drop function history_key;
drop function history_lock_key;
drop table row_version;
drop table history_table;
drop table history_setting;
