drop table share_action;
drop table share;
drop function share_action_changed;
drop function share_changed;
delete from catalog_fact where target = 'share' or value_type = 'date_range';
alter table catalog_fact
    drop constraint catalog_fact_share_not_portable,
    drop constraint catalog_fact_value_type_check,
    add constraint catalog_fact_value_type_check
        check (value_type in ('string', 'integer', 'boolean', 'string_list')),
    drop constraint catalog_fact_target_check,
    add constraint catalog_fact_target_check check (target in ('tenant', 'membership'));
