drop trigger tenant_facts_changed on tenant;
drop function tenant_facts_changed();
alter table catalog_session_flag drop constraint catalog_session_flag_confine;
alter table catalog_session_flag drop column confine;
