delete from catalog_action where name = 'konklav:scopes:register';
drop table registered_scope;
drop function registered_scope_changed;
drop trigger catalog_scope_kind_containers_check on catalog_scope_kind;
drop function catalog_scope_kind_containers_check;
drop function registered_scope_check;
alter table role_assignment drop column scope_kind_registered;
alter table catalog_scope_kind
    drop constraint catalog_scope_kind_registered_key,
    drop column registered;
