delete from row_version where relation = 'catalog_vouch'::regclass;
delete from history_table where relation = 'catalog_vouch'::regclass;
drop table catalog_vouch;
