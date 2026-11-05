drop table dpop_proof;
alter table oidc_client drop column require_dpop;
alter table session drop column dpop_jkt;
