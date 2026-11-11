drop trigger role_changed on role;
create trigger role_changed after insert or update or delete on role
for each statement execute function definitions_changed();
drop trigger template_changed on template;
create trigger template_changed after insert or update or delete on template
for each statement execute function definitions_changed();
drop trigger share_changed on share;
create trigger share_changed after insert or update on share
for each row execute function share_changed();
drop trigger membership_changed on membership;
create trigger membership_changed after insert or update or delete on membership
for each row execute function membership_changed();

drop trigger subject_metadata_changed on subject;
drop trigger credential_metadata_changed on credential;
drop trigger challenge_metadata_changed on challenge;
drop trigger tenant_metadata_changed on tenant;
drop trigger membership_metadata_changed on membership;
drop trigger share_metadata_changed on share;
drop trigger oidc_client_metadata_changed on oidc_client;
drop trigger template_metadata_changed on template;
drop trigger role_metadata_changed on role;
drop function metadata_changed();

drop index challenge_invite_metadata_idx;
drop index challenge_invite_idx;
update row_version set data = data - 'metadata'
where relation in ('subject'::regclass, 'tenant'::regclass, 'membership'::regclass, 'share'::regclass);

alter table oidc_client drop column metadata;
alter table share drop column metadata;
alter table membership drop column metadata;
alter table tenant drop column metadata;
alter table challenge drop column metadata;
alter table credential drop column metadata;
alter table subject drop column metadata;
