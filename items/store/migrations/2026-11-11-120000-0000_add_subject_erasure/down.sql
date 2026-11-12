drop index event_metadata_idx;
drop index event_delivery_idx;
drop index row_version_key_idx;
drop trigger role_assignment_member_not_erased on role_assignment;
drop function role_assignment_member_not_erased();
drop trigger oidc_client_subject_not_erased on oidc_client;
drop trigger role_assignment_subject_not_erased on role_assignment;
drop trigger membership_subject_stays_erased on membership;
drop trigger membership_subject_not_erased on membership;
drop trigger session_impersonator_not_erased on session;
drop trigger session_subject_not_erased on session;
drop trigger challenge_subject_not_erased on challenge;
drop trigger mfa_factor_subject_not_erased on mfa_factor;
drop trigger credential_subject_not_erased on credential;
drop function subject_not_erased();
alter table session
    drop constraint session_credential_until_ended,
    drop constraint session_credential_id_fkey,
    add constraint session_credential_id_fkey foreign key (credential_id) references credential (id);
delete from session where credential_id is null;
alter table session alter column credential_id set not null;
drop trigger subject_stays_erased on subject;
drop function subject_stays_erased();
drop index subject_erased_idx;
delete from subject where state = 'erased';
alter table subject
    drop constraint subject_erased_at,
    drop column erased_at,
    drop constraint subject_state_check,
    add constraint subject_state_check check (state in ('active', 'disabled'));
delete from catalog_action where name = 'konklav:subjects:erase';
