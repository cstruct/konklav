drop index session_identity_claims_ended;
alter table session
    drop constraint session_identity_claims_object,
    drop column identity_claims;
