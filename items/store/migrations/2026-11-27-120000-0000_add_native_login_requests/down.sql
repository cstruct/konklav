delete from challenge where purpose in ('native_authorize', 'native_code');
alter table challenge drop constraint challenge_purpose_check;
alter table challenge add constraint challenge_purpose_check check (purpose in (
    'email_link', 'phone_code', 'mfa_email_code', 'invite', 'reset_password',
    'oidc_login', 'oidc_link', 'oidc_authorize', 'oidc_code',
    'passkey_register', 'passkey_login'
));
