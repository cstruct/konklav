-- Federated credentials: an account at an identity provider, found by the
-- provider and the provider's subject (`<provider>|<hex of sub>`, since
-- identifiers are lowercased and `sub` is case-sensitive). The readable
-- `sub` and the email the provider reported are kept in `data`.
create or replace function credential_data_schema(kind text) returns json
language sql immutable parallel safe
as $$
    select case kind
        when 'password' then '{
            "type": "object",
            "additionalProperties": false,
            "required": ["hash"],
            "properties": {
                "hash": {"type": "string", "pattern": "^\\$argon2(id|i|d)\\$"}
            }
        }'::json
        when 'secret_key' then '{
            "type": "object",
            "additionalProperties": false,
            "required": ["a", "b"],
            "properties": {
                "a": {"$ref": "#/$defs/slot"},
                "b": {"$ref": "#/$defs/slot"}
            },
            "$defs": {
                "slot": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["hash", "created_at"],
                    "properties": {
                        "hash": {"type": "string", "pattern": "^\\$argon2(id|i|d)\\$"},
                        "created_at": {"type": "string", "format": "date-time"},
                        "expires_at": {"type": ["string", "null"], "format": "date-time"}
                    }
                }
            }
        }'::json
        when 'email_link' then '{"type": "object", "additionalProperties": false}'::json
        when 'phone_otp' then '{"type": "object", "additionalProperties": false}'::json
        when 'federated' then '{
            "type": "object",
            "additionalProperties": false,
            "required": ["provider", "subject"],
            "properties": {
                "provider": {"type": "string", "minLength": 1},
                "subject": {"type": "string", "minLength": 1},
                "email": {"type": ["string", "null"]},
                "email_verified": {"type": ["boolean", "null"]}
            }
        }'::json
    end
$$;

alter table credential drop constraint credential_kind_check;
alter table credential add constraint credential_kind_check
    check (kind in ('password', 'secret_key', 'email_link', 'phone_otp', 'federated'));

-- Federated login and linking keep `state`, `nonce` and the PKCE verifier as
-- a challenge until the identity provider redirects back.
alter table challenge drop constraint challenge_purpose_check;
alter table challenge add constraint challenge_purpose_check check (purpose in (
    'email_link', 'phone_code', 'mfa_email_code', 'invite', 'reset_password',
    'oidc_login', 'oidc_link'
));
