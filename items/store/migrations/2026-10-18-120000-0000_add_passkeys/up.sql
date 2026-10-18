-- Passkeys: `public_key` credentials, identified by their WebAuthn
-- credential ID. `state` is the verifier's serialised view of the key
-- (public key, algorithm, signature counter), versioned so a later
-- library upgrade can migrate it; the store does not interpret it.
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
        when 'client' then '{"type": "object", "additionalProperties": false}'::json
        when 'public_key' then '{
            "type": "object",
            "additionalProperties": false,
            "required": ["label", "attestation_format", "state_version", "state"],
            "properties": {
                "label": {"type": "string", "minLength": 1, "maxLength": 100},
                "attestation_format": {"type": "string", "minLength": 1},
                "last_used_at": {"type": ["string", "null"], "format": "date-time"},
                "state_version": {"const": 1},
                "state": {"type": "object"}
            }
        }'::json
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
    check (kind in ('password', 'secret_key', 'email_link', 'phone_otp', 'federated', 'client', 'public_key'));

-- Ceremony state for registering a passkey and for logging in or stepping
-- up with one lives in `details` until the ceremony finishes.
alter table challenge drop constraint challenge_purpose_check;
alter table challenge add constraint challenge_purpose_check check (purpose in (
    'email_link', 'phone_code', 'mfa_email_code', 'invite', 'reset_password',
    'oidc_login', 'oidc_link', 'oidc_authorize', 'oidc_code',
    'passkey_register', 'passkey_login'
));
