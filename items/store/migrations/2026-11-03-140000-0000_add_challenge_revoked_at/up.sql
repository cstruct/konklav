-- When an operator revoked the challenge, such as an invite. A revoked
-- challenge is also consumed, so nothing can use it any more.
alter table challenge add column revoked_at timestamptz;
