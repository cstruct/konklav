-- Restrictive session flags every session started with the credential
-- carries, such as a relying system's flag for passwordless sessions.
alter table credential add column session_flags text[] not null default '{}';
