-- `jti`s of JWT bearer assertions (workload tokens from identity
-- providers) already exchanged, until they expire, so none is accepted
-- twice.
create table bearer_assertion (
    issuer text not null,
    jti text not null,
    expires_at timestamptz not null,
    primary key (issuer, jti)
);
