-- DPoP (RFC 9449). A bound session's key thumbprint, set when the session
-- is created and never changed.
alter table session add column dpop_jkt text;

-- Whether a client's grants must come with a DPoP proof.
alter table oidc_client add column require_dpop boolean not null default false;

-- `jti`s of DPoP proofs Konklav accepted, per key, until the proofs are too
-- old to pass the freshness check, so none is accepted twice.
create table dpop_proof (
    jkt text not null,
    jti text not null,
    expires_at timestamptz not null,
    primary key (jkt, jti)
);

create index dpop_proof_expires_at_idx on dpop_proof (expires_at);
