-- Bulk import of existing identity data (pre-hashed credentials, sessions,
-- MFA seeds) from a system Conclave replaces.
insert into catalog_action (name, description, builtin) values
    ('conclave:import', 'Import subjects, credentials, MFA factors and sessions in bulk', true);
