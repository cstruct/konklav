-- The app backend's database, apart from Konklav's. Runs once, when the
-- Postgres volume is first initialised.
CREATE ROLE notes LOGIN PASSWORD 'notes';
CREATE DATABASE notes OWNER notes;
