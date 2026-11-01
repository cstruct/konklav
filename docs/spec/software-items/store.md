# Store Software Item

Stable implementation contracts owned by `konklav-store`, which owns
Konklav's PostgreSQL schema, migrations and repositories.

r[item.store.compile-snapshot]
`konklav-store` MUST read compile input (the catalog, the subject's state,
its active assignments and the newest event cursor) in one read-only
repeatable-read transaction, so that the revision it reports reflects
exactly the data it returns.

r[item.store.typed-data]
The database MUST reject kind-specific credential and MFA-factor data that
does not match the JSON Schema for its kind, so that every reader can decode
stored data without checking its shape again.
