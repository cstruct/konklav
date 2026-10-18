# Storage

## Postgres with Diesel

Conclave owns one Postgres database. Diesel gives compile-time-checked
queries against a generated `schema.rs`. `diesel-async` with a deadpool
pool keeps the server on tokio, and `diesel_migrations` embeds the
forward-only migrations so that readiness can confirm none are pending.

Diesel has no `LISTEN` support, so the one place that needs it (waking SSE
writers) uses a dedicated `tokio-postgres` connection. Nothing else depends
on it, and losing it only delays pushes until the next poll
(`r[feed.notify-hint-only]`).

## Required extensions

[pg_jsonschema](https://github.com/supabase/pg_jsonschema) validates `jsonb`
columns against JSON Schemas in check constraints. The migrations run
`create extension if not exists`, which needs elevated privileges, so
production databases should have it installed beforehand. The development
image in `dev/postgres` includes it.

## Credentials: one table, typed data

All credential kinds share the `credential` table. The common columns are
id, subject, kind, normalized login identifier, MFA requirement,
replacement link and revocation. Kind-specific material lives in `data
jsonb`, and a check constraint validates it with
`jsonb_matches_schema(credential_data_schema(kind), data)`.
`credential_data_schema` is an immutable SQL function holding one JSON Schema
per kind. The `kind` check lists only kinds that have a schema, so no
unvalidated data can slip through.

Compared with a base table plus one subtype table per kind, adding a kind is
a migration that extends `kind` and `credential_data_schema`, with no new
table, view or join. The schemas mirror the serde types in
`konklav-store`'s `credentials` module, and the two must change together.

## Shape

- Ordinary mutable tables with `created_at` and `updated_at`. Bitemporal
  history is not the default. Tables that need history (credentials,
  sessions) keep it explicitly, either as superseded rows with a reason or
  as revoked or expired rows kept for a retention period.
- UUIDv7 identifiers everywhere, including caller-supplied ones
  (`r[platform.idempotency.client-ids]`).
- `event` is the outbox, with columns `cursor bigserial`, `kind`, `subject`,
  `tenant`, `payload jsonb`, `created_at`. A helper inside the repository
  transaction writes events, so no state change can commit without its
  event (`r[platform.storage.transactional-events]`).
- The revision of any piece of state is the cursor of the last event that
  touched it. There are no separate revision counters to keep in sync.

## Events from triggers

Session and signing-key events are appended by repository code, because
their payloads come from the change itself. Authorization events
(`entitlements.changed`, `tenant.changed`) are appended by triggers through
`konklav_emit(kind, payload)`, so every write path invalidates, bulk SQL
included. Writes report their cursor with
`events::last_in_transaction`, which finds the newest event whose `xmin` is
the current transaction.

## Entitlement storage

Entitlement sets are compiled on demand by `konklav-authz` from the
current rows and cached in the server process, keyed by (subject, tenant)
and invalidated by the server's own outbox events.

Materializing compiled entitlements into tables is a later optimization if
compile cost turns out to matter. The pure compiler makes that a storage
decision, not a semantic one.

## Retention

The outbox, revoked sessions, used challenges and superseded credentials
are pruned by a background job according to configured retention periods.
