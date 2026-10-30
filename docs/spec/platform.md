# Platform

Repository-level and runtime requirements.

## Repository shape

r[platform.repo.spec-first]
User-facing capabilities MUST be described in Tracey-managed specifications
under `docs/spec/` before they are treated as implementation targets.

r[platform.repo.relying-agnostic]
Konklav code, specs and architecture notes MUST NOT depend on or name a
specific relying system. Relying-system concepts such as scope kinds, action
names, fact keys and session flags MUST enter Konklav only as catalog data.

## Runtime

r[platform.server.single-binary]
Konklav MUST run as one server binary that serves the subject-facing,
relying and control-plane surfaces.

r[platform.server.surface-separation]
The server MUST keep the three surfaces separately routable so that
deployments can expose them on different listeners or ingress paths.

r[platform.server.versioned-paths]
Every HTTP endpoint other than health checks and `/.well-known/*` MUST live
under a major-version prefix, starting with `/v1`.

r[platform.server.client-address]
The server MUST take a client's address from the connection, unless the
connection comes from a configured trusted proxy. Then it MUST use the last
address in `X-Forwarded-For` that is not a trusted proxy, so clients can't
choose their own address by sending the header.

r[platform.server.limits]
Every listener MUST bound request body size, how long a request may take to
be answered, and how many requests it serves at once, refusing the excess
with a typed error. Change-feed streams MUST count against the time bound
only until they start.

r[platform.server.health]
The server MUST expose a liveness endpoint and a readiness endpoint. The
readiness endpoint MUST fail while the database is unreachable or migrations
are pending.

## Configuration

r[platform.config.layered]
Runtime configuration MUST be loaded from layered sources (files, then
environment) so that each value's winning source can be reported.

r[platform.config.secrets-separate]
Secret-bearing configuration MUST load only from secret sources (secret
files or files they reference). The environment and command-line flags MUST
NOT supply secret values, though they MAY locate secret files.

r[platform.config.bootstrap-token]
A bootstrap control-plane token MUST be at least 32 characters, or the
server MUST refuse to start. Its use MUST be logged, the server MUST warn
at startup while one is configured, and it MUST stop being accepted after
its configured expiry.

r[platform.config.report-all-errors]
Configuration loading MUST report every problem it finds (unknown keys,
misplaced secrets, decode errors) together, not just the first one.

## Storage

r[platform.storage.postgres]
Konklav MUST persist its authoritative state in a PostgreSQL database that
it owns exclusively. Relying systems MUST NOT read or write that database
directly.

r[platform.storage.forward-migrations]
Schema changes MUST be applied as forward-only migrations that the server
can verify at startup.

r[platform.storage.transactional-events]
Every state change that produces a change-feed event MUST write that event
in the same database transaction as the change itself.

## Errors

r[platform.error.typed-codes]
Every error response MUST carry a stable machine-readable code in
`SCREAMING_SNAKE_CASE` and a human-readable message. Clients MUST be able to
rely on codes, not messages.

r[platform.error.no-enumeration]
Authentication failures MUST NOT reveal whether a login identifier, subject
or credential exists.

r[platform.error.retry-after]
A `RATE_LIMITED` response MUST carry a `Retry-After` header whose value
includes random jitter, so that clients refused at the same time don't
retry at the same time.

## Idempotency

r[platform.idempotency.client-ids]
Control-plane create operations for tenants, subjects and memberships MUST
accept a caller-supplied identifier and MUST be idempotent on that
identifier: repeating an identical request succeeds, and repeating it with
conflicting content fails with a typed conflict error.

r[platform.idempotency.write-cursor]
Every successful state-changing response MUST include the change-feed cursor
of the last event the change produced, so that callers can wait for their
own writes to propagate.

## Import

r[import.idempotent]
Konklav MUST offer a bulk import of subjects, credentials, MFA factors and
sessions that keeps the imported identifiers and can be re-run: records
whose identifiers already exist are skipped. Import MUST require a
dedicated control-plane capability.

r[import.credentials]
Imported password and secret-key credentials MUST be accepted as Argon2
hashes and stored as given, so existing secrets keep working.

r[import.credentials.secret-key-rotation]
Re-importing an active secret-key credential with different slots MUST
replace its slots, so a source system that still rotates keys before
cutover stays in step. Other credential kinds MUST NOT be changed by a
re-import.

r[import.mfa]
Imported TOTP seeds MUST be encrypted with Konklav's own keys on arrival.

r[import.sessions]
Imported sessions MUST keep their identifiers, versions and expiry, with a
refresh-token hash supplied by the importer, so that people stay signed in
across a migration.

## Bootstrap

r[bootstrap.command]
The server binary MUST offer a `bootstrap` command that reads a bootstrap
set from files and applies it to the database directly, without serving
any surface. It MUST refuse to run while migrations are pending.

r[bootstrap.formats]
The command MUST accept flat tables (CSV, one file per kind of record,
with a fixed header) and nested documents (Styx), and MUST accept both in
one run, read into a single bootstrap set.

r[bootstrap.contents]
A bootstrap set MAY contain the action catalog, templates, tenants,
subjects, credentials (federated ones included), MFA factors, memberships,
membership and global role assignments, and sessions.

r[bootstrap.ids]
Every record's identifier MUST be resolved the same way in both formats:
- an identifier that is a UUID MUST be used as given
- any other identifier is an external id, and MUST become UUID version 5
  of the set's id namespace and `<kind>:<external id>`
- in nested documents, a record without an identifier is found by its
  natural key: a tenant's key MUST be treated as its external id, and a
  subject MUST be the one with an active credential for its login
  identifier, or else a new subject

A set that uses external ids or tenant keys MUST declare an id namespace.
Flat tables MUST give every record an identifier.

r[bootstrap.idempotent]
Applying a bootstrap set MUST create the records that don't exist and skip
those that exist with the same content. A record that exists with
different content MUST be reported as a conflict, except that secret-key
slots are replaced as `import.credentials.secret-key-rotation` describes.
Applying MUST NOT delete or change anything the set doesn't name.

r[bootstrap.validate-first]
Before writing anything, the command MUST read every file, resolve every
identifier and reference, check the set against the catalog (in the set or
already stored), and report every problem it finds together, each with its
file and line.

r[bootstrap.atomic]
A run MUST apply in one transaction: either everything in the set is
applied or nothing is. A conflict MUST fail the run.

r[bootstrap.dry-run]
The command MUST offer a dry run that does everything except commit, and
reports how many records of each kind would be created, skipped or in
conflict.

r[bootstrap.secrets]
Passwords and secret keys MUST arrive as Argon2 hashes, as
`import.credentials` describes. Plaintext passwords MUST be refused unless
the run explicitly allows them, and are then hashed before they are
stored. TOTP seeds MUST be encrypted on arrival, as `import.mfa` describes.

r[bootstrap.events]
Applying a bootstrap set MUST emit the same events as the equivalent
control-plane writes, in the same transaction, so relying systems see the
result on the change feed.
