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

## Retention

r[retention.sweep]
A sweeper MUST periodically delete what retention allows, in batches of a
bounded size, so that no table grows without bound. With several server
instances on one database, at most one sweeper MUST run at a time.

r[retention.challenges]
A challenge MUST be deleted once it has expired, but not before the longest
send-limit window has passed since it was created, since send limits count
challenges.

r[retention.batch-results]
A remembered batch answer MUST be deleted once its idempotency key's
lifetime has passed (`platform.batch.key-lifetime`).

r[retention.login-attempts]
A login attempt MUST be deleted once the longest rate-limit window has
passed since it was made.

r[retention.assertions]
A recorded client-assertion, bearer-assertion or DPoP-proof identifier
MUST be deleted once the assertion or proof it was recorded for has expired
(for a DPoP proof: once it is too old to pass the freshness check).

r[retention.sessions]
A session MUST be deleted a configured period after it expired or was
revoked, together with its refresh history and the challenges that refer to
it. A session MUST NOT be deleted while it has not ended, while a
back-channel logout for it is pending, or while an impersonation session
started from it is kept.

r[retention.delivery-material]
The challenge material in a stored `delivery.requested` event MUST be erased
once the challenge has expired, not only withheld from the feed.

r[retention.identity-claims]
Claims passed from an identity provider MUST be erased from a session once
it has been revoked or has expired, without waiting for the session itself
to be deleted.

r[retention.history]
A row version MUST be deleted once history's configured retention has
passed since it stopped being current. A current row version MUST NOT be
deleted, however old.

## History

r[history.config]
History MUST be off unless configuration enables it, and its retention
MUST be configurable.

r[history.record]
While history is enabled, every write to a subject, tenant, membership, the
action catalog, a template, role, policy, role assignment, share or
registered scope MUST keep the row version it replaces, including when the
row is deleted, in the same transaction as the write. Enabling history MUST
record every such row as it is then, and history MUST NOT claim to know
anything earlier.

r[history.disabled]
While history is disabled, nothing MUST be recorded, and disabling it MUST
discard the row versions recorded so far, since they could no longer be
trusted.

r[history.as-of]
Reading the state as of a time within the history horizon MUST return
exactly the row versions that were current then, and MUST NOT change the
current state.

## Telemetry

Konklav exports telemetry over OTLP to any collector or backend that
accepts it. Telemetry is for operators; relying systems use the change feed.

r[telemetry.init]
Telemetry MUST be set up from configuration before the server is built,
with the providers of the enabled signals installed globally, and MUST be
flushed and shut down when the server stops.

r[telemetry.endpoints]
A signal MUST be exported to its own endpoint when one is configured, used
as is, and otherwise to the OTLP endpoint, with the signal's path (such as
`/v1/metrics`) appended over HTTP. Without either, the standard
`OTEL_EXPORTER_OTLP_*` environment variables MUST apply. Export headers are
secret configuration.

r[telemetry.privacy]
Telemetry MUST NOT record login identifiers, secrets, tokens, codes, client
addresses or request paths. Requests MUST be named by their route template,
never by a path with ids in it.

r[telemetry.metrics]
When metrics are enabled, they MUST be exported periodically over OTLP, with
the configured service name and resource attributes. Their attributes MUST
be low-cardinality: surfaces, route templates, methods, status codes, error
codes, kinds and outcomes.

r[telemetry.metrics.requests]
The duration of every request MUST be recorded as
`http.server.request.duration`, with its method, route template, status
code, the surfaces of its listener and, for an error response, its error
code. Requests refused before routing, for being too many or taking too
long, MUST be counted by reason.

r[telemetry.metrics.internals]
Konklav MUST record:
- how long password hashing waited for a slot, and how many slots are busy
- access tokens issued, by kind
- open change-feed streams
- back-channel logout deliveries, by outcome
- rows the sweeper deleted, by kind
- the database pool's connections, by whether they are in use
- outbound HTTP requests, by operation and outcome

r[telemetry.traces]
When traces are enabled, spans MUST be exported over OTLP in batches with
the configured service name and resource attributes. The configured share
of traces Konklav starts MUST be sampled, and a trace continued from a
caller MUST follow the caller's sampling decision.

r[telemetry.traces.requests]
Every request MUST be a server span named by its method and route template,
continuing the trace named by its W3C `traceparent` header, if any. The span
MUST record the status code and error code, and MUST be failed when the
response is a server error.

r[telemetry.traces.outbound]
Requests to identity providers, their key sets, back-channel logout
endpoints and the claims hook MUST be client spans named by operation, failed when they fail,
and MUST carry the trace in a `traceparent` header. Sweeps, back-channel
logout runs and peer syncs MUST be spans of their own.

r[telemetry.logs]
Logs MUST be written to stderr, filtered by the configured level, or by
`RUST_LOG` when set, as human-readable text or as one JSON object per line.
A JSON line MUST carry its time, level, target, message and fields, the
spans it is in, and the trace and span ids when traced. An invalid level
MUST be refused.

r[telemetry.logs.export]
When log export is enabled, logs MUST be sent over OTLP in batches with the
trace context of the span they were logged in, filtered by the same level,
leaving out what the exporters themselves log.

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
Every control-plane create operation MUST accept a caller-supplied
identifier and MUST be idempotent on that identifier: repeating an
identical request succeeds without applying it again, and repeating it
with conflicting content fails with a typed conflict error. Where the
first answer showed a generated secret, which Konklav keeps only hashed,
an identical repeat MUST generate a new secret, show it, and stop
accepting the first. A repeated invite MUST NOT be delivered again.

r[platform.idempotency.write-cursor]
Every successful state-changing response MUST include the change-feed cursor
of the last event the change produced, so that callers can wait for their
own writes to propagate.

## Batches

r[platform.batch.atomic]
The control plane MUST offer a batch: one request holding an ordered list
of control-plane operations, applied in order in one database transaction.
Either every operation is applied or none is.

r[platform.batch.operations]
Each operation in a batch MUST name a method, a control-plane path without
its version prefix (with an optional query string), and the request body
the operation takes on its own. A batch MUST accept only `PUT`, `POST` and
`DELETE` operations, and MUST NOT contain a batch.

r[platform.batch.same-as-alone]
Each operation in a batch MUST be routed, authorized, validated and
answered exactly as it would be on its own, against the capabilities of
the batch's caller. A batch MUST NOT add an operation that doesn't exist
on its own.

r[platform.batch.limits]
A batch MUST hold at most a configured number of operations, 100 by
default, and MUST count as one request against `platform.server.limits`.
An empty batch is invalid.

r[platform.batch.results]
A batch that succeeds MUST answer with each operation's status and body,
in order, as the operation would have answered alone, and with the
change-feed cursor of the last event the whole batch produced, if it
produced any (`platform.idempotency.write-cursor`).

r[platform.batch.failure]
A batch whose operation fails MUST commit nothing and MUST answer with
that operation's status and error, with the operation's position in the
batch, counted from zero, added to the error as `operation`.

r[platform.batch.idempotency-key]
A batch MAY carry an idempotency key. A repeat of a batch with the same
key, from the same caller and with the same operations, MUST answer what
the first answered without applying anything again, except that secrets
the first answer showed are generated anew and shown, as for
`platform.idempotency.client-ids`. The same key with other operations MUST
fail with a typed conflict error. Only a batch that committed is
remembered, so a failed batch may be repeated with its key.

r[platform.batch.key-lifetime]
Konklav MUST remember an idempotency key for a configured time, 10 minutes
by default, and for longer when the batch asks, up to a configured maximum
of 1 hour by default.

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

r[bootstrap.format.version]
A bootstrap set's tables and documents MUST follow a bootstrap format
version, `major.minor`, which is separate from Konklav's release version. A
new minor version MUST only add: a new optional table, column or key. Any
other change, such as removing or renaming a table, column or key, making
one required, or changing what a value means, MUST be a new major version.

r[bootstrap.format.declare]
A set MAY declare its format version as the top-level `format` key of any
of its nested documents; flat tables can't declare it. Declarations that
differ MUST be reported as a problem. A set that declares none is format 1.0.

r[bootstrap.format.read]
The command MUST read a set of its own major format version at any minor
version up to its own. It MUST refuse a set of a newer minor version or of
another major version before reading its records, with one problem at the
declaration that names the version the set needs and the newest it reads.
A set of an older major version MAY instead be upgraded in memory to the
current format after it is read, so that applying sees one shape.

r[bootstrap.format.export]
The `export` command MUST declare the current format version in the set it
writes.

r[bootstrap.format.released]
Every released format version MUST keep a frozen set that the command
still reads and applies. A change to the tables, columns or keys MUST be
checked against the latest released format version, so that the current
version is that version bumped as the change needs: unchanged, the next
minor version or the next major version.

r[bootstrap.contents]
A bootstrap set MAY contain the action catalog, templates, tenants,
subjects, credentials (federated ones included), MFA factors, memberships,
membership and global role assignments, and sessions.

r[bootstrap.metadata]
Templates and roles in a bootstrap set MAY carry metadata, a JSON object.
It MUST be stored as the control plane stores a template's or role's
metadata, and it is part of the record's content when a run compares the
record with a stored one.

r[bootstrap.ids]
Every record's identifier MUST be resolved the same way in both formats:
- an identifier that is a UUID MUST be used as given
- any other identifier is an external id, and MUST become UUID version 5
  of the set's id namespace and `<kind>:<external id>`
- in nested documents, a record without an identifier is found by its
  natural key:
  - a tenant's key MUST be treated as its external id
  - a subject MUST be the one with an active credential for its login
    identifier, or else a new subject, which the set MUST give a credential
    for that identifier
  - a credential MUST be the active one of its kind for its login
    identifier, and a membership the subject's active one in the tenant,
    or else a new one
  - an MFA factor MUST be identified by its subject and its position among
    that subject's factors in the set

A set that uses external ids or tenant keys MUST declare an id namespace.
Flat tables MUST give every record an identifier.

r[bootstrap.idempotent]
Applying a bootstrap set MUST create the records that don't exist and skip
those that exist with the same content. A record that exists with
different content MUST be reported as a conflict, with two exceptions:
secret-key slots are replaced as `import.credentials.secret-key-rotation`
describes, and a session that exists is skipped, since sessions change as
they are used. The set's catalog MUST be merged into the stored one: its
new entries are added, and an entry it declares differently from the
stored one is a conflict. Applying MUST NOT delete or change anything the
set doesn't name.

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

r[bootstrap.export]
An `export` command MUST write the database's catalog, templates, tenants,
roles, subjects, credentials with their hashes, MFA factors, memberships
and role assignments as a bootstrap set that `bootstrap` applies to an
empty database without problems or conflicts, so that exporting that
database writes the same set. It MUST read the database directly, never
the control plane, and MUST NOT write sessions or signing keys. It MUST
report what it left out because a bootstrap set can't hold it.

r[bootstrap.events]
Applying a bootstrap set MUST emit the same events as the equivalent
control-plane writes, in the same transaction, so relying systems see the
result on the change feed.
