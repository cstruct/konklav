# Platform

Repository-level and runtime requirements.

## Repository shape

r[platform.repo.spec-first]
User-facing capabilities MUST be described in Tracey-managed specifications
under `docs/spec/` before they are treated as implementation targets.

r[platform.repo.relying-agnostic]
Conclave code, specs and architecture notes MUST NOT depend on or name a
specific relying system. Relying-system concepts such as scope kinds, action
names, fact keys and session flags MUST enter Conclave only as catalog data.

## Runtime

r[platform.server.single-binary]
Conclave MUST run as one server binary that serves the subject-facing,
relying and control-plane surfaces.

r[platform.server.surface-separation]
The server MUST keep the three surfaces separately routable so that
deployments can expose them on different listeners or ingress paths.

r[platform.server.versioned-paths]
Every HTTP endpoint other than health checks and `/.well-known/*` MUST live
under a major-version prefix, starting with `/v1`.

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

r[platform.config.report-all-errors]
Configuration loading MUST report every problem it finds (unknown keys,
misplaced secrets, decode errors) together, not just the first one.

## Storage

r[platform.storage.postgres]
Conclave MUST persist its authoritative state in a PostgreSQL database that
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
