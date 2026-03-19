# Typed Temporal Feldera Store

This note defines task 1 of the control-plane implementation plan: replacing the generic managed-event bucket with typed temporal Feldera tables and typed current-state views.

## Naming decision

The typed store keeps `lower_snake_case` as the canonical spelling for tables, views, and columns.

The first implementation used unquoted identifiers to align with the existing generated authorization SQL, which already emits names such as `action_catalog` and `managed_role_templates`.

Real-manager verification against Feldera `v0.268.0` showed that this is not cleanly valid for every object name. In particular, `session` is rejected as a reserved name even when quoted. The fallback is therefore active for reserved-name collisions:

- keep the canonical spelling in `lower_snake_case`
- use quoted SQL identifiers where Feldera accepts them
- if a reserved word still collides, use a stable disambiguated backing-table name such as `session_state` while preserving entity-facing view names such as `current_session`
- continue deserializing query results with both lowercase field names and uppercase aliases so response-shape differences do not leak into the rest of the server

## Managed tables

Each managed table is append-only. Committed history is exposed through a `versioned_*` materialized view and current state is exposed through a `current_*` materialized view.

Shared managed columns:

- stable key columns for the entity kind
- `apply_id`
- `row_version`
- `valid_from`
- `deleted`

The `versioned_*` views derive `valid_to` by looking for the next committed row for the same logical entity key. The `current_*` views select rows whose derived `valid_to` is `NULL` and whose `deleted` flag is `FALSE`.

Managed entity keys and version scope:

- `tenant`
  - key: `tenant_id`
  - version scope: one stream per tenant
- `subject`
  - key: `subject_id`
  - version scope: one stream per subject
- `membership`
  - key: `tenant_id`, `subject_id`
  - version scope: one stream per tenant membership
- `assumption_grant`
  - key: `subject_id`, `source_tenant_id`, `target_tenant_id`
  - version scope: one stream per delegated assumption grant
- `action`
  - key: `action_name`
  - version scope: one stream per action symbol
- `template`
  - key: `tenant_id`, `template_key`
  - version scope: one stream per tenant-local template
- `role`
  - key: `tenant_id`, `role_key`
  - version scope: one stream per tenant-local role

Entity-specific payload columns:

- `tenant`
  - `display_name`, `parent_tenant_id`, `state`
- `subject`
  - `display_name`
- `membership`
  - `roles_json`, `facts_json`
- `assumption_grant`
  - `target_roles_json`, `ttl_seconds`
- `action`
  - `description`
- `template`
  - `source_tenant_id`, `source_template_key`, `source_mode`, `policies_json`
- `role`
  - `template_key`, `policies_json`

`roles_json`, `facts_json`, and `policies_json` remain JSON-encoded columns for now. That keeps the storage surface typed by entity kind without reintroducing a generic multi-kind bucket, and leaves room for later normalization when task 4 expands compiled authorization views.

## Runtime-auth tables

Runtime-auth rows are also typed temporal rows, but they use `change_id` instead of `apply_id` because they are not produced by managed apply.

Shared runtime-auth columns:

- stable key columns for the entity kind
- `change_id`
- `row_version`
- `valid_from`
- `deleted`

Runtime-auth entity keys and version scope:

- `invite`
  - key: `invite_id`
  - version scope: one stream per invite
- `subject_credential`
  - key: `subject_id`
  - version scope: one stream per subject credential record
- `session_state`
  - key: `session_id`
  - version scope: one stream per session

Entity-specific payload columns:

- `invite`
  - `subject_id`, `redeem_code_hash`, `created_at`, `expires_at`, `redeemed_at`
- `subject_credential`
  - `salt`, `password_hash`, `credential_valid_to`
- `session`
  - `subject_id`, `tenant_id`, `created_at`, `last_seen_at`, `session_valid_to`

Runtime-auth views follow the same `versioned_*` and `current_*` pattern as managed tables. The current implementation uses `session_state` as the backing table for the logical `session` entity because Feldera reserves `session` as a predefined function name.

## Current-state read model

Server read paths should query typed `current_*` views directly:

- `current_tenant`
- `current_subject`
- `current_membership`
- `current_assumption_grant`
- `current_action`
- `current_template`
- `current_role`
- `current_invite`
- `current_subject_credential`
- `current_session`

History queries should target the matching `versioned_*` view for the entity kind.

## Apply semantics for task 1

Task 1 keeps the existing apply barrier model:

1. insert new managed rows into typed tables with one `apply_id`
2. insert the corresponding committed `apply_commit` row
3. expose current state only through rows joined to committed applies

Managed rows always carry `apply_id`. Runtime-auth rows never do; they carry `change_id` and join through `auth_runtime_commit` instead.
