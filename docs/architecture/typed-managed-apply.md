# Typed Managed Apply

This note defines task 2 of the control-plane implementation plan: moving managed reconciliation onto typed managed-entity rows with durable apply and ownership metadata.

## Durable state

Task 2 adds two durable control records:

- `managed_apply`
  - one row per evaluated apply attempt
  - records `apply_id`, apply time, bundle fingerprint, mutation summary, and whether the apply was a noop
  - stores the desired managed bundle JSON so the last applied declarative state remains introspectible
- `managed_ownership`
  - one current row per currently managed logical entity
  - records the entity kind, stable entity key, latest owning `apply_id`, and a stable desired-state fingerprint
  - uses the same append-only validity-window pattern as the typed entity tables

## Reconciliation inputs

Each managed apply evaluates three inputs:

1. desired managed bundle
2. observed live typed current-state rows
3. persisted current `managed_ownership` rows

The ownership rows are the persisted “prior applied state or equivalent ownership metadata” input for task 2.

## Entity-level ownership semantics

Task 2 tracks ownership at the logical entity level rather than at individual field paths.

For each managed entity key:

- if the entity is present in desired state, apply writes the desired typed row when the live row differs and ensures the entity has a current ownership row
- if the entity is absent from desired state and currently has a current ownership row, apply writes a typed deletion row and retires the ownership row
- if the entity is absent from desired state and has no current ownership row, apply leaves the live row untouched

This keeps the implementation aligned with typed entity tables while leaving room for later field-level ownership expansion.

## Apply ordering and visibility

The typed managed apply order is:

1. compute the ownership-aware plan from desired state, current typed rows, and current ownership rows
2. write typed entity mutations and ownership rows using one `apply_id`
3. write the `managed_apply` row for that same `apply_id`
4. write the committed `apply_commit` row

Current-state views only expose rows that belong to committed applies, so readers never observe a partially published apply.

## Noop apply behavior

If the ownership-aware plan has no entity mutations and no ownership mutations, the store still writes a `managed_apply` row marked `noop = TRUE` and publishes the `apply_id`.

That keeps the “state of last apply” introspectible while preserving idempotent live state.
