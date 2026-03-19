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

## Transaction boundary

The target task-2 end state is a transactional managed apply path built on Feldera transactions:

1. start one Feldera transaction for the control-plane pipeline
2. write all managed source-table updates for the apply inside that transaction
3. allow Feldera to refresh all dependent current-state and compiled managed views within that same transaction
4. commit the transaction

Managed apply success is defined at transaction commit completion, not at “rows accepted for ingress.” Until commit completes, current-state and compiled-state readers must continue to observe the previously committed state.

The `effective_grants` view is explicitly in scope for this transaction boundary once task 4 lands. It must commit together with the managed source rows that feed it.

## Apply ordering and visibility

The typed managed apply order is:

1. compute the ownership-aware plan from desired state, current typed rows, and current ownership rows
2. start a Feldera transaction
3. write typed entity mutations and ownership rows using one `apply_id`
4. write the `managed_apply` row for that same `apply_id`
5. commit the Feldera transaction
6. publish the `apply_commit` row only as part of that same transaction, or derive committed visibility directly from the transaction boundary if the store model is updated to do so

Current-state views only expose rows that belong to committed applies, so readers never observe a partially published apply.

## Partial failure and recovery

The desired partial-failure contract is:

- if transaction commit succeeds, the apply succeeded and all managed source and compiled managed views become visible together
- if any step fails before transaction commit completes, the apply failed and the prior committed state remains authoritative
- the operator receives as much diagnostic context as the server can gather about the failing step, Feldera transaction state, and any recovery action taken

Feldera's current transaction documentation says transactions are experimental and cannot be aborted or rolled back directly. The recovery strategy for this design is therefore based on checkpoint-and-resume support:

- Conclave should only rely on this transactional apply mode when the Feldera pipeline is configured with checkpoint-and-resume support
- if transaction handling fails in a way that leaves the pipeline unusable, the recovery path is to stop the pipeline without clearing checkpointed state and then resume from the most recent pre-transaction durable point
- if checkpoint-and-resume is unavailable, this transactional apply mode is not considered safe to claim as the authoritative partial-failure solution

## Noop apply behavior

If the ownership-aware plan has no entity mutations and no ownership mutations, the store still writes a `managed_apply` row marked `noop = TRUE` and publishes the `apply_id`.

That keeps the “state of last apply” introspectible while preserving idempotent live state.

## Open Questions

- Should `managed_apply` record transaction identifiers and recovery-attempt metadata, or is failure context in server logs and API responses sufficient?
- Should `apply_commit` remain an explicit table once Feldera transaction commit becomes the authoritative visibility barrier, or should committed visibility derive from transaction semantics alone?
- How should Conclave detect and surface “commit still in progress” versus “commit failed and recovery required” in operator-facing APIs?
- `effective_grants` is in the transaction boundary by decision, but signing-key rotation and JWKS publication are still undecided and need a later architectural call.
- The exact Feldera runtime/storage configuration that Conclave should require for checkpoint-and-resume safety is still open; the current design assumes this becomes an explicit deployment prerequisite rather than an implicit best effort.
