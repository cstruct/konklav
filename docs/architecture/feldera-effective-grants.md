# Feldera Effective Grants

This note defines the current Task 4 direction for moving compiled authorization state toward Feldera-backed projections and `effective_grants`.

## Current direction

The current implementation keeps managed authorization state in typed temporal source tables and expands authorization semantics in Rust before the final Feldera-backed `effective_grants` view exists.

The important Task 4 semantic decisions are:

- role assignments are ordered rather than numerically prioritized
- role inheritance edges are ordered rather than numerically prioritized
- later authored entries have higher precedence
- `deny` overrides `allow` only when scope specificity and effective compiled order are otherwise equal
- pinned template sources may author `pin "latest"` as shorthand, but plan and apply normalize that shorthand into a concrete upstream template revision

## Ordered precedence model

Compiled authorization precedence is determined in this order:

1. scope specificity
2. effective compiled order
3. effect, where `deny` overrides `allow` on an exact tie

`effective compiled order` is produced from authored order:

- inherited roles are flattened in the order they are listed on the descendant role
- a role's local template, if present, is applied after inherited roles
- a role's local policies are applied after inherited roles and template-derived policies
- membership role assignments and delegated target-role assignments are applied in authored order

This means later role assignments act as stronger overrides, which matches the intended future relying-system UX of `add first`, `add before`, `add after`, and `add last`.

## Pinned template normalization

Pinned template sources are declarative, but the persisted managed state must store a concrete pinned upstream revision.

The current normalization rule is:

- `mode "tracking"` stores no `pin`
- `mode "pinned", pin "latest"` resolves to the upstream template revision visible during plan or apply
- `mode "pinned", pin "<revision>"` is accepted only when the current compile-time snapshot can resolve that concrete upstream revision

After normalization:

- the persisted template source stores the concrete pinned revision string
- compiled template metadata records `source_revision`
- later upstream changes do not affect the descendant until the operator asks to move the pin again

This gives the control plane stable persisted semantics for pinned descendants while preserving operator-facing shorthand in authored config.

## Current implementation boundary

Task 4 currently spans three layers:

- typed source persistence for templates and roles now preserves ordered inheritance and normalized pinned-source metadata
- Rust compilation still produces memberships and delegated-grant source rows for the authz pipeline
- the dedicated Feldera authz pipeline now derives template lineage, final role policies, `effective_grants`, and `effective_grant_actions` from typed source tables and runtime token issuance or validation reads that derived surface when it is available

The important shift in the current slice is that `effective_grants` is no longer published as a precomputed row with serialized bitsets. Instead, the authz pipeline now persists:

- `compiled_authz_metadata`
- `action_catalog`
- `template_policy_overrides`
- `resolved_template_metadata`
- `template_lineage`
- `role_inheritance_edges`
- `role_policy_overrides`
- `effective_grant_identity`
- `effective_grant_role_assignment`

Feldera materialized views then derive:

- `compiled_template_policies`
- `compiled_role_policies`
- `compiled_role_action_effects`
- `effective_grants`
- `effective_grant_action_candidates`
- `effective_grant_action_max_order`
- `effective_grant_action_precedence`
- `effective_grant_actions`

At read time, the server reconstructs the runtime `CompiledEffectiveGrant` shape from the derived Feldera rows. This moves selector expansion, template-lineage expansion, grant derivation, and assignment-order precedence into Feldera even though final role policy compilation still begins in Rust.

## Runtime read boundary

When Feldera is enabled:

- startup and managed apply refresh the dedicated authz pipeline from the current managed snapshot
- direct token issuance reads one `effective_grants` identity row and the corresponding `effective_grant_actions` rows for the subject and target tenant
- delegated assumption token issuance reads one `effective_grants` identity row and the corresponding `effective_grant_actions` rows for the subject, source tenant, and target tenant
- token validation and relying-surface revision or catalog reads use `compiled_authz_metadata` and `action_catalog`

If the authz pipeline has not been populated yet, Feldera-backed compiled-authz reads now fail closed instead of silently rebuilding a Rust snapshot.

## Open questions

- Should managed plan and apply responses eventually return a structured normalized managed bundle or patch, instead of surfacing normalization only through persisted state and change summaries?
- Should the final `effective_grants` surface live entirely in the main control-plane pipeline, or should a dedicated authorization compilation pipeline remain part of the design?
- How much of selector expansion and precedence explanation should be queryable directly from Feldera views versus reconstructed in bounded server-side explanation helpers?
- When the authz pipeline refresh path is reliable enough, should the snapshot fallback be removed entirely so Feldera becomes the only compiled-grant read surface in Feldera mode?
