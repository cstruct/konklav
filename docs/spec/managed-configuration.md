# Managed Configuration

This file defines declarative management for slow-moving control-plane state such as bootstrap tenants, managed role templates, tenant-local roles, action catalogs, and related platform resources.

## Scope

r[config.managed.control-plane-only]
The platform MUST support declarative management for slow-moving control-plane resources such as bootstrap tenant configuration, tenant hierarchy metadata, action catalogs, managed role templates, tenant-local roles, and selected platform integrations.

r[config.managed.exclude-runtime-state]
Declarative management MUST NOT be the primary control surface for highly dynamic runtime state such as sessions, issued tokens, compiled grants, or just-in-time identity events.

## Reconciliation model

r[config.managed.three-way-diff]
Managed resources MUST support server-side three-way reconciliation using desired state, observed live state, and persisted prior applied state or equivalent field-ownership metadata.

r[config.managed.server-authoritative-validation]
Operator tooling MAY perform local parsing and static validation, but the Conclave control plane MUST re-validate desired managed state against live system context before plan or apply.

r[config.managed.plan-before-apply]
The platform MUST support a server-evaluated plan phase that reports the concrete resource mutations implied by a declarative change before apply.

r[config.managed.validate-operation]
The Conclave control plane MUST expose a non-mutating validation operation for managed configuration bundles.

r[config.managed.import-existing]
The platform MUST support importing existing live resources into declarative management without requiring destructive recreation.

r[config.managed.drift-detection]
The platform MUST detect drift between declarative intent and live managed state.

r[config.managed.ownership]
Managed resources MUST persist ownership or manager metadata so Conclave can distinguish declaratively managed fields from manually managed fields.

r[config.managed.versioned-history]
Persisted managed control-plane state MUST preserve introspectible temporal history using validity windows rather than destructive in-place replacement.

## Apply semantics

r[config.managed.apply-operation]
The Conclave control plane MUST expose an authenticated apply operation that reconciles a managed configuration bundle against live control-plane state.

r[config.managed.bundle-interface]
The managed configuration interface MUST use a single canonical root schema for tenant and authorization desired state so operator tooling can assemble one bundle before validation, plan, and apply.

r[config.managed.fragment-assembly]
The managed configuration interface MUST support assembling one managed bundle from multiple Styx documents using deterministic merge semantics over the canonical root schema so operators can organize desired state across files.

r[config.managed.bootstrap-seed]
The server MUST be able to seed an empty control-plane store from managed configuration during startup so the initial operator and subject story can be exercised without a separate apply step.

r[config.managed.bundle-transaction]
Applying a declarative configuration bundle MUST be atomic at least at the bundle or tenant scope selected for the operation.

r[config.managed.idempotent-apply]
Reapplying an unchanged declarative configuration MUST be idempotent.

r[config.managed.partial-failure]
If a declarative apply fails, the platform MUST surface which managed resources changed, which were rolled back, and which require operator intervention.

## Authorization and template interaction

r[config.managed.authz-template-resources]
Managed role templates, tenant-local roles, template lineage settings, and action-catalog entries MUST be representable as declarative managed resources.

r[config.managed.authz-intent-not-revisions]
Desired managed authorization configuration MUST express intended policy state without requiring operators to author system revision numbers for action catalogs, templates, or roles.

r[config.managed.authz-system-revisions]
Applying managed authorization configuration MUST mint or update immutable system-managed revisions for catalog, template, and role state whenever the effective authored state changes.

r[config.managed.authz-selector-overrides]
If managed authorization configuration supports derived templates or template-backed roles, override behavior MUST be deterministic and based on stable policy selector semantics.

r[config.managed.exclude-conclave-capabilities]
Tenant-managed authorization configuration MUST NOT be the control surface for Conclave built-in control-plane capabilities.

r[config.managed.authz-recompile-before-issuance]
When declarative changes affect action catalogs, managed role templates, tenant-local roles, or template lineage, the platform MUST complete the required recompilation of derived templates and compiled grants before issuing new tokens from the affected state.

r[config.managed.authz-revision-bump]
Declarative changes that alter compiled authorization outcomes MUST advance the relevant authorization revision used for token staleness checks.
