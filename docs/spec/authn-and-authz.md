# Authentication And Authorization

This file captures the requirements around login, SSO, IAM, delegated tenant assumption, control-plane authorization, and decentralized authorization.

## Authentication and sessions

r[authn.session.tenant-awareness]
Authentication sessions MUST remain tenant-aware so the same person can interact with multiple tenants without ambiguous security context.

r[sso.browser.single-login]
Browser-based SSO MUST allow a user to establish one authenticated session that can be reused across compatible applications within the same trust boundary.

r[authn.step-up.context]
The authentication model MUST support step-up requirements driven by application context, tenant policy, or risk signals.

r[authn.session.explicit-assumption]
Authenticated subjects MUST operate in one target tenant context at a time and switch into a different tenant context only through an explicit assumption flow.

r[authn.assumption.conclave-action]
Assumption into a child tenant MUST require an explicit Conclave-managed assumption grant rather than tenant-authored policy actions or implicit inheritance of the child tenant's roles.

r[authn.assumption.time-bounded]
Assumed tenant sessions MUST be time-bounded and auditable.

r[authn.assumption.target-context]
Once assumption succeeds, authorization for the assumed session MUST be evaluated in the target tenant context while preserving the originating actor chain for audit and policy inspection.

r[authn.bootstrap.root-operator]
The platform MUST support an initial bootstrap operator credential for authenticating the first root operator to the Conclave control plane.

r[authn.local-credential.login]
The platform MUST support a local subject login flow that redeems a linked credential into a tenant-aware session and token without requiring browser SSO for the initial operator and subject story.

r[authn.session.persisted-history]
Tenant-aware sessions MUST be persisted with introspectible temporal history so login and tenant context activity remain auditable across server restarts.

## IAM and authorization

r[authz.role.tenant-scoped]
Roles MUST be assignable within tenant scope so the same subject can hold different privileges in different tenants.

r[authz.permission.composable-model]
The IAM model MUST support permissions that can be composed into roles and policy decisions without hard-coding application-specific privilege names into the core platform.

r[authz.action.catalog.versioned]
The platform MUST assign a stable system-managed revision to the action catalog so compiled entitlements and tokens can be interpreted against a stable symbol set without requiring operators to hand-author catalog revision numbers in desired configuration.

r[authz.action.namespace.reserved]
Authorization actions MUST use colon-delimited hierarchical names with reserved top-level namespaces including `tenant`, `sys`, and `conclave`.

r[authz.action.namespace.tenant-owned]
Tenant-controlled actions MUST use the `tenant:` namespace, and operator-level relying-system integrations MAY use the `sys:` namespace where Conclave allows it.

r[authz.action.namespace.conclave-internal]
The reserved `conclave:` namespace MUST be system-defined for Conclave control-plane capabilities and MUST NOT be authored through tenant-managed authorization configuration.

r[authz.action.wildcard.trailing]
Wildcard action selectors MUST expand only across complete trailing action segments against the action catalog, such as `tenant:user:*`.

r[authz.policy.structured]
Policies MUST be structured as an action selector, an effect, and optional scope selectors and typed conditions.

r[authz.policy.effect.model]
Policy effects MUST support at least `allow` and `deny`.

r[authz.scope.hierarchy.within-tenant]
Authorization scopes MUST support hierarchical resources within a tenant, such as organization, clinic, project, or equivalent tenant-local resource kinds.

r[authz.role.definition.reusable]
Roles MUST be reusable definitions that remain separate from the subject assignments that activate them.

r[authz.role.assignable.local]
Assignable roles MUST be tenant-local definitions that are activated only within the tenant where they are defined.

r[authz.role.runtime.tenant-local]
Runtime role assignments, compiled grants, and issued entitlements MUST be resolved from tenant-local role state in the target tenant.

r[authz.role.template.managed]
The platform MUST support managed role templates as non-assignable export surfaces with explicit lineage across the tenant hierarchy.

r[authz.role.template.versioned]
Managed role templates MUST receive system-managed immutable revisions when applied so descendant tenants can detect upstream changes deterministically without hand-managed version fields in desired configuration.

r[authz.role.template.non-assignable]
Managed role templates MUST NOT be assigned directly to subjects.

r[authz.role.template.publish-descendants]
Role templates MUST be derivable by descendant tenants by definition rather than requiring a per-template publication toggle in desired configuration.

r[authz.role.template.derive-local]
When a tenant-local role is created from local template state, the materialized role definition MUST be resolved before assignment and token compilation.

r[authz.role.template.overlay]
Derived templates and template-backed roles MUST express overrides through their own policy blocks using deterministic selector-matching semantics rather than separate add and remove patch lists.

r[authz.role.template.sync-modes]
Derived templates MUST support at least tracking and pinned upstream sync modes.

r[authz.role.template.recompute-lineage]
When an upstream template revision changes, descendants configured to track upstream MUST incorporate that change through template-lineage recomputation before newly compiled grants or tokens are issued.

r[authz.role.template.descendant-publish]
A descendant tenant's derived template MUST be eligible to act as an upstream source for its own descendants.

r[authz.role.template.managed-config-reconcile]
Declarative management of template lineage or override state MUST reconcile through the same lineage recomputation rules used for direct template updates.

r[authz.role.inheritance.dag]
Roles MAY inherit from parent roles through an acyclic graph.

r[authz.role.inheritance.priority]
Role inheritance edges MUST contribute deterministic authored order to compiled authorization precedence.

r[authz.role.inheritance.tenant-boundary]
Role inheritance MUST NOT cross tenant boundaries.

r[authz.assignment.multiple]
Subjects MUST be able to hold multiple role assignments within the same tenant.

r[authz.assignment.priority]
Role assignments MUST contribute deterministic authored order to compiled authorization precedence.

r[authz.decision.precedence]
The authorization engine MUST resolve overlapping matching policies deterministically using scope specificity, effective compiled order, and effect.

r[authz.decision.deny-equal-precedence]
When matching policies have equal scope specificity and equal effective compiled order, `deny` MUST override `allow`.

r[authz.compile.effective-grants]
The platform MUST precompute effective grants from assignments, role inheritance, wildcard expansion, and conflict rules so request-time evaluation avoids recursive role expansion.

r[authz.query.no-recursive-expansion]
Request-time authorization checks against compiled entitlements MUST avoid recursive traversal of role inheritance graphs.

r[authz.condition.typed-predicates]
Attribute-based conditions MUST use a constrained typed predicate model rather than arbitrary executable policy code.

r[authz.condition.portable-facts]
The authorization model MUST distinguish between token-portable facts that can be evaluated offline and non-portable facts that require local resource or request context.

r[authz.explainability.decision-trace]
The platform MUST be able to explain an authorization decision in terms of compiled grants and the source policy state that produced them.

r[authz.token.self-contained-claims]
Issued tokens MUST be able to carry enough authorization context for downstream services to make common allow or deny decisions without a synchronous callback to the control plane.

r[authz.token.revocation-story]
The authorization model MUST define how token-carried claims are constrained by expiry, rotation, revocation, or versioning so decentralized decisions remain bounded in time.

r[authz.offline.relying-system-library]
Relying systems MUST be able to validate Conclave-issued JWTs and evaluate token-carried authorization snapshots offline through a stable library boundary.

## Control-plane authorization

r[authz.control-plane.capability.built-in]
Operations against the Conclave control plane MUST be authorized through system-defined built-in capabilities that are separate from tenant-authored action catalogs.

r[authz.control-plane.capability.assumption-separate]
Delegated tenant assumption MUST be modeled as a first-class Conclave-managed grant surface separate from tenant-local role policies and token-carried tenant authorization snapshots.
