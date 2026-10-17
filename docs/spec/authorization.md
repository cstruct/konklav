# Authorization

Catalog, roles, templates, policies, assignments, entitlements and the check
API.

## Action catalog

r[authz.catalog.data]
Actions, action groups, scope kinds, fact keys and session flags MUST be
declared as catalog data supplied through the control plane. Conclave MUST
NOT hard-code any of them except the `conclave:` control-plane capabilities.

r[authz.catalog.names]
Action names MUST be colon-delimited. The `conclave:` namespace MUST be
reserved for control-plane capabilities and MUST NOT be authored.

r[authz.catalog.groups]
An action group MUST expand to a fixed set of catalog actions, defined
either by listing them or by a namespace selector (for example "every action
not in `sys:`"). Expansion MUST happen during compilation.

r[authz.catalog.revision]
Every catalog change MUST produce a new revision and an
`entitlements.changed` event for all subjects.

r[authz.catalog.removal]
An action MUST NOT be removed from the catalog while any policy references
it.

## Roles, templates and policies

r[authz.template.blueprint]
Templates MUST be reusable role blueprints that cannot be assigned directly.

r[authz.role.tenant-local]
Roles MUST belong to exactly one tenant and MUST be assignable only within
that tenant, except global roles, which belong to the root tenant.

r[authz.role.from-template]
A role MAY be derived from a template. Its effective policies are then the
template's policies, overridden per action by the role's own policies.

r[authz.role.priority]
Every role MUST have an integer priority used to resolve conflicts between
roles.

r[authz.role.instantiate]
Creating a tenant MUST be able to instantiate roles from a list of templates
atomically with the tenant itself.

r[authz.policy.shape]
A policy MUST consist of an action or action group, an effect (`allow` or
`deny`) and a scope-bound flag.

r[authz.policy.scope-bound]
A scope-bound policy MUST apply only at the scope of the assignment that
activates it. A policy that is not scope-bound MUST apply tenant-wide even
when its assignment is scoped.

## Assignments

r[authz.assignment.membership]
Tenant roles MUST be assigned to memberships, either tenant-wide or at one
scope.

r[authz.assignment.global]
Global roles MUST be assigned to subjects directly. Their grants MUST apply
regardless of the target tenant.

r[authz.assignment.capabilities]
Control-plane capabilities MUST only be grantable through global
assignments.

r[authz.assignment.multiple]
A membership MUST be able to hold several assignments, including several at
the same scope.

r[authz.assignment.scope-kind]
A scoped assignment MUST use a scope kind declared in the catalog.

## Compilation

r[authz.compile.entitlements]
Conclave MUST compile assignments, roles, templates, policies and action
groups into an entitlement set per (subject, tenant), containing global
actions, tenant-wide actions, and actions per scope.

r[authz.compile.precedence]
When several policies match the same action at the same level, the one from
the highest-priority role MUST win, and at equal priority `deny` MUST win
over `allow`.

r[authz.compile.allows-only]
Entitlement sets MUST contain only effective allows. Denies MUST be fully
resolved during compilation.

r[authz.compile.subsumption]
An action granted at a higher level (global, then tenant-wide) MUST NOT be
repeated at lower levels of the same entitlement set.

r[authz.compile.reference-semantics]
Compilation semantics MUST be pinned by golden tests. Any change to them
MUST be an explicit, versioned catalog option, never a silent change.

r[authz.compile.inactive]
Ended memberships, disabled subjects and non-active tenants MUST contribute
no entitlements.

r[authz.compile.revision]
Every entitlement set MUST carry the revision it was compiled at.

## Invalidation

r[authz.invalidate.subject]
A change to a subject's memberships, assignments or global assignments MUST
emit an `entitlements.changed` event naming that subject.

r[authz.invalidate.definition]
A change to a role, template, policy or the catalog MUST emit an
`entitlements.changed` event naming either the affected subjects or all
subjects.

## Relying surface

r[authz.api.entitlements]
The relying surface MUST serve the entitlement set for a (subject, tenant)
pair to authorized relying systems.

r[authz.api.check]
The relying surface MUST offer a check API. Given an access token and an
operation's requirements (actions per level and scope, admitted and required
session flags, step-up requirements), it returns a decision computed from
current state, including session validity.

r[authz.api.check-equivalence]
For the same state, the check API and local evaluation by the relying core
MUST reach the same decision.

r[authz.resource-context.external]
Decisions that depend on relying-system resources (for example, which
scopes a resource belongs to) MUST be resolved by the relying system into
scopes before asking Conclave or the relying core.

r[authz.explain]
The control plane MUST be able to explain an entitlement in terms of the
assignments, roles, templates and policies that produced it.
