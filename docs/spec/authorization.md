# Authorization

Catalog, roles, templates, policies, assignments, entitlements and the check
API.

## Action catalog

r[authz.catalog.data]
Actions, action groups, scope kinds, fact keys and session flags MUST be
declared as catalog data supplied through the control plane. Konklav MUST
NOT hard-code any of them except the `konklav:` control-plane capabilities.

r[authz.catalog.names]
Action names MUST be colon-delimited. The `konklav:` namespace MUST be
reserved for control-plane capabilities and MUST NOT be authored.

r[authz.catalog.groups]
An action group MUST expand to a fixed set of catalog names, defined either
by listing actions or by a prefix selector (for example "every name not in
`sys:`"). Granting a group MUST also grant the group's own name, so that
operations can require the group itself. Expansion MUST happen during
compilation.

r[authz.catalog.revision]
Every catalog change MUST produce a new revision and an
`entitlements.changed` event for all subjects.

r[authz.catalog.removal]
An action MUST NOT be removed from the catalog while any policy references
it.

r[authz.catalog.flag-confinement]
A session flag entry MAY carry a confinement as `confine`, an object whose
`tenant` member maps tenant fact keys to lists of allowed values, such as
`{"tenant": {"tenant_type": ["personal"]}}` (see `session.flags.confine`).
A catalog document is validated as a whole, so a change that stops
declaring a fact a confinement names, or makes it non-portable or changes
its type, MUST be rejected unless the same document changes the
confinement too.

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

r[authz.role.builtin]
Konklav MUST ship built-in global roles whose policies only it defines.
They MUST be assignable like any other global role, and the control plane
MUST NOT create, change or delete them.

r[authz.role.reserved-key]
Role keys starting with `konklav.` MUST be reserved for built-in roles in
every tenant. Writing a role with a reserved key MUST fail as an invalid
request.

r[authz.role.builtin.set]
The built-in roles MUST be exactly these:

- `konklav.admin`, which allows `konklav:control:all`. It MUST NOT grant
  impersonation or reading delivery requests.
- `konklav.delivery`, which allows `konklav:delivery:read`.

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

r[authz.control-plane.capability]
Built-in capabilities MUST be catalog actions in the `konklav:` namespace
that only Konklav defines. Catalog documents MUST NOT declare or remove
them, and action groups MUST NOT expand to them, so they are only ever
granted by name. Every control-plane operation, impersonation and reading
delivery requests MUST each require a capability.

r[authz.assignment.capabilities]
Control-plane capabilities MUST only be grantable through global
assignments.

r[authz.control-plane.escalation]
Granting or withdrawing control-plane capabilities (writing or deleting a
role or template whose policies allow one, or assigning or unassigning such
a role) MUST require `konklav:control:all`. So MUST changing the state or
credentials of a subject that holds any capability. No narrower capability
may lead to more capabilities.

r[authz.control-plane.own-capabilities]
The subject-facing surface MUST let a subject with a full (non-partial)
session list the control-plane capabilities it holds, so operator tools can
show what an operator may do before trying it. It MUST NOT reveal another
subject's capabilities, or actions outside the `konklav:` namespace.

r[authz.assignment.multiple]
A membership MUST be able to hold several assignments, including several at
the same scope.

r[authz.assignment.scope-kind]
A scoped assignment MUST use a scope kind declared in the catalog.

r[authz.assignment.not-registered]
A scoped assignment MUST NOT use a registered scope kind (see Registered
scopes).

## Compilation

r[authz.compile.entitlements]
Konklav MUST compile assignments, roles, templates, policies and action
groups into an entitlement set per (subject, tenant), containing global
actions, tenant-wide actions, actions per scope, and the actions shared
with the tenant (see Sharing).

r[authz.compile.precedence]
When several policies match the same action at the same level, the one from
the highest-priority role MUST win, and at equal priority `deny` MUST win
over `allow`.

r[authz.compile.allows-only]
Entitlement sets MUST contain only effective allows. Denies MUST be fully
resolved during compilation.

r[authz.compile.deny-level]
A deny MUST cancel allows only at its own level: global, tenant-wide, or the
same scope. A tenant-wide deny does not remove an allow granted at a scope,
and a global deny does not remove a tenant-wide allow.

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

r[authz.compile.registered-kinds]
Every entitlement set MUST name the catalog's registered scope kinds, so a
relying core knows which requirements need a registered scope's record.

r[authz.compile.confinements]
Every entitlement set MUST carry the catalog's confinements, so a relying
core can decide them without another lookup, from the tenant facts the set
carries (`authz.compile.tenant-facts`).

r[authz.compile.tenant-facts]
Every entitlement set MUST carry the current values of all of its tenant's
portable facts (none for a set without a tenant), so a relying core can
decide confinements and tenant fact requirements without another lookup.
The portable facts are bounded (`fact.bounded`), so carrying all of them
keeps the set small, and the set doesn't depend on which requirements it
will be used for.

## Sharing

r[authz.share.shape]
A share MUST name its owner tenant, one of the owner's scopes, a recipient
tenant other than the owner, optionally a scope of the recipient tenant,
the actions or action groups it allows, its attributes, and an optional
validity period. The shared scope's id MUST be opaque to Konklav, like any
scope id. Control-plane capabilities MUST NOT be shared.

r[authz.share.acceptance]
A share MUST be offered first and take effect only once it has been
accepted for the recipient tenant. Changing the terms of a share MUST offer
it again. Either side MUST be able to revoke a share, and a revoked share
MUST NOT be accepted or changed again.

r[authz.share.unique]
At most one offered or accepted share MUST exist per owner scope and
recipient (tenant and recipient scope).

r[authz.share.ceiling]
A member of the recipient tenant MUST receive, at the shared scope, only the
actions the share allows that the member holds at the recipient: tenant-wide
when the share names no recipient scope, or at the recipient scope. Shares
MUST NOT chain into further shares, and an inactive owner tenant's shares
MUST grant nothing.

r[authz.share.validity]
A share MUST grant nothing before its `valid_from` or after its
`valid_until`, decided against the time of each decision.

r[authz.share.attributes]
Share attributes MUST be declared in the catalog as facts with target
`share` and validated when a share is written. Konklav MUST NOT interpret
them: an allow decision that relied on a share MUST return the share's
attributes as an obligation.

r[authz.share.requirements]
A scope requirement MUST be able to name the scope's owner tenant. When that
is another tenant than the token's, only accepted shares of that scope MUST
satisfy it.

r[authz.share.events]
Offering, accepting, changing or revoking a share MUST emit a
`share.changed` event naming the share, both tenants and its state, and an
`entitlements.changed` event for the recipient tenant.

## Registered scopes

r[authz.registered.catalog]
A scope kind MAY be declared in the catalog as registered. A catalog change
that stops declaring a kind as registered, or removes it, MUST be rejected
while any registered scope of that kind is recorded, active or removed.

r[authz.registered.shape]
A registered scope MUST record its kind, its opaque id, its owner tenant and
a possibly empty set of containing scopes. Each containing scope MUST be of
a declared scope kind that is not registered. Its id stays opaque to
Konklav, and Konklav MUST NOT require it to be recorded anywhere.

r[authz.registered.tenant-fixed]
A registered scope's tenant MUST NOT change once recorded. Recording it
again in another tenant MUST fail as a conflict, including after the scope
has been removed.

r[authz.registered.containers]
Recording a registered scope again in its own tenant MUST replace its
containing scopes, so a relying system can move it between them.

r[authz.registered.unknown-denies]
A scope requirement at a registered scope kind MUST NOT be satisfied by any
grant when the scope was never recorded or has been removed.

r[authz.registered.evaluation]
A scope requirement at an active registered scope MUST be decided against
the scope's recorded tenant, whatever tenant the requirement names. When
the requirement names a tenant other than the recorded one, it MUST NOT be
satisfied. When the recorded tenant is the token's, each required action
MUST be satisfied by the global or tenant-wide actions, or the actions at
the scope itself or at any one of its containing scopes.

r[authz.registered.shares]
When a registered scope's tenant is not the token's, its required actions
MUST be satisfied only by accepted shares owned by that tenant, valid at
the time of the decision, of the scope itself or of one of its containing
scopes, and the allow MUST carry their obligations.

r[authz.registered.no-tenant]
A token that targets no tenant MUST satisfy a requirement at a registered
scope only through global actions.

r[authz.registered.batch]
The control plane MUST be able to record and remove up to 1000 registered
scopes in one all-or-nothing request. A failure MUST name every entry that
caused it.

r[authz.registered.events]
Recording, changing or removing registered scopes MUST emit one
`scope.changed` event per transaction, naming each changed scope with its
kind, id, tenant and state. It MUST NOT emit `entitlements.changed`.

r[authz.registered.api]
The relying surface MUST serve a registered scope's tenant, state and
containing scopes by kind and id, to authorized relying systems.

r[authz.registered.capability]
Recording and removing registered scopes MUST require the
`konklav:scopes:register` capability or `konklav:control:all`.

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
session flags, step-up requirements, required tenant facts), it returns a
decision computed from current state, including session validity.

r[authz.api.check-equivalence]
For the same state, the check API and local evaluation by the relying core
MUST reach the same decision.

r[authz.decision.tenant-facts]
An operation MAY require tenant facts as `tenant_facts`, an object mapping
tenant fact keys to the values each fact may have, such as
`{"tenant_facts": {"tenant_type": ["client"]}}`. Like a confinement
(`session.flags.confine`), it is a conjunction of fact predicates: the
tenant matches when, for every predicate, it has the fact and its value
equals one of the listed values. A decision MUST deny unless the token
targets a tenant whose current facts match every predicate, whatever
actions the token holds, global ones included. An empty object requires
nothing.

r[authz.decision.tenant-facts.reason]
A decision denied for tenant facts MUST name the first predicate, by fact
key, that the tenant fails, as `{"tenant_facts": {"fact": "<key>"}}`. When
the token targets no tenant, every predicate fails, so the first is named.

r[authz.decision.tenant-facts.shape]
Requirements MUST be refused as invalid when a tenant fact predicate lists
no values, or lists a value that isn't a string, an integer or a boolean,
the types a confinement can match (`session.flags.confine.facts`). Reading
requirements MUST NOT depend on the catalog, so that the check API and the
relying core refuse the same requirements: a predicate on a fact that isn't
a declared, portable tenant fact, or with values of another type than the
fact's, is not refused, and denies, since no tenant's carried facts can
match it.

r[authz.resource-context.external]
Decisions that depend on relying-system resources (for example, which
scopes a resource belongs to) MUST be resolved by the relying system into
scopes before asking Konklav or the relying core, except for registered
scopes, which Konklav and the relying core resolve from Konklav's record.

r[authz.explain]
The control plane MUST be able to explain an entitlement in terms of the
assignments, roles, templates and policies that produced it.

r[authz.explain.decision]
The control plane MUST be able to explain a decision for a subject, a tenant
and requirements, optionally in the context of one of the subject's
sessions. For each required action at each level it MUST say whether the
action is granted and why, in words and as data: the policy that allows it
(with denies that don't cancel it), the deny that cancels it and the allows
that deny overrides, that it is granted only at other scopes, that no policy
grants it, or what about a share grants it or doesn't.

r[authz.explain.checks]
A decision explanation MUST also report each other check that decides the
outcome: whether the subject, its membership and the tenant are active, and
with a session, whether the session is current, and the token kind, session
flag and step-up checks.

r[authz.explain.confinement]
With a session that carries a confined flag, a decision explanation MUST
report a confinement check that names each such flag, its confinement and
the tenant's values of the facts it names, and says which predicate fails
when one does.

r[authz.explain.tenant-facts]
With tenant fact requirements, a decision explanation MUST report a
`tenant_facts` check that names each predicate and the tenant's values of
the facts they name, and says which predicate fails when one does, or that
the decision is for no tenant.

r[authz.explain.at]
With history enabled, the control plane MUST be able to explain a decision
for a subject, a tenant and requirements as of a past time, reading the
state current then and judging share validity at that time. It MUST refuse
a time outside the history horizon or in the future, and a session together
with a time, since history doesn't keep sessions.

r[authz.explain.agreement]
A decision explanation MUST agree with the decision the check API reaches
for the same state: it allows exactly when every check passes and every
required action is granted.
