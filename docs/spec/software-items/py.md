# Python Relying Binding Software Item

Stable implementation contracts owned by `konklav-py`, the Python binding of
the relying core, published as `konklav-relying` and imported as
`konklav_relying`.

## Route policies

A route policy (see the nomenclature) states an operation's requirements
with scope ids left unresolved, so a relying system can declare one per
route or router and resolve it per request.

r[item.py.policy.framework-free]
The route-policy layer (`Policy`, `StepUp`, `Decision`, `AccessToken` and
their parts) MUST be built from frozen dataclasses and the standard library
alone. It MUST NOT import a web framework or a validation library, so that
framework integrations such as a FastAPI package can build on it.

r[item.py.policy.fields]
`Policy` MUST be able to state everything a decide request expresses
(`relying.decision.requirements`): global and tenant actions, actions per
scope kind with the scope ids left unresolved, token kinds, admitted
restrictive flags, required assertive flags, step-up and tenant facts. A
field that is `None` MUST leave its part of the requirements unconstrained,
so that the requirements it resolves to leave that member out and Konklav's
default applies (only `tenant` tokens, no admitted flag).

r[item.py.policy.validation]
`Policy` MUST refuse, when it is constructed, tenant fact predicates that
Konklav refuses (`authz.decision.tenant-facts.shape`): a predicate with no
values, or a value that isn't a string, an integer or a boolean.

r[item.py.policy.merge]
`Policy.merge` MUST combine the policies declared on nested layers, outermost
first, into one policy:

- actions accumulate: global and tenant actions, and per scope kind the
  scope actions, are unions;
- allowed sets intersect: token kinds, admitted flags, step-up's allowed
  methods, and per fact the allowed values of tenant facts;
- required sets accumulate: required flags, and the facts tenant facts
  constrain;
- the strictest step-up wins: the highest minimum number of methods and the
  smallest maximum age;
- a field that is `None` in one policy takes the other's value.

r[item.py.policy.merge-contradiction]
A merge whose tenant fact values for a fact intersect to nothing MUST raise
`PolicyError` instead of producing requirements Konklav would refuse, so a
relying system finds the contradiction where it declares its policies.

r[item.py.policy.override]
`Policy.override` MUST make a policy that, merged after others, replaces
only the fields it sets, and leaves the merged values of the others.

r[item.py.policy.public]
`Policy.public()` MUST make a policy that admits anyone without a token. A
merge MUST raise `PolicyError` when a public policy meets a policy that
constrains anything, unless the constraining one is an override, which then
replaces the public policy's fields and makes the result non-public.
`Policy.override(public=True)` makes the merged policy public again,
whatever came before. A public policy MUST NOT resolve to requirements.

r[item.py.policy.requirements]
`Policy.requirements(scope_ids)` MUST build the requirements JSON that
`decide` and `decide_request` take, with each scope kind's id taken from
`scope_ids`, and MUST raise `MissingScopeId` naming the kind when a scope
kind the policy requires has no id. It MAY take the owner tenant per scope
kind (`authz.share.requirements`). Ids of kinds the policy doesn't require
are ignored.

r[item.py.policy.token-tenant]
A policy's tenant actions, tenant facts, and scope requirements without an
owner tenant MUST mean the token's tenant, as they do for Konklav
(`relying.decision.requirements`): a policy never names a tenant. A host
that addresses a tenant on its own, such as from a route's path, MUST deny
before deciding when that tenant isn't the token's `tid`
(`AccessToken.tid`).

## Typed results

r[item.py.typed.decision]
`Decision.from_json` MUST read every decision the relying core and the check
API return: `allow` with its obligations, `deny` with a `DenyReason` that
carries the reason's code and its fields, and `step_up` with its
requirement as a `StepUp`. A deny reason with a code it doesn't know MUST
still be read, with the code kept, so a deny is never mistaken for an
allow.

r[item.py.typed.access-token]
`AccessToken.from_claims` MUST read the claims `verify` and
`verify_request` return into typed fields: `iss`, `aud`, `sub`, `knd`,
`tid`, `mid`, `sid`, `sv`, `jti`, `iat`, `exp`, `auth_time`, `amr`, `sfl`,
`fct`, `act`, `cid` and `cnf`, keeping ids as strings and times as Unix
seconds.

r[item.py.typed.compatible]
`RelyingClient`'s `decide`, `decide_request`, `verify` and `verify_request`
MUST keep returning the decoded JSON. Typed results MUST come from separate
methods, `decide_typed`, `decide_request_typed`, `verify_typed` and
`verify_request_typed`, which take the same arguments, also accept a
`Requirements` mapping built by `Policy.requirements`, and raise the same
errors.
