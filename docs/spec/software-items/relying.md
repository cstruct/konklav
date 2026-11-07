# Relying Core Software Item

Stable implementation contracts owned by `konklav-relying`, the relying
core.

r[item.relying.sans-io]
`konklav-relying` MUST NOT perform network I/O, read clocks, spawn tasks or
sleep. The host binding supplies the current time, JWKS documents,
entitlement responses, feed events and check-API responses.

r[item.relying.scheduler]
`konklav-relying` MUST expose its pending work (fetches to perform and the
earliest time each is due) so that host bindings can run them and feed the
results back.

r[item.relying.portable]
`konklav-relying` MUST compile for native targets and for `wasm32`, with no
platform-specific dependencies in its default feature set.

r[item.relying.request-descriptor]
The verification API of `konklav-relying` MUST accept an optional request
descriptor (method and URL) so that sender-constrained tokens can be
verified later without breaking the API.

r[item.relying.raw-headers]
The verification API of `konklav-relying` MUST take the request's raw
`Authorization` and `DPoP` header values, so host bindings never parse
authorization schemes or proofs themselves.

r[item.relying.single-implementation]
Host bindings MUST NOT re-implement verification, evaluation or cache-state
logic. They only translate between the core and their language's runtime.

r[item.relying.rate-limit]
`konklav-relying` MUST own the rate-limit algorithm, the local state, the
backoff, and the store's script with the keys and arguments it is called
with, and MUST interpret the script's answer. Host bindings only send the
call, report its answer or failure, and supply the time.

## Route policies

A route policy (see the nomenclature) states an operation's requirements
with scope ids left unresolved. Native Rust hosts and framework
integrations, such as `konklav-axum`, build on `konklav_relying::policy`
rather than merging route policies themselves, so every Rust integration
combines them alike. It follows the same rules as the Python binding's
`konklav_relying.policy.Policy` (`item.py.policy.*`).

r[item.relying.policy.fields]
`Policy` MUST be able to state everything `Requirements` expresses
(`relying.decision.requirements`): global and tenant actions, actions per
scope kind with the scope ids left unresolved, token kinds, admitted
restrictive flags, required assertive flags, step-up and tenant facts. A
field left unset MUST leave its part of the requirements unconstrained, so
that Konklav's default applies (only `tenant` tokens, no admitted flag).
Tenant fact values MUST be typed as strings, integers or booleans, the
values Konklav can match (`authz.decision.tenant-facts.shape`).

r[item.relying.policy.merge]
`Policy::merge` MUST combine the route policies declared on nested layers,
outermost first, into one, as `item.py.policy.merge` does: actions
accumulate; token kinds, admitted flags, step-up's allowed methods and each
tenant fact's allowed values intersect; required flags and the facts
constrained accumulate; the highest minimum number of methods and the
smallest maximum age win; and an unset field takes the other's value.

r[item.relying.policy.merge-contradiction]
`Policy::merge` MUST refuse with `PolicyError` a merge whose allowed values
of a tenant fact intersect to nothing, and a tenant fact listed with no
values, instead of producing requirements Konklav would refuse.

r[item.relying.policy.override]
`Policy::overriding()` MUST make a route policy that, merged after others,
replaces only the fields it sets and leaves the merged values of the
others.

r[item.relying.policy.public]
`Policy::public()` MUST make a route policy that admits anyone without a
token. A merge MUST refuse with `PolicyError` a public policy that also
constrains, and a public policy meeting one that constrains, unless the
constraining one is an override, which then replaces the public policy's
fields and makes the result non-public. `Policy::override_public()` makes
the merged policy public again, whatever came before. A public policy MUST
NOT resolve to requirements.

r[item.relying.policy.check]
`Policy::check` MUST refuse a route policy whose merge leaves an allowed set
empty, token kinds or step-up's allowed methods, since every request would
be denied.

r[item.relying.policy.requirements]
`Policy::requirements` MUST build `Requirements` for one request, with each
required scope kind's id, and optionally the scope kind the decision uses
and the scope's owner tenant (`authz.share.requirements`), from the
request's resolved scopes. It MUST refuse with `PolicyError::MissingScopeId`,
naming the kind, a required scope kind without a resolved scope, and MUST
ignore resolved scopes of kinds the policy doesn't require. Tenant actions,
tenant facts and scopes without an owner tenant mean the token's tenant
(`item.py.policy.token-tenant`).
