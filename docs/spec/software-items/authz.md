# Authorization Software Item

Stable implementation contracts owned by `konklav-authz`, which compiles
role assignments into entitlement sets and evaluates an operation's
requirements against them.

r[item.authz.sans-io]
`konklav-authz` MUST NOT perform I/O, read clocks or keep state between
calls. Callers supply the catalog, assignments, token claims, session flags
and entitlement sets, and get the result back as a value.

r[item.authz.portable]
`konklav-authz` MUST compile for native targets and for `wasm32`, with no
platform-specific dependencies in its default feature set, so that the
relying core can depend on it.

r[item.authz.single-evaluator]
`evaluate` in `konklav-authz` MUST be the only implementation of decision
evaluation. The check API and the relying core both call it, so that central
and local decisions are computed by the same code.
