# Conclave Specs

This directory holds the Tracey-managed requirements for Conclave v2.

Use the vocabulary in [`../nomenclature.md`](../nomenclature.md). Specs never
name a specific relying system.

Rules are defined with standalone `r[...]` markers. Implementation and tests
reference them from code comments as `r[impl ...]` and `r[verify ...]`.

Product specs:

- [platform](platform.md): repository shape, runtime, configuration,
  storage and errors
- [tenancy and identity](tenancy-and-identity.md): tenants, subjects,
  credentials, memberships and facts
- [authentication](authentication.md): login, MFA, step-up, sessions, session
  flags, challenges and delivery
- [authorization](authorization.md): catalog, roles, templates, policies,
  assignments, entitlements and the check API
- [tokens and claims](tokens-and-claims.md): access tokens, refresh tokens
  and signing keys
- [change feed](change-feed.md): events, cursors and transport
- [relying systems](relying-systems.md): obligations on the relying core and
  host bindings

Software-item implementation specs live under
[`software-items/`](software-items/README.md).

Rationale and tradeoffs live in [`../architecture/`](../architecture/); they
are not normative.
