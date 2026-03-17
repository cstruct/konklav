# Conclave Specs

This directory holds the Tracey-managed requirements for Conclave.

Shared terminology is defined in `../nomenclature.md` and should be treated as the default vocabulary for these specs.

Rules are defined with standalone `r[...]` markers. Implementation and tests can then reference the same rule IDs from code comments using `r[impl ...]` and `r[verify ...]`.

The current files are placeholders meant to establish the initial vocabulary and domain boundaries:

- platform
- managed configuration
- tenancy and identity
- authentication and authorization
- tokens and claims
- federation and protocols
