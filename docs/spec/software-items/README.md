# Software-Item Specs

This directory holds Tracey-managed software-item implementation specs.

These specs sit below the product-spec layer in `../` and capture stable implementation-contract obligations owned by individual software items.

Use this directory for:

- stable producer-owned contracts
- shared boundary behavior that multiple software items depend on
- implementation-level obligations that are too specific for product specs but too important for README-only documentation
- small stable contract clusters rather than one rule per type by default

Do not use this directory for:

- general product behavior that belongs in the main product specs
- design rationale that belongs in `../../architecture/`
- operational onboarding material that belongs in crate READMEs
- local implementation details that belong in code comments
- exhaustive one-rule-per-type inventories unless the individual types really carry separate long-lived obligations

Rule naming convention:

- `item.<software-item>.*`

Consumer `r[depends ...]` references are optional.

Add them sparingly when a consuming software item clearly relies on the producer-owned contract in a way that would matter during future review or refactoring.

Software-item specs in this directory include:

- `managed-config.md`
- `relying-auth.md`
- `controlplane-api.md`
