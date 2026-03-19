# Software-Item Implementation Specs

This note defines the proposed approach for software-item implementation specs in Conclave.

The goal is to capture stable implementation-contract obligations that matter below the product-spec layer without turning every crate detail into a Tracey rule.

## Why this layer exists

The existing product specs under `docs/spec/` answer questions such as:

- what Conclave must do
- what external or cross-cutting behavior must remain true
- what long-lived architectural obligations other software items can depend on

That is necessary, but not always sufficient.

Some implementation contracts are too low-level or software-item-specific to fit cleanly into product specs, yet too stable and important to leave only in READMEs, design notes, or nearby code comments.

Software-item implementation specs are for that middle layer.

## Requirement layering

Use these layers in order:

### Product specs

Location:

- `docs/spec/*.md`

Use product specs for:

- externally visible behavior
- cross-cutting architectural obligations
- domain rules that outlive any one software item

Product specs answer:

- what the platform must do
- what guarantees other software items or external consumers can depend on

### Software-item implementation specs

Location:

- `docs/spec/software-items/*.md`

Use software-item implementation specs for stable contracts owned by one software item.

Typical content:

- canonical internal boundary types
- stable assembly or translation behavior
- durable validation or compatibility obligations
- shared producer-owned contracts that multiple consumers depend on

Software-item specs answer:

- what stable contract this software item owns
- what other software items can depend on from this software item

### Design notes

Location:

- `docs/architecture/*.md`

Use design notes for:

- rationale
- tradeoffs
- migration plans
- evolving decomposition choices

Design notes explain why the system is shaped a certain way. They do not, by themselves, create normative obligations.

### READMEs

Location:

- crate-local `README.md`

Use READMEs for:

- onboarding
- navigation
- running and testing
- practical orientation

READMEs should link to specs. They should not be the only home of stable implementation contracts.

### Local code comments

Use code comments for:

- local invariants
- nearby implementation detail
- details that only matter at the point of code

If a comment describes a stable obligation that should survive code movement, it probably belongs in a software-item spec or product spec.

## Cross-item contracts

Use producer ownership by default.

The software item that owns and can change a contract should own the normative rule.

Consumers should not usually duplicate that rule in their own spec file. Instead:

- the producer owns the rule text
- important consumers may reference it from code with `r[depends ...]`
- READMEs may mention the relationship in narrative form

Treat `r[depends ...]` references as optional and sparse.

Use them when the dependency is a meaningful contract boundary that would be important to revisit if the producer-owned rule changes. Do not add them for every incidental type use or routine call site.

Use this heuristic:

- if one software item can change the behavior, that software item owns the rule
- if a dedicated shared boundary crate exists, that boundary crate owns the rule
- if the behavior is broader than any one software item, keep it in product spec

Examples in this repository:

- `conclave-managed-config` owns the canonical managed-config bundle and directory-assembly behavior
- `conclave-relying-auth` owns the JWT signing, verification, JWKS, and offline evaluation boundary
- `conclave-controlplane-api` owns the shared Rust DTO boundary for current control-plane operations

## Repository shape

Keep the existing product-spec location:

- `docs/spec/*.md`

Add software-item implementation specs under:

- `docs/spec/software-items/*.md`

Why this shape:

- it keeps all Tracey-managed requirements under one scanned tree
- it avoids introducing a second normative-doc root before there is a stronger need
- it lets product specs and software-item specs live next to each other while staying conceptually separate

## Naming conventions

Use the prefix:

- `item.<software-item>.*`

Examples:

- `item.managed-config.root-bundle`
- `item.relying-auth.validation-options`
- `item.controlplane-api.shared-dto-boundary`

Keep software-item rule names focused on stable producer-owned behavior, not on file structure or incidental implementation choices.

Software-item rules should usually describe a small stable contract cluster rather than every individual type, function, or DTO.

For example, one rule about managed-operation payload shape or one rule about subject-and-relying DTOs is usually better than one rule per request and response struct unless the individual DTOs truly have separate long-lived obligations.

## Acceptance criteria for adding a software-item rule

Add a software-item implementation rule when most of the following are true:

- the behavior is owned by one software item
- another software item or external consumer depends on it
- the obligation should remain true across refactors
- a README would be too informal and a product spec would be too broad

Do not add a software-item rule when most of the following are true:

- the behavior is just a local implementation preference
- it is likely to churn during ordinary refactoring
- a local code comment or design note communicates it well enough
- no other software item or long-lived boundary really depends on it

## Pilot selection

Start with software items that are shared boundaries rather than thin wrappers.

Recommended first pilots:

- `conclave-managed-config`
- `conclave-relying-auth`
- `conclave-controlplane-api`

Why these:

- they have clear producer-owned contracts
- they have multiple dependents
- they are easier to specify cleanly than the server, which already carries a lot of product-spec behavior

## Current pilot rules

The first pilot files live under `docs/spec/software-items/`:

- `managed-config.md`
- `relying-auth.md`
- `controlplane-api.md`

These should be treated as a starting point for discussion, naming, and scope, not as a sign that every crate now needs its own implementation spec immediately.
