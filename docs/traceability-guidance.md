# Repository Traceability Guidance

This note defines how Conclave repository documentation should be split across Tracey-managed specs, software-item implementation docs, design notes, crate READMEs, and local code comments.

It is intended to keep the repository practical for day-to-day development while leaving room for downstream regulated products to map Conclave into broader traceability models.

## Default boundary

Use `software item` as the default architecture and traceability boundary for repository guidance.

A software item is any identifiable part of a larger software product or subsystem that is important enough to track as a design, dependency, or traceability boundary.

In the current repository, a Rust crate will often be the first concrete software item. That is a convenience, not a rule. Future software items may be services, CLIs, SDKs, UIs, workers, or integrations that are not Rust crates.

Use `crate` only when the Rust-specific packaging boundary is the point.

Use `software unit` sparingly and only when a lower-level design or verification discussion depends on the fact that a software item is not being subdivided further.

## Documentation layers

### Tracey-managed specs

Use `docs/spec/` for stable, normative requirements about product behavior, externally visible contracts, and long-lived architectural obligations.

These docs answer questions such as:

- what Conclave must do
- which boundaries or guarantees other software items can depend on
- which behavior is stable enough to verify and keep traceable over time

Write a Tracey rule when a statement is expected to remain true across refactors and when implementation or verification should be discoverable from that rule ID.

Do not use Tracey for transient implementation choices, local refactors, or short-lived design experiments.

### Software-item implementation docs

Use software-item implementation docs for stable implementation-contract requirements that matter below the product-spec layer.

These docs answer questions such as:

- what responsibilities a software item owns
- which dependencies and interfaces are part of its stable contract
- which cross-item assumptions should stay visible even if code is reorganized

In the current repository, a crate README may be enough for many software items. If a software item grows stable contracts that deserve normative language, add a dedicated implementation doc rather than overloading the README.

### Design notes

Use `docs/architecture/` for rationale, tradeoffs, decomposition notes, migration plans, and evolving architectural decisions that are important but not yet stable enough to become normative requirements.

Design notes explain why the code is shaped a certain way. They do not, by themselves, create obligations that need Tracey coverage.

When a design decision becomes a durable contract that other software items depend on, promote the stable part into a Tracey-managed requirement and keep the rationale in the design note.

### Crate READMEs

Use crate READMEs for onboarding, navigation, and practical implementation orientation.

They should help a contributor answer:

- what this crate is for
- where its main entry points are
- which nearby crates or specs matter most
- how to build, test, or safely change it

Use [software-item README guidance](software-item-readmes.md) as the default format for new or substantially rewritten READMEs.

READMEs may link to specs, design notes, and software-item docs, but they should not become the only home of stable requirements.

### Local code comments

Use local code comments for details that only need to be understood at the point of implementation.

Examples include:

- why a function is structured in a non-obvious way
- invariants local to a module
- wire-format or storage quirks that are easier to understand beside the code

If a comment describes a stable obligation that should survive code movement, it probably belongs in a spec or software-item doc instead.

## When to add a Tracey rule

Add a Tracey rule when most of the following are true:

- another software item, subsystem, or public surface depends on the behavior
- the statement should remain true across refactors
- the rule would help someone find the implementing code or tests later
- violating the statement would be a real bug, contract break, or architectural regression

Keep a statement out of Tracey when most of the following are true:

- it is a local implementation preference
- it changes often during normal development
- it is better explained by code structure, tests, or a nearby comment
- the maintenance cost of a rule would outweigh its value as a durable obligation

## Downstream product mapping

This repository does not define a single repo-wide `software system` boundary.

That boundary belongs to the team responsible for the actual deployed product or service. Different adopters may define it differently for architectural, operational, contractual, assurance, or regulatory reasons.

In that context:

- Conclave as a whole may be treated as one software item within the downstream product or system
- a subset of Conclave may be treated as one or more software items if the downstream architecture needs finer decomposition
- repository-level Tracey rules can provide evidence about stable Conclave obligations without claiming to describe the entire regulated product

In regulated contexts, including medical-device software lifecycles, downstream teams may also map Conclave into a formal software-system and software-item model.

This keeps Conclave's open source documentation honest about its scope while still making it easier for downstream teams to reuse the repository in broader traceability models when they need to.
