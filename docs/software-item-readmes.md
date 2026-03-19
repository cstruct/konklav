# Software-Item READMEs

This note defines the default README format for Conclave software items.

Use `software item` as the architecture and traceability term. Use `crate` only when the Rust packaging boundary is the point.

## Goals

A software-item README should help a contributor answer:

- what this software item is for
- what it owns and what it does not own
- how it relates to nearby software items
- how to run it, if it can be run directly
- how to test it safely
- where its traceability and design context live

The README is for onboarding and navigation. It should not become the only home of stable requirements.

## Default sections

Use these sections by default.

### 1. Title

Use the software-item name as the heading.

For Rust crates, include the crate name in backticks immediately below or in the first paragraph.

### 2. Short description

Summarize the software item's purpose in one or two short paragraphs.

Name the artifact the way contributors or consumers encounter it.

Examples:

- CLI
- Rust crate
- library crate
- server
- shared API surface

Use `software item` as repository guidance vocabulary, not as a mandatory phrase in every opening sentence.

Cover:

- what it does
- who or what uses it
- when someone would interact with it

### 3. Responsibilities

List the main responsibilities the software item owns.

Also include a short `Out of scope` list when that boundary is useful for avoiding confusion.

### 4. Public interface

Describe the main entry points a contributor should know about.

Examples:

- exported types
- key functions or methods
- CLI commands
- HTTP surfaces
- configuration files

README interface sections are overview-level by default.

If the interface surface is small and stable, it is reasonable to enumerate all entry points.

If the interface surface is larger, summarize it by capability area, show representative entry points or commands where helpful, and link to the authoritative source instead of turning the README into a full reference.

### 5. Relationships

Document both direct dependencies and direct dependents.

Use a Markdown table as the default format.

For each relationship, explain why it exists. Do not provide a name-only list.

Treat this as an architectural relationship summary, not a mirror of `Cargo.toml` or another package manifest.

Mermaid diagrams are optional. Use them when the software item sits in a relationship graph that is easier to understand visually than textually.

Include:

- direct Conclave software-item dependencies
- direct Conclave software-item dependents
- external runtime systems when they materially shape the software item's contract, runtime behavior, or data model
- third-party libraries only when they are central enough that omitting them would hide an important architectural constraint

### 6. Usage

Include this section when the software item has a meaningful API, config surface, or invocation pattern that benefits from concrete examples.

For library software items, prefer short examples around the main entry points.

### 7. Running

This section is required.

If the software item is directly runnable, document the exact command or commands.

If it is not directly runnable, say so explicitly and explain how it is exercised instead.

### 8. Testing

This section is required.

Include exact commands for the testing surfaces that exist today.

Use this shape by default:

- `Direct coverage`
  - what the software item's own tests cover
- `Indirect coverage`
  - which downstream software items or end-to-end paths also exercise it

Do not imply that every software item should have the same kinds of tests. Describe the testing shape that exists and matters.

### 9. Behavior notes

This section is optional.

Use it for stable, practical details that are easy to miss when changing the software item.

Examples:

- deterministic merge or ordering rules
- special file handling
- compatibility quirks
- assumptions that are local but important

### 10. Traceability and related docs

Link to the most relevant nearby documentation.

Usually this includes:

- the most relevant spec file under `docs/spec/`
- relevant design notes under `docs/architecture/`
- [traceability guidance](traceability-guidance.md)
- [nomenclature](nomenclature.md)

## Writing guidance

- Prefer concise paragraphs and flat lists over long narratives.
- Explain relationships in terms of responsibilities and boundaries, not just package names.
- Do not duplicate package manifests in the dependency summary.
- Prefer stable facts over aspirational roadmap text.
- Keep examples short and real.
- Treat interface sections as navigational overviews, not exhaustive references, unless the surface is genuinely small.
- If a section does not apply, omit it unless the guidance above says it is required.
- For required sections that do not apply in the obvious way, state that explicitly rather than leaving ambiguity.

## Minimal skeleton

~~~md
# Software Item Name

`crate-name` is the Rust crate or CLI or server for ...

## Responsibilities

- ...

Out of scope:

- ...

## Public Interface

- ...

## Relationships

### Dependency Summary

| Software item | Relationship |
| --- | --- |
| `...` | ... |

### Dependent Summary

| Software item | Relationship |
| --- | --- |
| `...` | ... |

## Running

...

## Testing

```sh
cargo test -p crate-name
```

Coverage shape:

- Direct coverage
  - ...
- Indirect coverage
  - ...

## Traceability And Related Docs

- ...
~~~
