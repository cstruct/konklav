---
name: software-item-readme
description: Create or substantially update a Konklav software-item README. Use when adding a new README for a crate or other software item, or when revising README structure, relationships, run/test instructions, or traceability links.
---

# Software Item README

- Read `../../../docs/nomenclature.md` and `../../../docs/software-item-readmes.md` first.
- Keep the README aligned with the repo guidance instead of inventing a one-off format.
- Use `software item` for architecture and traceability language.
  - Use `crate` only when the Rust packaging boundary is the point.
- Build the README from repository facts, not guesses.
  - Inspect the software item's manifest, public entry points, direct dependencies, direct dependents, tests, and nearby specs or design notes.
- Required sections come from the repo doc.
  - `Running` and `Testing` are always required.
  - If a software item is not directly runnable, say so explicitly and explain how it is exercised.
- Keep `Public interface` at overview level unless the surface is genuinely small.
  - For larger HTTP, CLI, or config surfaces, group by capability and point to the authoritative source instead of enumerating every endpoint, flag, or field.
- In `Relationships`, explain why each dependency or dependent matters.
  - Use Markdown tables by default.
  - Treat the section as an architectural summary, not a package-manifest dump.
  - Prefer in-repo software items and external runtime systems.
  - Mention third-party libraries only when they impose an important architectural constraint.
  - Add Mermaid only when the visual graph genuinely helps.
- In `Testing`, document the current testing shape without implying missing categories are defects.
  - Use `Direct coverage` for what the software item's own tests cover.
  - Use `Indirect coverage` for downstream software items or end-to-end paths that also exercise it.
- Keep stable facts in the README.
  - Avoid speculative roadmap text and maintainer instructions that belong in repo guidance instead.
- Link the most relevant spec, architecture note, traceability guidance, and nomenclature docs.
- Before finishing, verify any documented commands you added if they are practical to run in the current environment.
