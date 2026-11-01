---
name: konklav-rust
description: Rust conventions for Konklav Rust workspace members. Use when editing Rust code in this repo, especially when introducing new modules, shared types, or representation boundaries.
---

# Konklav Rust

- Read `docs/nomenclature.md` first when a Rust change touches auth, tenancy, API terms, or docs.
- Prefer small facade modules that re-export focused submodules once a file mixes multiple concerns.
  - Good splits: `config`, `model`, `compile`, `tokens`, `sql`, `http`.
- Keep `types.rs` narrow.
  - Put only semantically stable shared aliases or value types there.
  - Do not move every DTO or domain struct into `types.rs`.
- When splitting crates, prefer ownership-based crates such as `core`, `store`, `authz`, `authn`, `server`, `relying` and `cli` (see `docs/architecture/overview.md`) over a generic catch-all shared-model crate.
- Keep `authz` compilation and the `relying` core free of I/O so they stay pure and testable.
- If a `core` crate exists, keep it tiny.
  - Good candidates: stable identifier/revision types and small value types used by multiple crates.
  - Bad candidates: compiled models, HTTP-only DTOs, or full desired-state/config trees.
- Keep representations near the code that owns them.
  - `config`: `ordna` config trees for runtime configuration.
  - `model`: domain models, compiled state, and stable response shapes.
  - `compile`: validation, derivation and resolution.
  - `tokens` or `db`: protocol- or storage-specific encoding logic (Diesel models stay in `store`).
- Prefer explicit transport DTOs in an API crate over sharing server-internal models across the network boundary.
- Preserve external module paths when refactoring.
  - Prefer `foo.rs` as a facade over `foo/` submodules so callers keep using `crate::foo::*`.
- Favor explicit conversions at boundaries over generic mapper crates while the model is still moving.
- Introduce macros only for stable repetition.
  - Good candidates: string newtypes or repetitive impl blocks.
  - Bad candidates: generating full config/create/read/internal type families.
- Keep domain-local structs local even when similar nouns exist elsewhere.
- Keep Tracey `r[impl ...]` and `r[verify ...]` comments attached to the smallest stable function or test that actually owns the behavior.
