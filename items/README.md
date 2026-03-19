# Items

This directory contains the software items that currently make up the Conclave workspace.

Each Rust workspace member under `items/` is also treated as a software item for repository documentation and traceability purposes.

This directory is the canonical namespace for software-item names in the repository. The software-item spec [docs/spec/software-items/managed-config.md](../docs/spec/software-items/managed-config.md) corresponds to `items/managed-config/`, and the same naming rule should hold for future items.

If the repository later grows non-Rust software items, they should also live under `items/` so the traceability and documentation model can keep using `software item` as the broader architecture term without implying that every software item is a Rust crate.

In practice:

- each Rust directory here is a Cargo package and workspace member
- each item should have a README that describes it in the terms contributors and consumers actually encounter, such as CLI, library crate, server, or shared API surface
- Rust item READMEs should follow [software-item README guidance](../docs/software-item-readmes.md)
