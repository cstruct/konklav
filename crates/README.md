# Crates

This directory contains the Rust workspace members for Conclave.

Today, each workspace member under `crates/` is also treated as a software item for repository documentation and traceability purposes.

That is a current repository convention, not a permanent rule that every future software item must be a Rust crate. If the repository later grows non-Rust software items, the traceability and documentation model should continue to use `software item` as the broader architecture term.

In practice:

- each directory here is a Rust crate and a workspace member
- each crate should have a README that describes it in the terms contributors and consumers actually encounter, such as CLI, library crate, server, or shared API surface
- crate READMEs should follow [software-item README guidance](../docs/software-item-readmes.md)
