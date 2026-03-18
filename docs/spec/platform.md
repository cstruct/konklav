# Platform

This file defines the repo-level requirements that let the project stay spec-driven as it grows.

## Repository shape

r[platform.monorepo.structure]
The repository MUST keep specifications under `docs/spec/` and implementation code under language-specific workspace roots so Tracey can map requirements to code as the system evolves.

r[platform.traceability.spec-first]
User-facing capabilities MUST be described in Tracey-managed specifications before they are treated as implementation targets.

## Server foundation

r[platform.server.bootstrap]
The repository MUST provide a Rust server workspace member that can build and run as the authoritative Conclave control-plane API entry point.

r[platform.cli.operator-interface]
The repository MUST provide a Rust CLI workspace member that serves as the operator interface for validating, planning, and applying managed configuration against the Conclave control plane.

r[platform.relying-auth.library]
The repository MUST provide a Rust library workspace member that lets relying systems validate Conclave-issued JWTs and evaluate token-carried authorization snapshots offline.

r[platform.server.control-plane-boundary]
The first server component MUST own the orchestration boundary for tenants, identities, authentication, authorization, and federation even if those domains are later split into separate services.

r[platform.server.multi-surface-runtime]
The first server component MUST support distinct control-plane, subject-facing, and relying-system HTTP surfaces even when they run from one process.
