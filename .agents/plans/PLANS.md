# Konklav Plan Standard

This file defines the shared standard for task-specific planning documents in this repository.

Use it when creating or updating concrete plan files such as `IMPLEMENTATION_PLAN.md`, `.agents/plans/<topic>.md`, or another task-specific Markdown file. This file is the rubric. It is not itself the active implementation plan for every change.

## Purpose

A plan document should let a new contributor, or a coding agent with no prior context, understand why the work matters, what the intended end state is, how to implement it safely, and how to prove it works.

Plans are required for work that is likely to span multiple commits, multiple sessions, or multiple design and implementation steps. Small, obvious, single-file edits do not need a full plan unless the user asks for one.

## Core Principles

Every plan must be:

- Self-contained enough that a newcomer can follow it without needing hidden context from chat history.
- Outcome-focused, not just a list of code edits.
- A living document that is updated as decisions, discoveries, and progress change.
- Spec-first: requirements and design should be clarified before implementation is treated as complete.
- Verifiable: it must say how to observe the intended behavior or otherwise prove the change works.

When a plan depends on prior work, restate the important assumptions instead of relying on memory. Link to relevant repo files, but also summarize the context the reader needs.

## When To Use A Plan

Create or update a task-specific plan when the work involves any of the following:

- A complex feature or substantial refactor.
- A migration that spans multiple files, layers, or milestones.
- Design uncertainty that should be resolved before or during implementation.
- Work that is expected to continue across multiple sessions.
- User-visible behavior, data model, persistence, or API changes that need explicit acceptance criteria.

If there are several concurrent efforts, prefer several focused plan files over one overloaded master plan.

## Required Structure

Each concrete plan file should usually contain these sections, adapted to the task:

1. Title
2. Purpose or goal
3. Current direction or constraints
4. Progress snapshot
5. Known gaps or open questions
6. Task workflow
7. Task list or milestones
8. Verification or testing strategy
9. Decision notes
10. Updating this plan

Not every plan needs the exact same section names, but it should cover the same concerns.

## Writing Guidance

Start by explaining what becomes possible after the work is done and how someone will know it succeeded. Prefer concrete outcomes over internal implementation language.

Name repository paths, modules, commands, and important data objects precisely. If a term is project-specific or easy to misread, define it in plain language the first time it appears.

Resolve ambiguity in the plan when possible. Do not leave major design choices implicit if those choices affect behavior, safety, migration order, or acceptance criteria.

Keep the plan idempotent and safe to resume. Someone should be able to stop midway, come back later, and continue from the document without guessing what changed.

## Plan Workflow

Every task or milestone in a concrete plan should follow this workflow unless there is a documented reason not to:

- Define or update requirements first.
- Write or update design notes before committing to implementation details.
- Implement the code.
- Add or update tests.
- Update docs.
- Run verification and compare requirements, design, code, tests, and docs.
- If any mismatch appears, loop back to requirements and design before continuing.
- Land one coherent changeset where practical.
- Update the plan to reflect the new reality.

If something is unclear and the answer would materially change the implementation, record the question explicitly and resolve it before marking the work complete.

## Progress Tracking

Concrete plan files should make progress easy to inspect at a glance.

Use checklists for:

- Completed slices
- Known gaps
- Per-task or per-milestone work items

Checklist items in concrete plans should include stable short IDs when the plan is likely to be referenced across multiple sessions or status updates.

- Prefer IDs that are easy to read in conversation, for example `T5.1`, `G2`, or `V3`.
- IDs should be stable once introduced; do not renumber completed items unless there is a strong reason.
- Put the ID at the start of the checklist text so humans and agents can cite it directly in chat and progress reports.
- Apply IDs at least to task and milestone checklists. Use them for progress snapshots or known gaps too when those lists are expected to be referenced frequently.

When a task completes:

1. Mark the relevant checklist items complete.
2. Update the progress snapshot.
3. Record follow-up work discovered during implementation.
4. Update decision notes if the design changed.

Do not leave stale checked or unchecked items that no longer describe the codebase.

## Verification Standard

A plan must describe how the reader can validate the intended behavior. Good verification includes one or more of:

- Specific tests to run.
- Expected observable behavior.
- Migration checks.
- Restart or persistence checks where relevant.
- Documentation updates that match the implemented system.

Avoid acceptance criteria that only restate internal code structure. Prefer statements that a human can verify directly.

## Decision Notes

Include a section for important design decisions, tradeoffs, and reversals. The goal is to preserve why the current direction was chosen, not just what the current direction is.

When you change the plan materially, update this section so a later reader can understand the pivot without reading prior chat logs.

## Relationship To Existing Plans

`IMPLEMENTATION_PLAN.md` and similar files are concrete plan instances. They should follow this standard while staying tailored to the actual effort.

It is acceptable to keep:

- one long-lived implementation plan for an ongoing initiative
- several focused plan files for parallel efforts
- short plan files for one-off migrations or refactors

Choose the structure that keeps each plan readable and current. For agent-maintained task plans, prefer `.agents/plans/` unless there is a reason for the plan to live at the repository root.

## Anti-Patterns

Avoid plans that:

- only list code edits without stating the user-visible goal
- assume unstated background knowledge
- become stale after implementation starts
- mix unrelated initiatives into one giant checklist
- treat tests or docs as optional afterthoughts
- mark work complete without describing verification

## Minimal Skeleton

Use this as a starting point for new task-specific plans:

```md
# <Plan Title>

This file tracks the plan for <initiative>.

## Goal

Describe the outcome and how success will be recognized.

## Constraints And Assumptions

- ...

## Progress Snapshot

Completed slices:

- [ ] ...

Known gaps:

- [ ] ...

## Task Workflow

- [ ] Define or update requirements first.
- [ ] Write or update design notes.
- [ ] Implement the code.
- [ ] Add or update tests.
- [ ] Update docs.
- [ ] Run verification and compare requirements, design, code, tests, and docs.
- [ ] If any mismatch appears, loop back before continuing.
- [ ] Land one coherent changeset.
- [ ] Mark the task complete in this file.

## Task List

### Task 1: <name>

Goal: <goal>

- [ ] T1.1 ...

## Verification Strategy

- ...

## Decision Notes

- ...

## Updating This Plan

1. Mark completed work.
2. Add follow-up tasks.
3. Keep the snapshot and gaps current.
```
