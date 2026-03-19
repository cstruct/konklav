# Repository Guidance

- Read [docs/nomenclature.md](conclave/docs/nomenclature.md) before changing specs, API surfaces, auth models, or documentation.
- Read [.agents/skills/conclave-rust/SKILL.md](conclave/.agents/skills/conclave-rust/SKILL.md) before changing Rust code under `items/`.
- For complex features, substantial refactors, or multi-step migrations, create or update a task-specific plan file using [.agents/plans/PLANS.md](conclave/.agents/plans/PLANS.md) before implementation.
- Keep concrete task plans in dedicated Markdown files such as `IMPLEMENTATION_PLAN.md` or `.agents/plans/<topic>.md`; `.agents/plans/PLANS.md` defines the shared planning standard, not a single project plan.
- Use the terminology from [docs/nomenclature.md](conclave/docs/nomenclature.md) consistently in new code, tests, and docs.
- If a new project term is needed, add it to [docs/nomenclature.md](conclave/docs/nomenclature.md) before relying on it elsewhere.
