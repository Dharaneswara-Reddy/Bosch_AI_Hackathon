---
name: ship-feature
description: Implement a single vertical slice from docs/03-spec.md using TDD and fresh-context code review.
---
Implement the requested feature slice cleanly:
1. Read `docs/02-architecture.md` and `docs/03-spec.md` for the target slice.
2. Write failing acceptance/unit tests first that verify the spec's success criteria.
3. Implement clean, modular code adhering strictly to `CLAUDE.md`.
4. Run the full test suite and type‑checker via Bash until green.
5. Invoke the `reviewer` subagent on the changes. Fix any correctness or security findings, re‑run tests, and summarize what shipped.
