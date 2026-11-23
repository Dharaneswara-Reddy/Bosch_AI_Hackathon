---
name: design-phase
description: Convert docs/01-research.md into a locked system architecture and vertical-slice spec.
---
Execute the System Design Phase:
1. Invoke the `architect` subagent to read `docs/01-research.md` and generate `docs/02-architecture.md` and `docs/03-spec.md`.
2. Review the generated spec with the user, highlighting any open decisions (auth, DB choice, external APIs).
3. Once approved, scaffold the directory structure and base configuration files (`.env.example`, linter config, test runner).
