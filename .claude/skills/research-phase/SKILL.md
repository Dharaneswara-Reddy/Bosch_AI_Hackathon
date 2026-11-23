---
name: research-phase
description: Run deep pre-code research on a hackathon problem statement and save findings to docs/01-research.md.
---
Execute the Research Phase for the problem statement provided by the user:
1. Spawn 2–3 parallel `researcher` subagents to investigate:
   - Subagent 1: State-of-the-art methods, algorithms, and model architectures for this problem.
   - Subagent 2: Best-in-class SDKs, APIs, and open-source tools to build it fast.
   - Subagent 3: Edge cases, evaluation metrics, and winning differentiation angles.
2. Synthesize all findings into `docs/01-research.md` with a clear recommendation on the winning approach.
3. Stop and ask the user to confirm the chosen approach before moving to `/design-phase`.
