# Project Standards & Factory Rules

## Workflow Phases (Strict Order)
1. **Research (`/research-phase`)**: Never write application code before `docs/01-research.md` exists.
2. **Design (`/design-phase`)**: Lock architecture, data models, and API contracts in `docs/02-architecture.md` and `docs/03-spec.md` before scaffolding.
3. **Build (`/ship-feature`)**: Implement one vertical slice at a time with tests and fresh-context review.

## Industry Coding Standards
- **Modularity**: Single Responsibility Principle. Keep functions under 40 lines; separate business logic (services) from transport (routes/UI) and data access.
- **Type Safety & Validation**: Strict typing everywhere (no `any` or untyped dicts). Validate all external inputs at system boundaries (Pydantic / Zod).
- **Error Handling**: Never swallow exceptions silently. Return structured error responses with actionable messages.
- **Security**: Zero hardcoded secrets. Load all keys via `.env` and validate presence at startup.
- **Cleanliness**: No dead code, no commented-out blocks, no `TODO` placeholders in committed features.

## Commands
- Build: `<your build command>`
- Test: `<your test command>`
- Lint/Typecheck: `<your lint & typecheck command>`
