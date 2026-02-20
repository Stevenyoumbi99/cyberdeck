# CyberDeck Git Workflow

> Branching strategy, commit conventions, and team collaboration rules.

## Branches

- `main` — Stable releases only. Never develop directly on main.
- `dev` — Integration branch. All feature branches merge here first.
- `feature/*` — One branch per module (e.g., `feature/lan-scan`, `feature/wifi-audit`).

## Commit Message Format

```
type(scope): short description

Examples:
feat(lan_scan): add ARP discovery function
fix(logger): handle missing log directory
docs(architecture): add data flow diagram
refactor(menu): simplify module discovery
```

## Rules

1. Always `git pull origin dev` before starting work.
2. Never develop on `main` or `dev` directly.
3. Create a feature branch for every module or change.
4. Test locally before merging.
5. Never edit someone else's module without telling them.
