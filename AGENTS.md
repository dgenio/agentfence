# AGENTS.md — repo rules for AI coding agents

This file gives AI coding agents the repo-specific rules to follow **before
opening a PR**. It is a thin pointer to the canonical sources — the
[Makefile](Makefile) and [CONTRIBUTING.md](CONTRIBUTING.md) — not a duplicate of
them. When in doubt, those two win.

## Before every push

Run the same gate CI runs, and do not open a PR that fails it:

```bash
make ci   # gofmt -l check + go vet + go test -race with coverage
```

`make fmt` applies formatting; CI rejects any file that is not `gofmt`-clean.

## Rebase carefully against these high-churn files

These conflict often across concurrent agent branches — rebase (don't blindly
merge) and re-run `make ci` after:

- `cmd/agentfence/main.go`
- `cmd/agentfence/main_test.go`
- `README.md`
- `CHANGELOG.md`

## Branch naming

Use a prefix that matches the change (see CONTRIBUTING.md):
`feat/` · `fix/` · `docs/` · `chore/` · `test/`. Example: `docs/quickstart`.

## Commits and PRs

- **Conventional Commit** titles: `feat:`, `fix(engine):`, `docs(modes):`, etc.
- Every PR references an issue: `Fixes #N` or `Refs #N`.
- Use the [PR template](.github/PULL_REQUEST_TEMPLATE.md); don't delete its
  checklist — check items off or mark them N/A.
- One PR = one concern; open a separate issue for unrelated bugs you spot.

## Security-sensitive paths (extra scrutiny)

Changes under `internal/policy`, `internal/engine`, `internal/audit`, or
`internal/redact`:

- Call it out in the PR description.
- Add explicit tests for the security-critical behaviour (deny precedence,
  redaction of nested structures, path-escape attempts).
- Never relax default-deny behaviour without prior discussion in an issue.

## Test style

- Standard library `testing` only — no testify or helper libraries.
- Prefer table-driven tests (see `internal/engine/engine_test.go`).
- Tests must fail without the change and pass with it.
- Never use real credentials, even in fixtures — use obvious fakes like
  `sk-demo-secret` or `ghp_fake_token_for_tests`.

## Where to look

- Build/test/lint targets: [Makefile](Makefile) (`make help`).
- Full contributor guide: [CONTRIBUTING.md](CONTRIBUTING.md).
- Architecture: [docs/architecture.md](docs/architecture.md).
- What the project does and does not promise: [docs/claims.md](docs/claims.md).
- Direction: [ROADMAP.md](ROADMAP.md).
