# Contributing to AgentFence

Thanks for your interest in AgentFence. This document covers everything you
need to build, test, and submit changes.

AgentFence is a security tool. Changes that affect policy evaluation, audit
logging, or redaction receive extra scrutiny.

## Prerequisites

- **Go**: 1.22 or newer (the module declares `go 1.22`; newer toolchains work).
- **make**: any reasonably recent GNU make.
- No other runtime dependencies. The project uses the Go standard library plus
  `gopkg.in/yaml.v3` and nothing else.

Verify:

```bash
go version   # go1.22 or newer
make help    # lists available targets
```

## Build

```bash
make build           # produces ./agentfence
./agentfence version
```

To embed a release version at build time:

```bash
make build VERSION=0.1.0
./agentfence version
# agentfence 0.1.0 linux/amd64
```

## Test

```bash
make test            # plain go test ./...
make test-race       # go test -race with coverage profile (used in CI)
make cover           # runs test-race then opens an HTML coverage report
```

To run a single package or test:

```bash
go test ./internal/engine/...
go test ./internal/policy -run TestParsePolicy
```

### Test style

- Use the standard library `testing` package only — no testify, no helper
  libraries.
- Prefer table-driven tests for branching logic (see
  `internal/engine/engine_test.go` for examples).
- Tests must fail without the change and pass with it.
- Do **not** use real credentials, even in fixtures. Use clearly fake values
  such as `sk-demo-secret` or `ghp_fake_token_for_tests`.

### Fuzz tests

Go native fuzz targets cover the security-critical parsers — policy YAML,
tool-call JSONL, the glob matcher, and the redactor. They are kept under the
same `_test.go` files (`internal/{policy,engine,redact}/fuzz_test.go`).

The seed corpora run as part of `go test ./...` (and therefore `make ci`).
To actually fuzz, use the `fuzz` target:

```bash
make fuzz                 # 30s per target (default)
make fuzz FUZZTIME=2s     # quick smoke
make fuzz FUZZTIME=5m     # overnight-ish
```

Go's native fuzzer only fuzzes one target per `go test` invocation, so `make
fuzz` iterates them sequentially. Any newly discovered failing inputs are
written to `testdata/fuzz/<TargetName>/…` under the affected package; commit
them as regression fixtures alongside the fix.

## Lint

```bash
make lint            # vet + gofmt -l check
make fmt             # apply gofmt in place
make fmt-check       # fail if anything needs reformatting (used in CI)
```

CI rejects any code that is not `gofmt`-clean. Run `make fmt` before committing
or wire your editor to format on save.

## Demo

```bash
make demo
```

Expected output is shown in the README under **Demo output**. If you change
the demo, update the README to match.

## Pre-push gate

Before opening a pull request, run:

```bash
make ci
```

This is the same command CI runs. It performs `fmt-check`, `vet`, and
`test-race` with coverage. If `make ci` is green, your PR should pass CI.

## Release artifacts

We use [GoReleaser](https://goreleaser.com) for cross-platform release
artifacts. To validate the configuration locally without producing a release:

```bash
# Install goreleaser once (see https://goreleaser.com/install/)
make release-check
```

CI also runs `goreleaser check` on every PR.

## PR guidelines

### Branch naming

Use a short prefix that describes the change:

- `feat/` — new feature or capability
- `fix/` — bug fix
- `docs/` — documentation only
- `chore/` — tooling, CI, deps, refactors
- `test/` — tests only

Example: `feat/policy-imports`, `fix/redact-nested-arrays`.

### Commit and PR titles

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add policy imports for reusable packs
fix(engine): handle empty path argument
docs(threat-model): add MCP proxy attack surface
chore(ci): add coverage summary step
```

The `^docs:`, `^test:`, and `^chore:` prefixes are excluded from auto-generated
release changelogs (see `.goreleaser.yml`).

### PR scope

- One PR = one concern. Smaller PRs ship faster and review better.
- If you find an unrelated bug while working on something else, open a
  separate issue rather than bundling fixes.
- Use the [PR template](.github/PULL_REQUEST_TEMPLATE.md). Every PR must
  reference the issue it addresses with `Fixes #N` or `Refs #N`.

### Required checks

Every PR must:

- [ ] Pass `make ci` locally before push.
- [ ] Update or add tests for any behavior change.
- [ ] Update README, `docs/`, or inline documentation if user-visible behavior
  changes.
- [ ] Reference an issue number.

## Adding a new package

- Packages live under `internal/` unless they are intentionally part of the
  public Go API (none are today).
- Each package keeps its tests next to the code (`foo.go` + `foo_test.go`).
- Avoid cross-package import cycles. If two packages need each other, extract
  the shared types into a third package.

## Policy schema changes

The policy schema (`internal/policy/policy.go`) is user-facing. Any change to
it must:

1. Be backward-compatible with existing policies where possible, or include a
   clear deprecation path.
2. Update `docs/policy-language.md`.
3. Update `examples/policy.yaml` to demonstrate the new field where useful.
4. Add cases to `internal/policy/policy_test.go` covering valid, invalid, and
   omitted forms.
5. If the change affects the audit event format, bump the audit schema
   version (see issue #31 once implemented).

## Security-sensitive changes

If your change touches `internal/policy`, `internal/engine`, `internal/audit`,
or `internal/redact`:

- Call it out in the PR description.
- Add explicit test cases for the security-critical behavior (e.g., deny
  precedence, redaction of nested structures, escape attempts).
- Do not relax existing default-deny behavior without explicit discussion in
  an issue first.

## Reporting bugs

Use the [bug report issue template](.github/ISSUE_TEMPLATE/bug_report.md).
Include the AgentFence version (`./agentfence version`), Go version, OS, and
a minimal policy + tool-call input that reproduces the problem.

## Reporting vulnerabilities

Do **not** open a public issue for security vulnerabilities. See the project
README for current contact channels.

## License

By contributing, you agree that your contributions will be licensed under the
same license as the project (see [LICENSE](LICENSE)).
