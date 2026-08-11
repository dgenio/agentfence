# Contributing to AgentFence

Thanks for your interest in AgentFence. This document covers everything you
need to build, test, and submit changes.

AgentFence is a security tool. Changes that affect policy evaluation, audit
logging, approval, proxy mediation, identity assumptions, or redaction receive
extra scrutiny.

## Before you start: claim substantial issue work

AgentFence is developed quickly, including with maintainer-run coding agents.
That should not make external contribution a race against maintainer automation.

If you plan more than a tiny drive-by fix, **comment on the issue before you
start** with the scope you intend to implement. For issues carrying `help
wanted` or `good first issue`, the maintainer will acknowledge the claim and
reserve the work for a bounded window (normally about 14 days, adjusted for
scope).

While an issue is reserved:

- maintainer-run coding agents should not implement or bundle that issue into a
  sweep PR;
- the contributor should post a short progress update if the work needs more
  time;
- an active reservation can be extended reasonably when progress is visible;
- if the reservation expires without progress, the issue becomes available
  again;
- a security emergency or release-blocking fix may override a reservation, but
  the maintainer should explain why and, where practical, offer another
  suitable issue.

This policy is meant to prevent duplicated/obsolete contributor work, not to
reserve speculative issues indefinitely. Design-heavy work labeled
`needs-design` should normally be resolved at the issue/design level before an
implementation is claimed.

If you opened a PR without claiming an issue first, it is still welcome, but
there is a higher risk that the same area changed in parallel.

See [#224](https://github.com/dgenio/agentfence/issues/224) for the contributor-
experience rationale and follow-up work.

## Prerequisites

- **Go**: 1.22 or newer (the module declares `go 1.22`; newer toolchains work).
- **make**: any reasonably recent GNU make.
- No other runtime dependencies. The project uses the Go standard library plus
  `gopkg.in/yaml.v3` and `github.com/google/uuid`.

Verify:

```bash
go version   # go1.22 or newer
make help    # lists available targets
```

## Build

```bash
make build
./agentfence version
```

To embed a release version at build time:

```bash
make build VERSION=0.1.0
./agentfence version
```

## Test

```bash
make test
make test-race
make cover
```

To run a single package or test:

```bash
go test ./internal/engine/...
go test ./internal/policy -run TestParsePolicy
```

### Test style

- Use the standard library `testing` package unless an existing package already
  requires something else.
- Prefer table-driven tests for branching logic.
- Tests for behavior changes should fail without the change and pass with it.
- Do **not** use real credentials, even in fixtures. Use clearly fake values
  such as `sk-demo-secret` or `ghp_fake_token_for_tests`.
- Security claims need negative/adversarial cases, not only happy paths.

### Fuzz tests

Go native fuzz targets cover security-critical parsers and matchers. The seed
corpora run as part of ordinary tests; to fuzz actively:

```bash
make fuzz
make fuzz FUZZTIME=2s
make fuzz FUZZTIME=5m
```

Commit newly discovered failing inputs as regression fixtures alongside the
fix.

## Lint

```bash
make lint
make fmt
make fmt-check
make golangci
make sec
```

CI rejects code that is not `gofmt`-clean. `make lint` also runs
`golangci-lint` and `gosec`. Intentional security-tool behavior is annotated at
the call site rather than disabled globally so new findings still fail the
build.

## Dependency and vulnerability hygiene

```bash
make vuln
```

Dependencies and pinned GitHub Actions are updated automatically by Dependabot,
and CI runs vulnerability/security checks. See `SECURITY.md` for the
supply-chain posture.

## Examples and docs checks

```bash
make examples
make doc-check
```

Both run in CI. Keep `examples/`, README, and `docs/` synchronized with actual
CLI behavior. Security examples must distinguish what the demo proves from what
it does not prove.

## Demo

```bash
make demo
```

The maintained MCP boundary proof is also exercised by the examples CI. If a
change affects its claims, update the expected receipt/docs in the same PR.

## Pre-push gate

Before opening a pull request, run:

```bash
make ci
```

CI additionally exercises lint/security/examples/docs checks and a
Linux/macOS/Windows test matrix. A green local `make ci` is the minimum pre-push
signal, not a substitute for the hosted checks.

## Release artifacts

We use GoReleaser for cross-platform release artifacts. Validate release
configuration locally with:

```bash
make release-check
```

CI also runs the release-configuration checks.

## PR guidelines

### Branch naming

Use a short prefix that describes the change:

- `feat/` — new feature or capability
- `fix/` — bug fix
- `docs/` — documentation only
- `chore/` — tooling, CI, deps, refactors
- `test/` — tests only

Examples: `feat/policy-imports`, `fix/redact-nested-arrays`.

### Commit and PR titles

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```text
feat: add policy imports for reusable packs
fix(engine): handle empty path argument
docs(threat-model): add MCP proxy attack surface
chore(ci): add coverage summary step
```

The repository has an advisory PR-title check for this convention.

### Auto-labeling

PRs are labeled automatically by changed path using the existing `area:*` and
documentation/developer-experience taxonomy. Labels are additive and can be
adjusted manually.

### PR scope

- One PR = one concern. Smaller PRs ship faster and review better.
- If you find an unrelated bug, open a separate issue rather than bundling it.
- Use the [PR template](.github/PULL_REQUEST_TEMPLATE.md).
- Reference the issue with `Fixes #N` or `Refs #N`.
- If the issue was reserved to you, keep the issue updated if the scope or
  expected timing changes materially.

### Required checks

Every PR must:

- [ ] Pass `make ci` locally before push when the local environment supports it.
- [ ] Update/add tests for behavior changes.
- [ ] Update README/docs/inline documentation for user-visible behavior.
- [ ] Reference an issue number.
- [ ] State security-boundary changes explicitly when applicable.

## Maintainer-agent contribution rule

Maintainer-run agents are welcome for implementation, review, testing, and
maintenance, but they must not make human contribution futile.

When selecting work for automated/agentic implementation:

1. exclude issues currently claimed/reserved by an external contributor;
2. avoid bundling `good first issue` / `help wanted` work that has been
   intentionally left as an entry point;
3. prefer backlog items labeled `agent-ready` only when design is settled;
4. do not treat issue count or closure velocity as the primary OSS-health
   metric;
5. when an external PR overlaps newly landed maintainer work, explain the
   overlap clearly and salvage/rebase the contribution where reasonable rather
   than silently closing it.

The desired outcome is more useful outside work landing successfully, not
maximum maintainer throughput.

## Adding a new package

- Packages live under `internal/` unless intentionally part of a public Go API.
- Keep tests next to code.
- Avoid import cycles; extract shared types deliberately when necessary.

## Policy schema changes

The policy schema is user-facing. Changes must:

1. preserve compatibility where practical or document migration/deprecation;
2. update `docs/policy-language.md`;
3. update examples where useful;
4. add valid, invalid, omitted, and adversarial cases;
5. update any public schema/contract representation in lockstep;
6. update the audit schema/version when the serialized audit contract changes.

Authorization semantics should remain explicit and deterministic. Generic
reference policies are examples, not proof that an environment is safe.

## Security-sensitive changes

If your change touches the policy engine, MCP/HTTP proxy boundary, approval,
audit, redaction, server/tool identity, or policy binding:

- call it out prominently in the PR description;
- add explicit adversarial tests (bypass, malformed input, replay/drift, deny
  precedence, secret redaction, etc. as relevant);
- do not relax default-deny/fail-closed behavior without explicit issue/design
  discussion;
- distinguish current guarantees from aspirational design in docs;
- do not add broad security claims merely because a test/example passes;
- consider whether the change belongs in the scope of the independent security
  review tracked by [#223](https://github.com/dgenio/agentfence/issues/223).

## Reporting bugs

Use the [bug report issue template](.github/ISSUE_TEMPLATE/bug_report.md).
Include the AgentFence version, Go version, OS, and a minimal policy + tool-call
input that reproduces the problem.

## Reporting vulnerabilities

Do **not** open a public issue for security vulnerabilities. Follow
`SECURITY.md` and GitHub's private vulnerability-reporting path.

## License

By contributing, you agree that your contributions will be licensed under the
same license as the project (see [LICENSE](LICENSE)).
