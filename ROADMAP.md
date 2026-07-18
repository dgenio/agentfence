# AgentFence roadmap

_Last updated: 2026-07-05._

This is a **directional** roadmap, not a commitment or a dated release plan.
Items are described at the theme level; the authoritative, always-current source
of truth is the issue tracker — specifically the
[`roadmap`](https://github.com/dgenio/agentfence/labels/roadmap) label. When this
document and the tracker disagree, the tracker wins.

The README's short roadmap section links here rather than restating items, so the
two cannot drift.

## Completed foundations

AgentFence's initial phased roadmap is complete. Each phase was tracked as an
epic and is now closed:

- **Phase 0 — Harden the MVP** ([#2](https://github.com/dgenio/agentfence/issues/2)):
  CONTRIBUTING, CI (gofmt/vet/race/coverage), `version`/`validate`, structured
  output, strict YAML validation, safe path handling, release tooling.
- **Phase 1 — Expand the policy language** ([#3](https://github.com/dgenio/agentfence/issues/3)):
  wildcards and tool groups, argument/URL/shell-command constraints, `policy
  test`, `explain`, and policy imports/packs.
- **Phase 2 — MCP proxy support** ([#4](https://github.com/dgenio/agentfence/issues/4)):
  the stdio proxy, live tool-call interception, interactive TTY approval with
  timeout, and the integration guide.
- **Phase 3 — Trustworthy audit logs** ([#5](https://github.com/dgenio/agentfence/issues/5)):
  schema version + sequence + session id, tamper-evident hash chaining, `audit
  verify`, expanded threat model, and fuzz tests.

Additional shipped capabilities beyond the original phases include cryptographic
audit signing ([#95](https://github.com/dgenio/agentfence/issues/95)), a signed
multi-channel release with SBOM and provenance
([#111](https://github.com/dgenio/agentfence/issues/111)), a streamable-HTTP
proxy, and structured decision observability (reason codes, metrics, logging).
See [CHANGELOG.md](CHANGELOG.md) for specifics.

## Current direction

The forward-looking work presently carrying the `roadmap` label:

### Deeper enforcement

- **Response-side policy** ([#96](https://github.com/dgenio/agentfence/issues/96)):
  inspect, redact, or block tool *results* before they reach the agent — making
  AgentFence a bidirectional data-flow control point rather than a one-way
  request gate.

### Broader out-of-the-box coverage

- **More policy packs** ([#102](https://github.com/dgenio/agentfence/issues/102)):
  curated `browser` and `database` packs with bundled fixtures, alongside the
  existing `filesystem`, `github`, and `shell` packs.

### Adoption and onboarding

- **MCP client config recipes** ([#103](https://github.com/dgenio/agentfence/issues/103)):
  copy-paste setup for Claude Code, Cursor, VS Code, and Claude Desktop. (Being
  addressed as part of the onboarding-docs work.)

## Beyond the roadmap label

Plenty of smaller improvements — CLI ergonomics, performance, more tests and
benchmarks, docs — live in the tracker without the `roadmap` label. Browse
[open issues](https://github.com/dgenio/agentfence/issues) and the
[`good first issue`](https://github.com/dgenio/agentfence/labels/good%20first%20issue)
label for entry points. New ideas are welcome as issues.
