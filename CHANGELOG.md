# Changelog

All notable changes to AgentFence are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `audit export --format weaver-trace` emits audit decision records as a
  [weaver-spec](https://github.com/dgenio/weaver-spec) v0 (contract 0.6.0)
  aligned JSONL trace stream (a `PolicyDecision` and matching `TraceEvent` per
  event), so AgentFence findings can feed Weaver Stack consumers such as
  lessonweaver. The export is read-only over the native log, so the
  hash-chained audit remains verifiable. See [`docs/interop.md`](docs/interop.md). (#77)

## [0.4.0] - 2026-05-29

### Added
- `audit summarize` command reporting totals, decision counts, schema versions,
  top tools (overall/denied/allowed), and top reasons, in text and JSON.
- Policy imports and durable memory-write constraints.
- Fuzz coverage for the policy parser, glob matcher, and redaction.

### Fixed
- Surface partial hash chains and refuse mixed-mode appends in audit logs.
- Refuse `--tamper-evident` on partial-chain logs; tightened path-safety docs.

## [0.3.0] - 2026-05-22

### Added
- MCP **stdio proxy** (`agentfence proxy`) that intercepts `tools/call` and
  enforces policy with the same redaction and audit behavior as `check`.
- JSON-RPC and `tools/call` envelope types for MCP.
- Interactive TTY approval for `ask` decisions, approval timeout with
  default-deny, and a `--dry-run` evaluation mode for `check`.

### Fixed
- Use `O_APPEND` for the proxy audit log so history is preserved across
  restarts.

## [0.2.0] - 2026-05-20

### Added
- Audit-log schema versioning.
- Tamper-evident hash chaining (SHA-256 links between entries).
- `audit verify` command to validate audit-log integrity.

## [0.1.0] - 2026-05-20

### Added
- Core policy engine: allow/deny/ask decisions over YAML policies, wildcard
  tool-name matching, tool groups, and argument/URL/domain/shell/path
  constraints with cross-platform normalization and traversal hardening.
- CLI commands: `check`, `validate`, `explain`, `test`, `demo`, and `version`.
- Structured output modes (`--output json|jsonl`) and CI gating
  (`--fail-on deny|ask`).
- Auditable decision records with automatic redaction of sensitive-looking
  values.
- GoReleaser config and a GitHub Actions release workflow.

[Unreleased]: https://github.com/dgenio/agentfence/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/dgenio/agentfence/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/dgenio/agentfence/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/dgenio/agentfence/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/dgenio/agentfence/releases/tag/v0.1.0
