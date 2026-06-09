# Changelog

All notable changes to AgentFence are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2026-06-09

### Added
- Confused-deputy / **taint tracking** for tool calls — propagates sensitivity
  labels through tool arguments and results to detect exfiltration and
  unauthorized data flows. See [`docs/threat-model.md`](docs/threat-model.md). (#81)
- **Policy packs** — built-in, versioned policy collections (filesystem, shell,
  GitHub) shipped under `internal/packs/data/` and selectable via `--pack`.
  Each pack includes bundled tests validating its rules. (#81)
- **HTTP proxy mode** (`agentfence proxy`) — intercepts MCP and SSE traffic for
  real-time policy enforcement and taint observation without code changes in
  the consumer. (#81)
- `httpproxy` observes SSE tool results for taint tracking, enabling
  end-to-end label propagation across streaming responses. (#83)
- GitHub Action workflow example (`examples/github-action-workflow.yml`) and
  CI gate running policy checks on every push/PR. (#81)
- `init` and `version` subcommands now validate arguments and print usage on
  invalid input. (#81)

### Fixed
- `proxy`: logger panic when handling malformed frames — replaced bare
  dereference with safe nil-check. (#81)
- `proxy`: strip hop-by-hop headers (`Connection`, `Keep-Alive`, `TE`, etc.)
  to prevent injection and conformance issues. (#81)
- `httpproxy`: fall back to bare type token when `Content-Type` parsing fails,
  avoiding hard errors on exotic or missing headers. (#83)
- `httpproxy`: drop truncated SSE frames on scanner error instead of emitting
  partial/corrupt events. (#83)
- Address taint bounds-check gaps and expand test coverage for proxy edge
  cases. (#81)

### Changed
- Documentation expanded to cover taint tracking, policy packs, HTTP proxy
  mode, and GitHub Action integration. (#81)

## [0.5.0] - 2026-06-04

### Added
- `audit export --format weaver-trace` emits audit decision records as a
  [weaver-spec](https://github.com/dgenio/weaver-spec) v0 (contract 0.6.0)
  aligned JSONL trace stream (a `PolicyDecision` and matching `TraceEvent` per
  event), so AgentFence findings can feed Weaver Stack consumers such as
  lessonweaver. The export is read-only over the native log, so the
  hash-chained audit remains verifiable. See [`docs/interop.md`](docs/interop.md). (#77)

## [Unreleased]

[Unreleased]: https://github.com/dgenio/agentfence/compare/v0.6.0...HEAD
