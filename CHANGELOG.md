# Changelog

All notable changes to AgentFence are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `proxy-http`: **fail-closed request handling.** JSON-RPC batch (array) bodies
  are now refused by default (`--on-batch reject`) so a denied `tools/call`
  cannot be smuggled inside an array; `--on-batch evaluate` gates every member
  and forwards the batch only if all are allowed. (#128, #145)
- `proxy-http`: `--on-unparsed forward|reject` controls bodies that are not
  valid JSON-RPC, and oversize bodies are refused rather than forwarded
  uninspected. (#152)
- `proxy-http`: optional client authentication via `--auth-token` (or
  `$AGENTFENCE_PROXY_AUTH_TOKEN`); a startup warning fires when `--listen`
  binds a non-loopback address without a token. (#138)
- `docs/batch-handling.md`: cross-transport design note for JSON-RPC batch
  handling. (#145)

### Changed
- `proxy-http`: upstream and internal proxy failures are now surfaced as
  distinct JSON-RPC error envelopes (`-32002` upstream unavailable, `-32003`
  proxy error) addressed to the request id, instead of a generic HTTP 502, so
  the agent and operator can tell a transport failure apart from a policy
  block. (#133)

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

### Added
- **Ed25519-signed audit events** — `--sign-key <pem>` on `check`, `proxy`, and
  `proxy-http` adds a base64 signature over each event's canonical digest;
  `agentfence audit keygen` generates a key pair and `agentfence audit verify
  --pubkey` checks signatures offline. Signing authenticates the writer, which
  hash chaining alone cannot. (#95)
- **Audit anchors** — `agentfence audit anchor` emits a compact, publishable
  commitment to a tamper-evident log's final event; `agentfence audit verify
  --anchor` detects silent whole-log deletion or truncation against it.
  `audit anchor --sign-key` signs the anchor and `audit verify --anchor-pubkey`
  authenticates it, so a published anchor cannot be swapped for one naming an
  earlier event. (#99)
- **Audit-log rotation and retention** — `--audit-max-size`, `--audit-max-age`,
  and `--audit-keep` rotate a long-running log into segments, each of which
  starts a fresh chain root and stays independently verifiable. (#117)
- **External audit sinks** — `--audit-sink` streams events to an
  operator-controlled destination (`syslog://`, `syslog+tcp://`, or
  `http(s)://` webhook) with best-effort, non-blocking, bounded buffering. (#118)
- **Audit event JSON Schema** — `schema/agentfence-audit-event.schema.json` plus
  a reference page (`docs/audit-event-schema.md`) and a drift-guard test keeping
  the schema in sync with the Go struct. (#124)
- **Interactive approval in the proxies** — `agentfence proxy` and `proxy-http`
  now resolve `ask` decisions through the interactive `TTYApprover` instead of a
  hardwired deny-all. `--no-interactive` keeps the fail-closed `DenyAllApprover`,
  and the new `--approval-timeout <duration>` bounds an attended prompt before it
  auto-denies. Interactive proxy approval requires a real `/dev/tty` and never
  falls back to stdin (which carries the stdio proxy's JSON-RPC channel); with no
  terminal the proxy exits with guidance to use `--no-interactive`. (#126)

### Changed
- Audit event `schema_version` bumped to `"3"` for the optional `signature`
  field.
- `docs/threat-model.md` audit-integrity section updated to document signing,
  anchors, rotation, and sinks as implemented mitigations.
- **Unified approver contract** — `proxy.Approver`/`proxy.DenyAllApprover` and
  the `httpproxy` equivalents are now type aliases for the single
  `approval.Approver`/`approval.DenyAllApprover`, so one approver implementation
  wires into both proxies and `check`. (#137)
- The proxies now audit the **resolved** `ask` decision (`allow`/`deny`) with the
  approval outcome appended to the engine's reason (e.g. a taint escalation),
  rather than auditing the unresolved `ask`. The agent-facing blocked-call
  message uses the canonical approval reason (`denied interactively`, `approval
  timeout`, `approval I/O error`) and no longer leaks internal approver error
  text. (#126)
- Corrected `docs/integration-guide.md` and `docs/architecture.md`, which still
  described `proxy-http` and the interactive approver as unimplemented/roadmap
  and referenced closed issues #29/#30. (#127)

[Unreleased]: https://github.com/dgenio/agentfence/compare/v0.6.0...HEAD
