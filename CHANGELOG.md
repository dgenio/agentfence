# Changelog

All notable changes to AgentFence are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.0] - 2026-08-14

### Added
- **Strict MCP tool identity lock.** The new `identitylock` package introduces
  a versioned, canonicalized tool-identity descriptor that binds an MCP server
  upstream reference to an exact set of permitted tools. A lock can be
  serialized, verified against a descriptor, and used by the proxy to reject
  calls to tools that are not explicitly listed for a given upstream. This is
  the primitive for the "tool identity lock" deployment pattern documented in
  [`docs/threat-model.md`](docs/threat-model.md). (#221)
- **Deterministic exact JSON canonicalization.** The new `exactjson` package
  provides a stable, byte-for-byte canonical JSON representation that normalizes
  key order, whitespace, number formatting, and Unicode escapes. This is used
  by the identity lock and is available as a reusable primitive for any
  signature or comparison path that needs byte-exact JSON equality. (#246)

### Changed
- **Draft vulnerability research programme.** A new document
  ([`docs/draft-vulnerability-research-programme.md`](docs/draft-vulnerability-research-programme.md))
  outlines the scope, rules of engagement, and reporting process for external
  security research against AgentFence. (#252)

## [0.8.0] - 2026-08-12

### Added
- **Onboarding & adoption documentation and runnable examples.** A coherent set
  of docs and hermetic example scripts aimed at getting a new adopter from
  install to a gated agent, and at giving contributors (human and AI) clear
  guidance:
  - **Quickstart** ([`docs/quickstart.md`](docs/quickstart.md)) — a linear
    10-minute path from install to an observed allow + deny in the audit log.
    (#179)
  - **Daily Driver guide** ([`docs/daily-driver.md`](docs/daily-driver.md)) —
    the day-to-day operating loop, dry-run-first rollout, decision triage, CI
    defaults, and audit-log rotation. (#88)
  - **CLAIMS** ([`docs/claims.md`](docs/claims.md)) — each trust claim
    (local/no-telemetry, deny-by-default, redaction, tamper-evidence, …) with a
    runnable reproducer, plus explicit non-claims. (#90)
  - **Worked mode examples** in [`docs/modes.md`](docs/modes.md) — a runnable
    command, output, and audit `mode` field per enforcement mode. (#176)
  - **MCP client recipes** — Cursor and Claude Desktop config added to
    [`docs/integration-guide.md`](docs/integration-guide.md), each with a
    "confirm gating is working" step; the stale proxy flag table is corrected
    and completed. (#103)
  - **Runnable proxy examples** — [`examples/stub-mcp-server`](examples/stub-mcp-server)
    (a dependency-free stdio MCP stub), [`examples/proxy-smoke.sh`](examples/proxy-smoke.sh)
    (allowed read + denied write through the live proxy, #141), and
    [`examples/taint-scenario/`](examples/taint-scenario/) (the confused-deputy
    guard blocking a write derived from untrusted output, #153).
  - **Edge-proxy-vs-kernel** ([`docs/edge-proxy-vs-kernel.md`](docs/edge-proxy-vs-kernel.md), #85)
    and **Puppetmaster integration pattern**
    ([`docs/puppetmaster-integration.md`](docs/puppetmaster-integration.md), #92).
  - **`ROADMAP.md`** — a single, dated, directional roadmap tracking the
    `roadmap`-labeled issues; the README links to it instead of restating items.
    (#159)
  - **`AGENTS.md` + `CLAUDE.md`** — repo-specific rules for AI coding agents
    (the `make ci` gate, high-churn files, conventions), thin pointers to
    `CONTRIBUTING.md`/`Makefile`. (#185)
- **Structured decision observability.** A shared observability stack across the
  CLI and proxies:
  - **Typed reason codes.** Every decision now carries a stable, machine-readable
    `reason_code` (e.g. `path_denied`, `url_bare_ip`, `taint_escalated`,
    `approval_timeout`) alongside the human-readable reason, so summaries,
    metrics, and exporters can group decisions without matching prose. Audit
    `schema_version` is bumped to `"4"` and `audit summarize` reports a
    by-reason-code breakdown. (#136)
  - **Decision metrics.** `check --metrics` prints a dependency-free summary
    (counts by decision, tool, and reason code, plus taint escalations and
    approval outcomes) to stderr on exit. (#169)
  - **Prometheus metrics endpoint.** `proxy`/`proxy-http` expose the same
    counters — plus evaluation latency and operational error rates — as an
    opt-in, dependency-free Prometheus endpoint via `--metrics-listen <addr>`
    (off by default; local and operator-controlled). (#101)
  - **Structured operational logging.** `--log-format text|json` on `check`,
    `proxy`, and `proxy-http` routes stderr diagnostics through `log/slog`;
    `json` emits one structured record per line for log pipelines, while `text`
    (default) is unchanged. The operational log stays distinct from the audit
    log and the decision/JSON-RPC output. (#121, #163)

  See [`docs/observability.md`](docs/observability.md).
- **Machine-readable output completed across the CLI.** `policy test` and
  `audit verify` now accept `--output text|json`, matching the JSON convention
  already used by `check`, `explain`, and `audit summarize`. `policy test
  --output json` emits a per-case report (`{id, tool, expect, got, pass,
  reason}`) plus totals; `audit verify --output json` emits a combined
  `{chain, signatures?, anchor?}` object with a stable status enum. Both
  preserve their existing exit-code semantics. (#171, #160)
- `check`: **`--summary <file|->`** writes a compact JSON gate summary
  (per-decision counts, top denied tools/reasons, `--fail-on` match, and a
  `failed` flag) independent of `--output`, so CI can surface "what was denied"
  without a second `audit summarize` pass or bespoke `jq`. It is written before
  the `--fail-on` exit, so the artifact exists even when the gate fails. (#150)
- **Policy-engine contract hardening (tests + docs).** A doc-derived constraint
  conformance matrix pins every constraint family (`paths`, `args`, `urls`,
  `command`, `memory_write`) to `docs/policy-language.md` (#139); the import
  merge precedence (importer-wins scalars, OR-semantics enable flags) gains a
  worked table and tests (#142); the fail-closed invariants are documented in
  `docs/threat-model.md` with dedicated regression tests (#155); the path-safety
  guarantees and non-guarantees (lexical-only, no symlink resolution,
  case-sensitive matching) are documented and pinned (#170), with a
  cross-platform Windows-input test matrix (#175); and the YAML parser's
  empty / whitespace / tab / multi-document / duplicate-key behavior is
  specified and tested (#178).
- **Distribution, packaging & release hardening.** A coherent set of new ways to
  install and verify AgentFence:
  - **Shell completions and man page.** `agentfence completion <bash|zsh|fish>`
    and `agentfence man` generate their artifacts from the CLI itself; `make
    completions` / `make man` regenerate them and release archives bundle them
    under `completions/` and `manpages/`. (#107)
  - **Container image.** A from-source [`Dockerfile`](Dockerfile) (`make
    docker`) and a release [`Dockerfile.goreleaser`](Dockerfile.goreleaser) on a
    distroless static, non-root base; the release pipeline publishes a
    multi-arch (amd64/arm64) image to `ghcr.io/dgenio/agentfence`, and CI builds
    and smoke-tests the image on every push. (#149, #104)
  - **Install script and package managers.** A checksum-verifying
    [`scripts/install.sh`](scripts/install.sh) (`curl … | sh`, fails closed on
    mismatch), a Homebrew cask, and Scoop + winget manifests, all wired through
    GoReleaser. (#105, #120)
  - **Supply-chain provenance.** Release checksums are cosign-signed (keyless,
    GitHub OIDC) and each archive ships an SBOM; the published image manifest is
    cosign-signed. `agentfence version` now prints the stamped commit/build
    date. (#111)

  See [`docs/distribution.md`](docs/distribution.md). Some publish targets
  (Homebrew tap, Scoop bucket, winget fork) require maintainer-provisioned
  repositories/secrets, documented there.

### Changed
- Filesystem path-safety now also rejects Windows **drive-relative** paths
  (`C:foo`), not only the drive-absolute (`C:\…`) and bare-drive (`C:`) forms.
  On a non-Windows host such a path was previously treated as an ordinary
  relative name and allowed through. (#175, #170)

### Fixed
- **Preserve exact numeric tool-call arguments.** `check`, `proxy`, and
  `proxy-http` now preserve the exact textual representation of numeric
  arguments instead of rounding through `json.Number` → `float64`, preventing
  precision loss on large integers and scientific-notation values. (#238)
- **Never reuse late approval for a later call.** The interactive approver
  now rejects an approval that arrives after the next tool call has already
  started, closing a confused-deputy window where an approved response could
  have been applied to the wrong request. (#229)

## [0.7.0] - 2026-06-17

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
- **Durable audit writes.** `--audit-fsync` (on `check`, `proxy`, and
  `proxy-http`) forces each audit event through to stable storage before the
  call proceeds, and again on shutdown, so a decision the proxy already acted on
  survives a crash or power loss instead of lingering in the OS page cache.
  `audit.Writer` also gains a `Sync()` method used by the shutdown path. (#132)
- `proxy`/`proxy-http`: **graceful-shutdown audit flush.** On `SIGINT`/`SIGTERM`
  the relay stops and the audit destination is flushed (fsync under
  `--audit-fsync`) and closed before exit, so an in-flight decision is never
  lost to an attended `Ctrl-C` or an orchestrator's `SIGTERM`; the shutdown
  ordering is documented in `docs/threat-model.md`. (#158)
- Race-detector coverage for the stdio proxy's `lockedWriter` (JSON-RPC frame
  atomicity) and the audit `Writer` (gap-free sequence numbers under
  concurrency), protecting two security-relevant invariants. (#172)
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
- `proxy-http`: upstream and internal proxy failures are now surfaced as
  distinct JSON-RPC error envelopes (`-32002` upstream unavailable, `-32003`
  proxy error) addressed to the request id, instead of a generic HTTP 502, so
  the agent and operator can tell a transport failure apart from a policy
  block. (#133)
- `audit verify` now reports a damaged/unreadable log as `CORRUPT` and an
  internally inconsistent chain as `FAILED` (possible tampering) on separate
  status lines, so an operator does not mistake a truncated download or disk
  fault for an attack. The underlying `audit.VerifyError` carries a `Malformed`
  flag to distinguish the two. (#180)

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

[Unreleased]: https://github.com/dgenio/agentfence/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/dgenio/agentfence/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/dgenio/agentfence/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/dgenio/agentfence/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/dgenio/agentfence/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/dgenio/agentfence/compare/v0.4.0...v0.5.0
