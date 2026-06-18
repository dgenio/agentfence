# AgentFence

[![CI](https://github.com/dgenio/agentfence/actions/workflows/ci.yml/badge.svg)](https://github.com/dgenio/agentfence/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/dgenio/agentfence?sort=semver)](https://github.com/dgenio/agentfence/releases)
[![Go version](https://img.shields.io/github/go-mod/go-version/dgenio/agentfence)](go.mod)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## An open, local MCP policy firewall you fully control — no cloud, no telemetry, auditable by design

AI coding agents are getting access to your filesystem, GitHub, browser, databases, and internal APIs. AgentFence is the policy gate that sits in front of those tool calls and decides what is **allowed, denied, or sent for approval** — before anything executes.

Unlike the wave of hosted agent-security gateways, AgentFence gives you a trust moat the funded players can't match:

- **Open and local-first** — a single Go binary you run yourself. No SaaS, no account, nothing leaves your machine.
- **Vendor-neutral** — an MCP stdio proxy in front of *any* MCP server, and a CLI gate for any tool-call pipeline.
- **No telemetry** — it never phones home.
- **Deny-by-default** — safe defaults; you opt calls in, not out.
- **Tamper-evident audit you own** — hash-chained decision logs you can verify offline.

**Who it's for:** security and platform operators who need to gate agents they didn't write, with a policy they fully control and an audit trail they own.

## Current status

AgentFence is in active development. The table below distinguishes what works
today from what is planned. Do not assume planned features are usable yet.

| Capability                                          | Status         | Where to read more |
|-----------------------------------------------------|----------------|--------------------|
| JSONL batch policy evaluation (`check`)             | Implemented    | [Quickstart](#quickstart) |
| Allow / deny / ask decisions                        | Implemented    | [`docs/policy-language.md`](docs/policy-language.md) |
| Path, argument, URL, and shell-command constraints  | Implemented    | [`docs/policy-language.md`](docs/policy-language.md) |
| Tool groups and wildcard matching                   | Implemented    | [`docs/policy-language.md`](docs/policy-language.md) |
| Strict policy validation (`validate`)               | Implemented    | [Quickstart](#quickstart) |
| Single-call trace (`explain`)                       | Implemented    | `agentfence explain --help` |
| Policy fixture tests (`policy test`)                | Implemented    | [`examples/policy-tests.yaml`](examples/policy-tests.yaml) |
| Regex-based redaction of audit values               | Implemented    | [`docs/policy-language.md`](docs/policy-language.md) |
| Structured output modes (text / json / jsonl)       | Implemented    | `agentfence check --help` |
| CI gating via `--fail-on`                           | Implemented    | `agentfence check --help` |
| Pre-built release binaries                          | Implemented    | [Pre-built binaries](#pre-built-binaries) |
| Detection / prevention / audit-only / dry-run modes | Documented     | [`docs/modes.md`](docs/modes.md) |
| Interactive TTY approval for `ask` decisions        | Implemented    | [Approval and dry-run](#approval-and-dry-run-modes) |
| Approval timeout with default-deny                  | Implemented    | [Approval and dry-run](#approval-and-dry-run-modes) |
| Dry-run evaluation mode                             | Implemented    | [Approval and dry-run](#approval-and-dry-run-modes) |
| MCP stdio proxy (`agentfence proxy`)                | Implemented    | [`docs/integration-guide.md`](docs/integration-guide.md), [`docs/architecture.md`](docs/architecture.md) |
| Policy enforcement on intercepted `tools/call`      | Implemented    | [`docs/integration-guide.md`](docs/integration-guide.md) |
| Tamper-evident hash-chained audit logs              | Implemented    | [`docs/threat-model.md`](docs/threat-model.md#audit-log-integrity) |
| Ed25519-signed audit events (`--sign-key`)          | Implemented    | [`docs/audit-event-schema.md`](docs/audit-event-schema.md), [`docs/threat-model.md`](docs/threat-model.md#audit-log-integrity) |
| Audit anchors (`audit anchor` / `verify --anchor`)  | Implemented    | [`docs/threat-model.md`](docs/threat-model.md#audit-log-integrity) |
| Audit-log rotation and retention (`--audit-max-*`)  | Implemented    | [`docs/threat-model.md`](docs/threat-model.md#audit-log-integrity) |
| Durable audit writes (`--audit-fsync`)              | Implemented    | [`docs/threat-model.md`](docs/threat-model.md#audit-log-integrity) |
| External audit sinks (`--audit-sink` syslog/HTTP)   | Implemented    | [`docs/threat-model.md`](docs/threat-model.md#audit-log-integrity) |
| Audit event JSON Schema                             | Implemented    | [`docs/audit-event-schema.md`](docs/audit-event-schema.md) |
| Audit-log summarisation (`audit summarize`)         | Implemented    | `agentfence audit summarize --help` |
| weaver-spec trace export (`audit export`)           | Implemented    | [`docs/interop.md`](docs/interop.md) |
| Fuzz coverage for parser, glob, and redaction       | Implemented    | `make fuzz` |
| MCP streamable-HTTP proxy (`agentfence proxy-http`) | Implemented    | [`docs/architecture.md`](docs/architecture.md), [`docs/integration-guide.md`](docs/integration-guide.md) |
| Confused-deputy / taint escalation                  | Implemented    | [`docs/threat-model.md`](docs/threat-model.md#confused-deputy--taint-tracking), [`docs/policy-language.md`](docs/policy-language.md) |
| Reusable policy packs (`init --pack`)               | Implemented    | [`docs/policy-language.md`](docs/policy-language.md#policy-packs) |
| GitHub Action for CI policy checks                  | Implemented    | [`docs/integration-guide.md`](docs/integration-guide.md#github-action) |

## Why this exists

Tool-capable agents are useful, but they can also be risky:

- Prompt injection can trigger unsafe calls.
- Agents may take destructive actions too quickly.
- Sensitive values can leak into logs.
- Teams need an audit trail of what was allowed, denied, or sent for approval.

AgentFence is a practical local control point before execution.

## Install

### Pre-built binaries

Pre-built binaries for Linux, macOS, and Windows (amd64 and arm64) are
published on the [GitHub Releases](https://github.com/dgenio/agentfence/releases)
page for each tagged release. Each release includes a `checksums.txt` for
verification. Download the archive matching your platform, extract it, and put
the `agentfence` binary on your `PATH`.

### Build from source

```bash
go build -o agentfence ./cmd/agentfence
```

To embed a release version at build time (compatible with goreleaser):

```bash
go build -ldflags "-X main.Version=0.1.0" -o agentfence ./cmd/agentfence
```

Or via the project Makefile:

```bash
make build VERSION=0.1.0
```

## Quickstart

Run the built-in demo:

```bash
./agentfence demo
```

Run policy checks against example tool calls:

```bash
./agentfence check --policy examples/policy.yaml --call examples/tool-calls.jsonl
```

Write audit events to an append-only, owner-readable log:

```bash
./agentfence check --policy examples/policy.yaml --call examples/tool-calls.jsonl --audit-log audit.jsonl
```

Sign each event (writer authentication), rotate the log, and ship a copy to an
external sink — then verify the chain *and* the signatures offline:

```bash
./agentfence audit keygen --private audit.key --public audit.pub
./agentfence check --policy examples/policy.yaml --call examples/tool-calls.jsonl \
  --audit-log audit.jsonl --tamper-evident --sign-key audit.key \
  --audit-max-size 10485760 --audit-keep 5 --audit-sink syslog://127.0.0.1:514
./agentfence audit verify --log audit.jsonl --pubkey audit.pub
```

Publish an anchor so a third party can later detect silent deletion or
truncation, then check the log against it:

```bash
./agentfence audit anchor --log audit.jsonl --out audit.anchor.json   # commit this somewhere you don't control
./agentfence audit verify --log audit.jsonl --anchor audit.anchor.json
```

Sign the anchor so a verifier can confirm it was not itself swapped for one
naming an earlier event:

```bash
./agentfence audit anchor --log audit.jsonl --out audit.anchor.json --sign-key audit.key
./agentfence audit verify --log audit.jsonl --anchor audit.anchor.json --anchor-pubkey audit.pub
```

Get machine-readable output for CI pipelines:

```bash
./agentfence check --policy examples/policy.yaml --call examples/tool-calls.jsonl --output json
./agentfence check --policy examples/policy.yaml --call examples/tool-calls.jsonl --output jsonl | jq '.decision'
```

`check --summary <file>` writes a compact JSON gate summary (per-decision
counts, top denied tools/reasons, and whether `--fail-on` matched) alongside the
decision stream, so CI can surface "what was denied" without recomputing it with
`jq`. Use `--summary -` to send it to stderr instead of a file, keeping
`--output` stdout clean:

```bash
./agentfence check --policy examples/policy.yaml --call examples/tool-calls.jsonl \
  --no-interactive --fail-on deny --output json --summary gate-summary.json
```

`policy test` and `audit verify` share the same `--output text|json` convention
as `check`, `explain`, and `audit summarize`, so every gate the pipeline runs
can be consumed structurally while preserving each command's exit code:

```bash
./agentfence policy test --policy examples/policy.yaml --tests examples/policy-tests.yaml --output json
./agentfence audit verify --log audit.jsonl --output json
```

Validate a policy file before use (catches typos and unknown fields):

```bash
./agentfence validate --policy examples/policy.yaml
```

## Approval and dry-run modes

`check` exposes three operator controls for the `ask` decision and for
"evaluate without enforcing" workflows:

- `--no-interactive` — never prompt; auto-deny any `ask` decision. The audit
  reason is `non-interactive: ask auto-denied`. Use this in CI.
- `--approval-timeout <duration>` — bound the wait for a y/N response (e.g.
  `30s`, `2m`). On expiry the call is denied with reason `approval timeout`.
  `0` (the default) waits forever.
- `--dry-run` — evaluate policy and write audit records but never invoke the
  approver and never propagate a non-zero exit from `--fail-on`. Each audit
  record carries `"mode": "dry_run"` so downstream readers can distinguish
  simulated decisions from enforced ones. Text output is suffixed with
  `[dry-run]`.

Typical CI invocation:

```bash
./agentfence check \
  --policy policy.yaml --call calls.jsonl \
  --no-interactive --approval-timeout 30s --fail-on deny,ask
```

Run the same input through `--dry-run` first to see what would happen without
failing the pipeline.

Initialize a starter policy in your current directory:

```bash
./agentfence init
```

Check the installed version:

```bash
./agentfence version
```

List commands and flags:

```bash
./agentfence --help
```

Run AgentFence as an MCP stdio proxy in front of any MCP server:

```bash
./agentfence proxy \
  --policy examples/policy.yaml \
  --audit-log audit.jsonl \
  -- \
  npx -y @modelcontextprotocol/server-filesystem /path/to/workspace
```

Or gate a remote MCP server reached over streamable HTTP / SSE:

```bash
./agentfence proxy-http \
  --policy examples/policy.yaml \
  --upstream https://mcp.example.com/mcp \
  --listen 127.0.0.1:8787 \
  --audit-log audit.jsonl
```

Point your MCP client at `http://127.0.0.1:8787`; AgentFence evaluates each
`tools/call` with the same decision, redaction, approval, and audit semantics
as the stdio proxy, and relays everything else (including SSE streams)
transparently. See [`docs/integration-guide.md`](docs/integration-guide.md)
for Claude Code and VS Code configuration, audit-log inspection, and
troubleshooting.

Scaffold a policy from curated **policy packs** instead of starting from a
blank file:

```bash
./agentfence init --pack filesystem,github,shell
```

This writes one pack file per surface plus an `agentfence.yaml` that imports
them; redeclare any tool key in `agentfence.yaml` to override a pack rule.

Summarise an existing audit log to see which tools are most active and which
rules dominate the deny pile:

```bash
./agentfence audit summarize --log audit.jsonl
./agentfence audit summarize --log audit.jsonl --output json --top 20
```

The text output reports totals, decision counts, schema versions, top tools
(overall, denied, allowed), and top reasons. The JSON output has the same
fields under stable snake_case keys for automation. Malformed JSONL lines are
counted as `malformed` and never abort the run.

## Demo output

Running the built-in demo against the bundled example tool calls produces the
output below. The first line of each pair is the human-readable decision; the
second line is the JSONL audit event with secret-looking values redacted.

```text
$ ./agentfence demo
AgentFence demo:
call_001 filesystem.read -> allow (tool filesystem.read matched explicit policy rule)
{"schema_version":"2","session_id":"<session_id>","seq":1,"timestamp":"<rfc3339>","call_id":"call_001","tool":"filesystem.read","decision":"allow","reason":"tool filesystem.read matched explicit policy rule","arguments":{"path":"README.md"}}
call_002 filesystem.write -> deny (path ".env" denied by pattern ".env")
{"schema_version":"2","session_id":"<session_id>","seq":2,"timestamp":"<rfc3339>","call_id":"call_002","tool":"filesystem.write","decision":"deny","reason":"path \".env\" denied by pattern \".env\"","arguments":{"content":"OPENAI_[REDACTED:generic_secret_assignment]","path":".env"}}
call_003 github.create_issue -> ask (tool github.create_issue matched explicit policy rule)
{"schema_version":"2","session_id":"<session_id>","seq":3,"timestamp":"<rfc3339>","call_id":"call_003","tool":"github.create_issue","decision":"ask","reason":"tool github.create_issue matched explicit policy rule","arguments":{"body":"Created by an agent","repo":"dgenio/agentfence","title":"Demo issue"}}
call_004 github.delete_repo -> deny (tool github.delete_repo matched explicit policy rule)
{"schema_version":"2","session_id":"<session_id>","seq":4,"timestamp":"<rfc3339>","call_id":"call_004","tool":"github.delete_repo","decision":"deny","reason":"tool github.delete_repo matched explicit policy rule","arguments":{"repo":"dgenio/agentfence"}}
```

`./agentfence check` against the example policy and tool calls produces the
same decisions plus a one-line summary:

```text
$ ./agentfence check --policy examples/policy.yaml --call examples/tool-calls.jsonl
call_001 filesystem.read -> allow (tool filesystem.read matched explicit policy rule)
{"schema_version":"2","session_id":"<session_id>","seq":1,"timestamp":"<rfc3339>","call_id":"call_001","tool":"filesystem.read","decision":"allow","reason":"tool filesystem.read matched explicit policy rule","arguments":{"path":"README.md"}}
call_002 filesystem.write -> deny (path ".env" denied by pattern ".env")
{"schema_version":"2","session_id":"<session_id>","seq":2,"timestamp":"<rfc3339>","call_id":"call_002","tool":"filesystem.write","decision":"deny","reason":"path \".env\" denied by pattern \".env\"","arguments":{"content":"OPENAI_[REDACTED:generic_secret_assignment]","path":".env"}}
call_003 github.create_issue -> ask (tool github.create_issue matched explicit policy rule)
{"schema_version":"2","session_id":"<session_id>","seq":3,"timestamp":"<rfc3339>","call_id":"call_003","tool":"github.create_issue","decision":"ask","reason":"tool github.create_issue matched explicit policy rule","arguments":{"body":"Created by an agent","repo":"dgenio/agentfence","title":"Demo issue"}}
call_004 github.delete_repo -> deny (tool github.delete_repo matched explicit policy rule)
{"schema_version":"2","session_id":"<session_id>","seq":4,"timestamp":"<rfc3339>","call_id":"call_004","tool":"github.delete_repo","decision":"deny","reason":"tool github.delete_repo matched explicit policy rule","arguments":{"repo":"dgenio/agentfence"}}

4 call(s) processed, 0 parse error(s): allow=1 deny=2 ask=1
```

Timestamps are real `time.RFC3339Nano` values at runtime, and session IDs are
UUIDs generated per run. They are shown as placeholders here so this section
does not need to be updated on every build.

## Example policy

```yaml
version: "0.1"
defaults:
  decision: deny
tools:
  filesystem.read:
    decision: allow
  filesystem.write:
    decision: ask
  github.create_issue:
    decision: ask
  github.delete_repo:
    decision: deny
```

See [`examples/policy.yaml`](examples/policy.yaml) for the full policy including constraints and redaction patterns.

## Threat model summary

AgentFence is built to reduce practical risks from agent tool calls:

- prompt injection
- confused deputy behavior
- accidental destructive actions
- secret leakage through logs
- excessive default permissions

See [`docs/threat-model.md`](docs/threat-model.md) for the full threat model
(including the MCP proxy threat surface, confused-deputy-via-MCP-proxy, and
audit-log integrity), [`docs/architecture.md`](docs/architecture.md) for the
evaluation flow, and [`docs/modes.md`](docs/modes.md) for the
detection/prevention/audit-only/dry-run mode taxonomy.

AgentFence is not a sandbox. It enforces policy *before* a tool call executes;
it does not contain a tool call that has already been forwarded. Pair it with
OS-level isolation for defense in depth.

## Part of the Weaver Stack

AgentFence is the **external policy edge** of the Weaver Stack — a set of
small, composable tools for building and operating safer AI agents. Each works
standalone; together they cover an agent's lifecycle:

```text
   author & test          build & run            operate the edge          learn
  ┌──────────────┐     ┌──────────────────┐    ┌────────────────────┐   ┌──────────────┐
  │  vibeguard   │     │   agent-kernel   │    │     AgentFence     │   │ lessonweaver │
  │  (dev-time)  │     │ (in-process      │    │  (external policy  │   │  (learning   │
  │              │     │  firewall)       │    │   edge)            │   │   loop)      │
  └──────────────┘     └──────────────────┘    └────────────────────┘   └──────────────┘

        agent ──tool calls──▶  AgentFence  ──allow / deny / ask──▶  MCP servers / tools
                               (+ tamper-evident audit) ──deny/ask traces──▶ lessonweaver
```

- **AgentFence** (this repo) — the external gate: an operator-controlled policy
  boundary in front of any MCP server or tool-call pipeline.
- **agent-kernel** — the in-process firewall compiled into an agent application.
- **vibeguard** — dev-time guardrails for agent code.
- **lessonweaver** — turns recurring deny/ask traces into reviewed policy lessons.

All of these are optional. **AgentFence works standalone with any agent and has
no hard dependency on any sibling.**

## Relationship to agent-kernel

AgentFence is the **external gate** in a layered approach to agent safety:

- **AgentFence** (this project): a standalone CLI and MCP stdio proxy
  that sits *outside* the agent process. It is configured by an operator and
  decides allow / deny / ask for each tool call before it reaches the tool
  server. Use AgentFence when you want a policy layer that does not require
  modifying the agent or the application embedding it.
- **agent-kernel**: an embeddable runtime/library layer for applications that
  build their own agent on top. It runs *inside* the agent process and is
  configured by the application author.

The two are complementary. An application can embed `agent-kernel` for
in-process safety and also run behind `agentfence` for an operator-controlled
policy boundary. If you only need one, pick AgentFence when the policy author
is not the application author, and pick `agent-kernel` when you are building
an agent application and want safety guarantees compiled in.

## Roadmap

- signed audit logs
- additional policy packs (browser, database)
- VS Code / Claude Code / Copilot CLI integration examples

## Non-goals

- Executing real tool calls
- Claiming full MCP proxy compatibility before it ships
- Replacing runtime sandboxing or OS-level isolation

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for local-development setup, test
conventions, and PR guidelines. The short version:

```bash
make ci
```

before opening a pull request. CI runs the same command.

By participating you agree to abide by our
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Release history is tracked in
[`CHANGELOG.md`](CHANGELOG.md).

## Security

To report a vulnerability, please follow the coordinated-disclosure process in
[`SECURITY.md`](SECURITY.md) — do not open a public issue for security reports.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
