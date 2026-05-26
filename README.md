# AgentFence

## A policy firewall for AI agents and MCP tools

AI coding agents are getting access to your filesystem, GitHub, browser, databases, and internal APIs. AgentFence gives you a local policy layer before tool calls happen.

AgentFence is local-first, vendor-neutral, MCP-friendly, and designed for safe defaults. It evaluates tool calls, supports allow/deny/ask decisions, redacts sensitive-looking values in logs, and writes auditable decision records.

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
| MCP streamable-HTTP proxy                           | Planned        | [`docs/architecture.md`](docs/architecture.md) |

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

Get machine-readable output for CI pipelines:

```bash
./agentfence check --policy examples/policy.yaml --call examples/tool-calls.jsonl --output json
./agentfence check --policy examples/policy.yaml --call examples/tool-calls.jsonl --output jsonl | jq '.decision'
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

Run AgentFence as an MCP stdio proxy in front of any MCP server:

```bash
./agentfence proxy \
  --policy examples/policy.yaml \
  --audit-log audit.jsonl \
  -- \
  npx -y @modelcontextprotocol/server-filesystem /path/to/workspace
```

See [`docs/integration-guide.md`](docs/integration-guide.md) for Claude Code
and VS Code configuration, audit-log inspection, and troubleshooting.

## Demo output

Running the built-in demo against the bundled example tool calls produces the
output below. The first line of each pair is the human-readable decision; the
second line is the JSONL audit event with secret-looking values redacted.

```text
$ ./agentfence demo
AgentFence demo:
call_001 filesystem.read -> allow (tool filesystem.read matched explicit policy rule)
{"timestamp":"<rfc3339>","call_id":"call_001","tool":"filesystem.read","decision":"allow","reason":"tool filesystem.read matched explicit policy rule","arguments":{"path":"README.md"}}
call_002 filesystem.write -> deny (path ".env" denied by pattern ".env")
{"timestamp":"<rfc3339>","call_id":"call_002","tool":"filesystem.write","decision":"deny","reason":"path \".env\" denied by pattern \".env\"","arguments":{"content":"OPENAI_[REDACTED:generic_secret_assignment]","path":".env"}}
call_003 github.create_issue -> ask (tool github.create_issue matched explicit policy rule)
{"timestamp":"<rfc3339>","call_id":"call_003","tool":"github.create_issue","decision":"ask","reason":"tool github.create_issue matched explicit policy rule","arguments":{"body":"Created by an agent","repo":"dgenio/agentfence","title":"Demo issue"}}
call_004 github.delete_repo -> deny (tool github.delete_repo matched explicit policy rule)
{"timestamp":"<rfc3339>","call_id":"call_004","tool":"github.delete_repo","decision":"deny","reason":"tool github.delete_repo matched explicit policy rule","arguments":{"repo":"dgenio/agentfence"}}
```

`./agentfence check` against the example policy and tool calls produces the
same decisions plus a one-line summary:

```text
$ ./agentfence check --policy examples/policy.yaml --call examples/tool-calls.jsonl
call_001 filesystem.read -> allow (tool filesystem.read matched explicit policy rule)
{"timestamp":"<rfc3339>","call_id":"call_001","tool":"filesystem.read","decision":"allow","reason":"tool filesystem.read matched explicit policy rule","arguments":{"path":"README.md"}}
call_002 filesystem.write -> deny (path ".env" denied by pattern ".env")
{"timestamp":"<rfc3339>","call_id":"call_002","tool":"filesystem.write","decision":"deny","reason":"path \".env\" denied by pattern \".env\"","arguments":{"content":"OPENAI_[REDACTED:generic_secret_assignment]","path":".env"}}
call_003 github.create_issue -> ask (tool github.create_issue matched explicit policy rule)
{"timestamp":"<rfc3339>","call_id":"call_003","tool":"github.create_issue","decision":"ask","reason":"tool github.create_issue matched explicit policy rule","arguments":{"body":"Created by an agent","repo":"dgenio/agentfence","title":"Demo issue"}}
call_004 github.delete_repo -> deny (tool github.delete_repo matched explicit policy rule)
{"timestamp":"<rfc3339>","call_id":"call_004","tool":"github.delete_repo","decision":"deny","reason":"tool github.delete_repo matched explicit policy rule","arguments":{"repo":"dgenio/agentfence"}}

4 call(s) processed, 0 parse error(s): allow=1 deny=2 ask=1
```

Timestamps are real `time.RFC3339Nano` values at runtime; they are shown as
`<rfc3339>` here so this section does not need to be updated on every build.

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

## Relationship to agent-kernel

AgentFence is the **external gate** in a layered approach to agent safety:

- **AgentFence** (this project): a standalone CLI and (planned) MCP proxy
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

- MCP stdio proxy mode
- MCP streamable HTTP proxy mode
- signed audit logs
- GitHub Action mode for CI policy checks
- reusable policy packs for filesystem, GitHub, browser, database, and shell tools
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

## License

Apache-2.0. See [`LICENSE`](LICENSE).
