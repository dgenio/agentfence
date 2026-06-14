# Integration guide: running AgentFence around an MCP server

This guide shows how to put AgentFence in front of a Model Context Protocol
(MCP) server so every `tools/call` request the agent makes is evaluated
against your policy before the server sees it.

If you only want to evaluate JSONL traces (no proxy, no live agent), use
`agentfence check` — see the project [README](../README.md). This guide is
specifically about the live MCP proxy (`agentfence proxy`).

## How AgentFence wraps an MCP server

```
┌────────┐   JSON-RPC over stdio   ┌──────────────┐   JSON-RPC   ┌────────────┐
│  Agent │ ──────────────────────► │  AgentFence  │ ───────────► │ MCP server │
│ (host) │ ◄────────────────────── │    proxy     │ ◄─────────── │ (your bin) │
└────────┘                         └──────────────┘              └────────────┘
                                          │
                                          ▼
                                   ┌──────────────┐
                                   │  audit log   │
                                   │   (JSONL)    │
                                   └──────────────┘
```

The proxy is a long-running process that:

1. Spawns your MCP server as a subprocess.
2. Connects the agent's stdin to the server via the proxy.
3. Parses every newline-delimited JSON-RPC message.
4. For `tools/call`: evaluates against the policy and either forwards the
   request (`allow`), responds with a `BlockedByPolicy` JSON-RPC error
   (`deny`), or calls the configured approver (`ask`).
5. Writes one audit event per evaluated call to the JSONL audit log.
6. Forwards everything else (initialize, ping, notifications, server
   responses) untouched.

## Prerequisites

- The `agentfence` binary on your `PATH` (`make build` or download from
  [Releases](https://github.com/dgenio/agentfence/releases)).
- An MCP server binary or runtime command. The proxy spawns this — it does
  not care what language or framework the server uses.
- A policy YAML file (see [`docs/policy-language.md`](policy-language.md) and
  [`examples/policy.yaml`](../examples/policy.yaml)).

## Wrapping an MCP server

The general invocation is:

```bash
agentfence proxy \
  --policy /path/to/policy.yaml \
  --audit-log /path/to/audit.jsonl \
  -- \
  /path/to/mcp-server arg1 arg2
```

Everything after `--` is the command (and arguments) AgentFence will spawn.
You can pass any executable that speaks MCP over stdio — `node`, `python`,
a compiled binary, `docker run -i ...`, etc.

Useful flags:

| Flag                  | What it does |
|-----------------------|--------------|
| `--policy <file>`     | Required unless `--passthrough`. Policy YAML to load. |
| `--audit-log <file>`  | Append JSONL audit events to this file. New files are created owner-readable on Unix (`0600`). If omitted, audit events are discarded (the proxy never mixes audit JSONL into the agent's stdout — that channel is reserved for JSON-RPC). |
| `--tamper-evident`    | Hash-chain audit events. Verify later with `agentfence audit verify --log <file>`. |
| `--passthrough`       | Skeleton mode: forward every message without policy evaluation. Useful for validating the relay; do **not** use in production. |
| `--no-interactive`    | Reserved. Today every `ask` decision is denied (see [Approval today](#approval-today)). |
| `--debug`             | Log every forwarded JSON-RPC message to stderr. Off by default because MCP messages routinely contain user content. |

## Wrapping a remote MCP server over HTTP

For MCP servers reached over streamable HTTP / SSE (remote or hosted tools),
use `proxy-http` instead. It listens locally and reverse-proxies to the
upstream, gating `tools/call` with the same policy, redaction, approval, and
audit behavior as the stdio proxy:

```bash
agentfence proxy-http \
  --policy /path/to/policy.yaml \
  --upstream https://mcp.example.com/mcp \
  --listen 127.0.0.1:8787 \
  --audit-log /path/to/audit.jsonl
```

Then point your MCP client at `http://127.0.0.1:8787`. Requests that are not
a single `tools/call` (initialize, ping, notifications, the SSE GET channel)
are forwarded transparently, and streamed `text/event-stream` responses are
relayed incrementally.

Useful flags mirror `proxy`, plus:

| Flag                      | What it does |
|---------------------------|--------------|
| `--upstream <url>`        | Required. Absolute base URL of the MCP server to forward to. |
| `--listen <addr>`         | Local address to bind (default `127.0.0.1:8787`). Keep it on loopback. |
| `--on-batch reject\|evaluate` | JSON-RPC batch (array) body handling. `reject` (default) refuses batches fail-closed; `evaluate` gates every member and forwards only if all are allowed. |
| `--on-unparsed forward\|reject` | Handling for POST bodies that are not valid JSON-RPC. `forward` (default) preserves non-JSON-RPC traffic; `reject` refuses them. |
| `--auth-token <token>`    | Require `Authorization: Bearer <token>` on every request (also read from `$AGENTFENCE_PROXY_AUTH_TOKEN`). Empty disables auth. |

Operational caveats specific to the HTTP transport — TLS being the operator's
responsibility, optional bearer-token authentication, one shared session per
running proxy, and how batch/oversize/unparseable bodies are handled
fail-closed — are documented in
[`threat-model.md`](threat-model.md#streamable-http-proxy-surface) and
[`batch-handling.md`](batch-handling.md).

<a id="github-action"></a>
## GitHub Action

Gate recorded tool calls in CI with the bundled composite action. It builds
`agentfence`, runs `agentfence check`, fails the job per `fail-on`, and writes
a decision table to the job summary.

```yaml
- name: AgentFence policy check
  uses: dgenio/agentfence@v0.5.0
  with:
    policy: examples/policy.yaml
    calls: examples/tool-calls.jsonl
    fail-on: deny           # deny | ask | deny,ask
```

Inputs: `policy` (required), `calls` (required), `fail-on` (default `deny`),
`audit-log`, `tamper-evident`, `approval-timeout`, `go-version`. Outputs:
`total`, `allow`, `deny`, `ask`, `decisions-file`. Because CI runs
non-interactively, `ask` decisions are auto-denied and counted under `deny`.
A copy-paste workflow is in
[`examples/github-action-workflow.yml`](../examples/github-action-workflow.yml).

## Approval

Both `proxy` and `proxy-http` resolve `ask` decisions interactively by default.
When AgentFence is attached to a terminal, an `ask` rule prompts the operator on
the TTY (`approve <tool> [<id>]? (y/N)`); answering `y`/`yes` forwards the call,
and anything else — an explicit `n`, a closed input, or an expired
`--approval-timeout` — denies it and returns a `BlockedByPolicy` response. The
prompt is read from `/dev/tty`, never from stdin, so it cannot collide with the
stdio proxy's JSON-RPC channel. If no controlling terminal is available (for
example in CI or a detached service), the proxy refuses to start rather than
falling back to stdin — re-run with `--no-interactive` for unattended use.

For unattended contexts (CI, a service with no terminal):

- `--no-interactive` auto-denies every `ask` (recorded with the
  `non-interactive: ask auto-denied` reason) instead of prompting.
- `--approval-timeout <duration>` (e.g. `30s`) bounds how long an attended
  prompt waits before falling back to deny with the `approval timeout` reason.

The audit event records the *resolved* decision (`allow`/`deny`) together with
the engine's reason for the original `ask` — for example a taint escalation —
so the trail captures both the cause and how it was resolved.

## Claude Code (CLI / Desktop)

Claude Code launches MCP servers via the `mcpServers` map in its settings
file. Wrap the server's `command` with `agentfence proxy`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "agentfence",
      "args": [
        "proxy",
        "--policy", "/Users/you/.config/agentfence/policy.yaml",
        "--audit-log", "/Users/you/.local/share/agentfence/audit.jsonl",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/Users/you/work"
      ]
    }
  }
}
```

Settings file locations:

- macOS / Linux desktop: `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `~/.config/Claude/claude_desktop_config.json` (Linux).
- Claude Code CLI: `~/.claude/settings.json`.

After saving, restart Claude. From the agent's perspective the server still
looks like one MCP server on stdio; AgentFence is invisible until a
decision is enforced.

## VS Code (Copilot MCP / GitHub Copilot Chat)

VS Code's MCP configuration lives in `settings.json` under `mcp.servers`
(exact key may evolve with the extension; check your extension's docs).
The pattern is the same — replace the `command`/`args` with the wrapped
invocation:

```jsonc
{
  "mcp.servers": {
    "filesystem": {
      "command": "agentfence",
      "args": [
        "proxy",
        "--policy", "${userHome}/.config/agentfence/policy.yaml",
        "--audit-log", "${userHome}/.local/share/agentfence/audit.jsonl",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "${workspaceFolder}"
      ]
    }
  }
}
```

`${userHome}` and `${workspaceFolder}` are VS Code variable substitutions —
AgentFence itself does not resolve them.

## Writing your first policy

A minimal `policy.yaml`:

```yaml
version: "0.1"
defaults:
  decision: deny

tools:
  filesystem.read:
    decision: allow
  filesystem.write:
    decision: ask           # prompts on a TTY; auto-denied with --no-interactive
  github.create_issue:
    decision: ask
  github.delete_repo:
    decision: deny

redaction:
  enabled: true
  patterns:
    - name: openai_api_key
      regex: 'sk-[A-Za-z0-9_-]{20,}'
    - name: github_token
      regex: 'gh[pousr]_[A-Za-z0-9_]{20,}'
```

Validate it before pointing the proxy at it:

```bash
agentfence validate --policy policy.yaml
```

See [`docs/policy-language.md`](policy-language.md) for the full schema:
groups, wildcards, path constraints, argument constraints, URL constraints,
and shell-command constraints.

## Inspecting the audit log

Each evaluated `tools/call` produces one JSONL audit event:

```jsonl
{"schema_version":"2","session_id":"…","seq":1,"timestamp":"…","call_id":"42","tool":"filesystem.read","decision":"allow","reason":"tool filesystem.read matched explicit policy rule","arguments":{"path":"README.md"}}
{"schema_version":"2","session_id":"…","seq":2,"timestamp":"…","call_id":"43","tool":"filesystem.write","decision":"deny","reason":"path \".env\" denied by pattern \".env\"","arguments":{"content":"OPENAI_[REDACTED:openai_api_key]","path":".env"}}
```

Useful one-liners:

```bash
# All denies in the last run:
jq -c 'select(.decision=="deny")' audit.jsonl

# Top tools by call count:
jq -r '.tool' audit.jsonl | sort | uniq -c | sort -rn

# Verify the hash chain (requires --tamper-evident at write time):
agentfence audit verify --log audit.jsonl
```

## Troubleshooting

**"proxy: a downstream command is required after `--`"** — you forgot the
`--` separator and the command. Compare:

```bash
# wrong
agentfence proxy --policy policy.yaml
# right
agentfence proxy --policy policy.yaml -- node server.js
```

**`--policy is required (or pass --passthrough …)`** — running in
enforcement mode without a policy. Either provide `--policy` or add
`--passthrough` (skeleton mode only — not for production).

**`exec: "...": executable file not found in $PATH`** — the downstream
command is not on `$PATH` from the proxy's perspective. Use an absolute
path, or make sure `$PATH` is exported through your launcher.

**The agent appears to hang on a tool call** — the policy probably issued
an `ask` decision and the proxy is waiting for your `y/N` answer on the
terminal. Answer the prompt, set `--approval-timeout` to bound the wait, or
pass `--no-interactive` to auto-deny `ask` immediately in unattended runs.
Run with `--debug` to see the forwarded messages on stderr.

**Audit log is empty** — `--audit-log` was not passed. The proxy
intentionally does not write audit JSONL to stdout because stdout is
reserved for the agent's JSON-RPC channel.

**`audit verify` reports `chain absent`** — the audit log was written
without `--tamper-evident`. Re-run the proxy with the flag if you want a
verifiable chain.

**`audit verify` reports `PARTIAL`** — the log mixes unchained and chained
events; only the chained suffix is integrity-protected. This happens when a
log written without `--tamper-evident` is later fed into a chain-aware writer
out of band. `check`/`proxy` refuses `--tamper-evident` on any existing log
that is not already fully chained from event 1 (both fully-unchained logs
and partial-chain logs are rejected) to prevent this; rotate the log (move
or archive it) before enabling the flag.

## Limitations and known issues

- A JSON-RPC batch (array) body is forwarded transparently and is not gated;
  keep `ask`/`deny` rules in mind for clients that batch.
- The threat model for the proxy is documented at the trust-boundary level
  only; expansion is tracked under
  [issue #35](https://github.com/dgenio/agentfence/issues/35).
