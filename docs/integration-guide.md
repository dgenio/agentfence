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
| `--audit-log <file>`  | Write JSONL audit events to this file. If omitted, audit events are discarded (the proxy never mixes audit JSONL into the agent's stdout — that channel is reserved for JSON-RPC). |
| `--tamper-evident`    | Hash-chain audit events. Verify later with `agentfence audit verify --log <file>`. |
| `--passthrough`       | Skeleton mode: forward every message without policy evaluation. Useful for validating the relay; do **not** use in production. |
| `--no-interactive`    | Reserved. Today every `ask` decision is denied (see [Approval today](#approval-today)). |
| `--debug`             | Log every forwarded JSON-RPC message to stderr. Off by default because MCP messages routinely contain user content. |

## Approval today

The current proxy ships with a default-deny approver: every `ask` decision is
converted to a `deny` and the agent sees a `BlockedByPolicy` response with
`"... (denied via ask)"` in the reason.

The interactive TTY approver is tracked under
[issue #29](https://github.com/dgenio/agentfence/issues/29); a non-blocking
timeout follows in [issue #30](https://github.com/dgenio/agentfence/issues/30).
Once those land, the `--no-interactive` flag will switch off the prompt.

For now, configure your policies so the only `ask` rules cover calls you are
fine seeing blocked in an unattended context — promote them to `allow` if
you really want them through, or to `deny` if you really want them stopped.

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
    decision: ask           # while #29/#30 are open, this becomes deny
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
{"schema_version":"1","session_id":"…","seq":1,"timestamp":"…","call_id":"42","tool":"filesystem.read","decision":"allow","reason":"tool filesystem.read matched explicit policy rule","arguments":{"path":"README.md"}}
{"schema_version":"1","session_id":"…","seq":2,"timestamp":"…","call_id":"43","tool":"filesystem.write","decision":"deny","reason":"path \".env\" denied by pattern \".env\"","arguments":{"content":"OPENAI_[REDACTED:openai_api_key]","path":".env"}}
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

**`proxy: a downstream command is required after `--``** — you forgot the
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
an `ask` decision. While #29/#30 are open, the default approver always
denies; the agent should receive a `BlockedByPolicy` response within
microseconds. If you actually see a hang, run with `--debug` to see the
forwarded messages on stderr.

**Audit log is empty** — `--audit-log` was not passed. The proxy
intentionally does not write audit JSONL to stdout because stdout is
reserved for the agent's JSON-RPC channel.

**`audit verify` reports `chain absent`** — the audit log was written
without `--tamper-evident`. Re-run the proxy with the flag if you want a
verifiable chain.

## Limitations and known issues

- The proxy supports stdio transport only. HTTP/SSE proxying is on the
  roadmap.
- `--no-interactive` is reserved; today every `ask` decision is denied
  (issue [#29](https://github.com/dgenio/agentfence/issues/29)).
- There is no approval timeout flag yet (issue
  [#30](https://github.com/dgenio/agentfence/issues/30)). The proxy's
  context cancellation propagates to the approver, but no per-decision
  timeout is wired in.
- The threat model for the proxy is documented at the trust-boundary level
  only; expansion is tracked under
  [issue #35](https://github.com/dgenio/agentfence/issues/35).
