# AgentFence

## A policy firewall for AI agents and MCP tools

AI coding agents are getting access to your filesystem, GitHub, browser, databases, and internal APIs. AgentFence gives you a local policy layer before tool calls happen.

AgentFence is local-first, vendor-neutral, MCP-friendly, and designed for safe defaults. It evaluates tool calls, supports allow/deny/ask decisions, redacts sensitive-looking values in logs, and writes auditable decision records.

> MVP status: this release evaluates and logs tool calls from JSONL input. Full MCP proxy support is planned next.

## Why this exists

Tool-capable agents are useful, but they can also be risky:

- Prompt injection can trigger unsafe calls.
- Agents may take destructive actions too quickly.
- Sensitive values can leak into logs.
- Teams need an audit trail of what was allowed, denied, or sent for approval.

AgentFence is a practical local control point before execution.

## Install

### Build from source

```bash
go build -o agentfence ./cmd/agentfence
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

Initialize a starter policy in your current directory:

```bash
./agentfence init
```

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

## Example evaluation

Input JSONL:

```json
{"id":"call_001","tool":"filesystem.read","arguments":{"path":"README.md"}}
{"id":"call_002","tool":"filesystem.write","arguments":{"path":".env","content":"OPENAI_API_KEY=sk-demo-secret"}}
```

Expected decisions:

- `call_001` -> `allow`
- `call_002` -> `deny` (path constraint), with secret-looking content redacted in audit output

## Threat model summary

AgentFence is built to reduce practical risks from agent tool calls:

- prompt injection
- confused deputy behavior
- accidental destructive actions
- secret leakage through logs
- excessive default permissions

See [`docs/threat-model.md`](docs/threat-model.md) for details.

## Roadmap

- MCP stdio proxy mode
- MCP streamable HTTP proxy mode
- interactive TTY approval
- signed audit logs
- GitHub Action mode for CI policy checks
- reusable policy packs for filesystem, GitHub, browser, database, and shell tools
- policy test command
- VS Code / Claude Code / Copilot CLI integration examples

## Non-goals (MVP)

- Executing real tool calls
- Claiming full MCP proxy compatibility
- Replacing runtime sandboxing or OS-level isolation

## Contributing

Issues and PRs are welcome. Please run:

```bash
go test ./...
go vet ./...
```

before opening a pull request.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
