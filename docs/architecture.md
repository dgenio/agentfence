# AgentFence architecture

AgentFence operates in two modes:

- **Batch `check` mode** — evaluate a JSONL stream of recorded tool calls
  offline. Does not execute tool calls; produces decisions + audit events.
- **MCP proxy mode (`agentfence proxy`)** — live policy gate that sits
  between an agent and an MCP tool server, intercepting `tools/call`
  requests in real time. Does not execute tool calls itself; it forwards
  allowed calls to the downstream MCP server and synthesizes JSON-RPC
  error responses for denied ones.

Neither mode is a sandbox: AgentFence enforces policy *before* a tool call
executes; it does not contain a tool call that has already been forwarded.

## Batch (`check`) architecture

AgentFence works as a local policy evaluator and audit logger:

1. Load YAML policy.
2. Read JSONL tool-call records.
3. Evaluate each call against policy rules. Malformed lines (invalid JSON or missing required fields) emit a synthetic `deny` audit event and processing continues — no subsequent calls are silently skipped.
4. Produce a decision (`allow`, `deny`, `ask`) and reason.
5. Redact sensitive-looking values in arguments.
6. Emit audit events as JSONL.

Fail-safe behavior: a single malformed line never aborts evaluation of remaining calls. An all-malformed input (every line fails to parse) returns a non-zero exit code.

## MCP proxy architecture

AgentFence can also run as an MCP-aware stdio proxy between an agent and
its tool servers (`agentfence proxy --policy <file> -- <command> [args...]`).
See [`integration-guide.md`](integration-guide.md) for end-to-end
configuration examples.

- Agent → AgentFence proxy → MCP server/tools.
- The proxy spawns the MCP server as a subprocess and relays newline-
  delimited JSON-RPC messages in both directions.
- Every `tools/call` request is parsed (`internal/mcp`) and converted to a
  `policy.ToolCall`, then evaluated by the engine. Non-`tools/call`
  messages (initialize, ping, notifications) are forwarded untouched.
- On `allow` the original request is forwarded to the subprocess.
- On `deny` the proxy answers the agent with a JSON-RPC error response
  (code `-32001`, "blocked by AgentFence policy: <reason>") and the
  subprocess never sees the request.
- On `ask` a pluggable `Approver` decides at runtime; an approved call is
  forwarded, a denied one becomes the same blocked-by-policy response.
  The default `DenyAllApprover` denies every `ask` until a TTY-backed
  approver lands (issues #29, #30).
- Every evaluated request produces one audit event using the same
  `audit.Writer` as `check`, so `--tamper-evident` and `agentfence audit
  verify` work identically against proxy logs.
- HTTP / streamable transport remains future work.

## Policy evaluation flow

- Rule lookup uses the following precedence (highest first):
  1. **Exact match** — tool name matches a key in `tools` exactly.
  2. **Group match** — tool name matches a member pattern of a named group in `groups` that also has a `tools` entry. Groups are checked in alphabetical name order; within a group, member patterns are checked in declaration order.
  3. **Wildcard match** — tool name matches a glob pattern key in `tools` that is not a group name. Patterns are checked in alphabetical order for determinism.
  4. **Default** — `defaults.decision` applies.
- Path constraints are checked when present.
- Argument value constraints (`constraints.args`) are checked after path constraints.
- URL constraints (`constraints.urls`) are checked for browser/HTTP tools.
- Command constraints (`constraints.command`) are checked for shell/terminal tools.
- Deny patterns/rules are evaluated before allow patterns.
- Any denied constraint returns `deny` immediately.

## Audit flow

- Every evaluated call creates one audit event.
- Each event carries a stable schema (`schema_version`), a per-run
  `session_id`, a monotonic `seq` number, plus `timestamp`, `call_id`, `tool`,
  `decision`, `reason`, and (optionally) redacted arguments.
- Events are encoded as JSONL for easy ingestion.
- `--tamper-evident` enables a SHA-256 hash chain: each event records its own
  `hash`; all but the first chained event record the previous event's `hash`
  in `prev_hash`. The chain can be verified after the fact with
  `agentfence audit verify --log <file>`. See
  [`threat-model.md`](threat-model.md#audit-log-integrity) for what this does
  and does not protect against.

## Redaction flow

- Redaction patterns are loaded from policy regex rules.
- Arguments are recursively traversed.
- String values matching any configured secret pattern are replaced with `[REDACTED:<pattern_name>]`.
- Redaction occurs before arguments are written into audit logs.
