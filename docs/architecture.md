# AgentFence architecture (MVP)

## Current MVP architecture

AgentFence currently works as a local policy evaluator and audit logger:

1. Load YAML policy.
2. Read JSONL tool-call records.
3. Evaluate each call against policy rules. Malformed lines (invalid JSON or missing required fields) emit a synthetic `deny` audit event and processing continues — no subsequent calls are silently skipped.
4. Produce a decision (`allow`, `deny`, `ask`) and reason.
5. Redact sensitive-looking values in arguments.
6. Emit audit events as JSONL.

Fail-safe behavior: a single malformed line never aborts evaluation of remaining calls. An all-malformed input (every line fails to parse) returns a non-zero exit code.

In MVP mode, AgentFence does **not** execute or proxy tool calls.

## Future MCP proxy architecture

Planned next step is to run AgentFence as an MCP-aware proxy between agents and tool providers:

- Agent -> AgentFence proxy -> MCP server/tools
- AgentFence evaluates and gates each call before forwarding.
- `ask` decisions can trigger interactive approval.
- Audit trail covers requests, approvals, and final disposition.

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
  `hash` and the previous event's `hash` in `prev_hash`. The chain can be
  verified after the fact with `agentfence audit verify --log <file>`. See
  [`threat-model.md`](threat-model.md#audit-log-integrity) for what this does
  and does not protect against.

## Redaction flow

- Redaction patterns are loaded from policy regex rules.
- Arguments are recursively traversed.
- String values matching any configured secret pattern are replaced with `[REDACTED:<pattern_name>]`.
- Redaction occurs before arguments are written into audit logs.

## Enforcement modes

AgentFence defines four enforcement modes (not all implemented at time of
writing; see [`modes.md`](modes.md) for status): **detection**,
**prevention**, **audit-only**, and **dry-run**. The
modes differ in whether decisions are enforced, whether the operator is
prompted, and how the exit code is propagated. The canonical definitions and
command-to-mode mapping live in [`modes.md`](modes.md); the threat model
references those modes when describing what each enforcement boundary
guarantees (see [`threat-model.md`](threat-model.md)).
