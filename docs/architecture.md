# AgentFence architecture (MVP)

## Current MVP architecture

AgentFence currently works as a local policy evaluator and audit logger:

1. Load YAML policy.
2. Read JSONL tool-call records.
3. Evaluate each call against policy rules.
4. Produce a decision (`allow`, `deny`, `ask`) and reason.
5. Redact sensitive-looking values in arguments.
6. Emit audit events as JSONL.

In MVP mode, AgentFence does **not** execute or proxy tool calls.

## Future MCP proxy architecture

Planned next step is to run AgentFence as an MCP-aware proxy between agents and tool providers:

- Agent -> AgentFence proxy -> MCP server/tools
- AgentFence evaluates and gates each call before forwarding.
- `ask` decisions can trigger interactive approval.
- Audit trail covers requests, approvals, and final disposition.

## Policy evaluation flow

- Exact tool name rule wins when present.
- Otherwise use `defaults.decision`.
- Path constraints are checked when present.
- Deny path patterns are evaluated before allow patterns.
- Any denied or non-allowed constrained path returns `deny`.

## Audit flow

- Every evaluated call creates one audit event.
- Event includes timestamp, call id, tool, decision, reason, and optionally redacted arguments.
- Events are encoded as JSONL for easy ingestion.

## Redaction flow

- Redaction patterns are loaded from policy regex rules.
- Arguments are recursively traversed.
- String values matching any configured secret pattern are replaced with `[REDACTED:<pattern_name>]`.
- Redaction occurs before arguments are written into audit logs.
