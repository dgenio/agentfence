# AgentFence threat model (MVP)

## Key risks

### Prompt injection

An agent may be tricked into issuing dangerous tool calls by untrusted prompt content.

### Confused deputy

The agent has access to high-privilege tools and may be induced to perform actions on behalf of an attacker.

### Accidental destructive actions

Automated write/delete calls can damage repos, infrastructure, or data.

### Secret leakage

Sensitive values in tool arguments can leak into logs.

### Excessive permissions

Agents often run with broad privileges that violate least-privilege principles.

## What AgentFence mitigates today

- Local policy decisions (`allow`, `deny`, `ask`) before execution.
- Safe defaults through default-deny policy.
- Path-based guardrails for filesystem tools.
- Audit logging for each decision.
- Regex-based redaction for sensitive-looking argument values.

## What MVP does not yet mitigate

- Full MCP transport proxying (stdio/HTTP) is not implemented yet.
- Native interactive approval UX is not implemented yet.
- Cryptographic signing/tamper-evidence for audit logs is not implemented yet.
- Runtime sandboxing of tool execution is out of scope for this MVP.
