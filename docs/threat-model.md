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
- Path-based guardrails for filesystem tools, including absolute, UNC, and
  parent-directory escape checks whenever a string `path` argument is present.
- Audit logging for each decision, with a versioned schema, monotonic sequence
  numbers, and per-run session identifiers.
- Regex-based redaction for sensitive-looking argument values, applied before
  arguments are written into audit events (including arguments nested inside
  objects and arrays).
- Optional tamper-evident audit chaining (`--tamper-evident` on `check`) so
  modification or deletion of audit events is detectable after the fact via
  `agentfence audit verify --log <file>`.

## Audit log integrity

The audit log is a security-critical artifact: investigators rely on it to
reconstruct what an agent did and what the gate decided. Without integrity
protection, an attacker with filesystem access can rewrite a `deny` to
`allow`, or delete inconvenient events, with no signature mismatch.

### Risk

- Filesystem-level modification of past audit events.
- Deletion or reordering of audit events.
- Silent truncation of the log to hide recent activity.

### Mitigation

- When the writer is run with `--tamper-evident`, each event records its
  SHA-256 (`hash`) and a `prev_hash` field referencing the previous event's
  hash. The first event in a chain omits `prev_hash`, which marks the chain
  start.
- `agentfence audit verify --log <file>` walks the chain, re-computes each
  event's hash, and refuses to confirm the log if any event has been altered
  or removed. Modification of a single event causes verification to fail on
  that exact event; deleting an event causes verification to fail at the next
  event because its `prev_hash` no longer matches.
- The hash is computed over the canonical JSON encoding of the event with
  its own `hash` field cleared. `encoding/json` emits struct fields in
  declaration order and sorts map keys, so the encoding is deterministic for
  a given logical event.

### Residual risk

- **Whole-log deletion is not detectable from the log alone.** If an attacker
  deletes the entire file, there is nothing left to verify. Mitigate by
  shipping audit events to an append-only sink (out of scope for this MVP).
- **Adding entirely new chained events** (with correctly recomputed hashes)
  is detectable only if the verifier has an externally trusted starting hash
  or counter. AgentFence does not currently support a "chain root" anchor.
- **The chain is unverifiable when interleaved with other output.** Running
  `--tamper-evident` without `--audit-log` mixes audit lines with stdout text;
  `audit verify` may then fail or be unable to find the chain. The CLI warns
  when this combination is requested.
- Tamper evidence is **not** the same as cryptographic signing. An attacker
  with write access to the log can still produce a fully consistent chain
  starting from any modified event. Detecting that requires a signed event
  (out of scope for this MVP).

## What MVP does not yet mitigate

- Full MCP transport proxying (stdio/HTTP) is not implemented yet.
- Native interactive approval UX is not implemented yet.
- Cryptographic signing of audit events is not implemented yet (tamper-evident
  chaining detects modification, but does not authenticate the writer).
- Runtime sandboxing of tool execution is out of scope for this MVP.
