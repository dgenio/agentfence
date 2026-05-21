# AgentFence enforcement modes

AgentFence supports four distinct operating modes. They differ in **whether
policy decisions are enforced**, **whether the operator is prompted**, and
**how the exit code is propagated**. The wording in this document is the
canonical source — `README.md`, `docs/architecture.md`, and
`docs/threat-model.md` all link here rather than restating the definitions.

## The four modes

### Detection

Evaluate every call against policy and emit audit events, but **never block
or prompt**. Allowed calls proceed; calls that would be denied or asked are
forwarded anyway and recorded with their would-be decision.

- **Purpose:** observe what a policy would do against live traffic before
  enabling enforcement; shadow-test rule changes.
- **Audit behavior:** every evaluated call produces an event.
- **Exit code:** zero unless a runtime error occurs; `--fail-on` is **not**
  honored.
- **User interaction:** none.

### Prevention (enforcement)

Evaluate every call and **enforce** the decision: `allow` forwards, `deny`
blocks (returning an error to the agent), `ask` triggers an approval flow
that resolves to `allow` or `deny`. This is the default for runtime use.

- **Purpose:** production gate between an agent and its tool servers.
- **Audit behavior:** every evaluated call produces an event with the final
  enforced decision.
- **Exit code:** for batch `check`, `--fail-on deny,ask` returns non-zero
  when matching decisions occur. For `proxy`, the process keeps running and
  reflects per-call denial via JSON-RPC error responses to the agent.
- **User interaction:** `ask` decisions invoke the configured approver
  (interactive TTY by default; `--no-interactive` forces auto-deny).

### Audit-only

Evaluate calls from a previously captured stream and produce audit records.
There is no live tool execution to enforce against; the records exist for
inspection, replay, or CI gating.

- **Purpose:** offline policy evaluation against a JSONL capture; CI gating
  via `--fail-on`; post-incident review.
- **Audit behavior:** every parsed call produces an event; malformed lines
  produce synthetic `deny` events and processing continues.
- **Exit code:** zero unless `--fail-on` matches at least one decision in
  the input, in which case the exit code is non-zero. An input where every
  line fails to parse also returns non-zero.
- **User interaction:** `ask` decisions invoke the configured approver
  (same as prevention); `--no-interactive` is recommended in CI.

### Dry-run (simulation)

Evaluate every call, write audit records with an explicit `"mode": "dry_run"`
marker, but **never invoke the approver and never propagate `--fail-on` as
a non-zero exit**. `ask` decisions are recorded verbatim — they are not
converted into `allow` or `deny`.

- **Purpose:** evaluate before enforcing; preview the impact of a policy
  change on an existing tool-call stream.
- **Audit behavior:** every event carries `"mode": "dry_run"` so downstream
  consumers can distinguish simulated decisions from enforced ones; text
  output is suffixed with `[dry-run]`.
- **Exit code:** zero unless a runtime error occurs. `--fail-on` reports
  what *would* have failed but does not change the exit code.
- **User interaction:** none — the approver is bypassed.

## Command-to-mode mapping

| Invocation                                            | Mode                | Status                  |
|-------------------------------------------------------|---------------------|-------------------------|
| `agentfence check --call <jsonl>`                     | Audit-only          | Implemented             |
| `agentfence check --call <jsonl> --fail-on deny`      | Audit-only (CI gate)| Implemented             |
| `agentfence check --call <jsonl> --dry-run`           | Dry-run             | In-progress (PR #50)    |
| `agentfence proxy --policy <file> -- <tool-server>`   | Prevention          | In-progress (PR #49)    |
| `agentfence proxy --passthrough ...`                  | Detection           | In-progress (PR #49)    |
| `agentfence audit verify --log <file>`                | Integrity check     | Implemented             |

The `In-progress` rows depend on PRs that are open at the time of writing
(#49 for the MCP proxy, #50 for dry-run). The mode taxonomy itself is
already canonical; flipping these rows to `Implemented` is a mechanical
follow-up once those PRs merge.

`audit verify` is not a runtime evaluation mode — it inspects an
already-produced audit log for tamper-evident chain integrity. It is listed
here so the table is exhaustive.

## Choosing a mode

| If you want to …                                      | Use         |
|-------------------------------------------------------|-------------|
| Block agent tool calls in production                  | Prevention  |
| Try a new policy against real traffic without risk    | Detection   |
| Gate a CI pipeline on a captured tool-call stream     | Audit-only with `--fail-on` |
| See what a policy change *would* do                   | Dry-run     |
| Confirm an audit log has not been tampered with       | `audit verify` |

## Audit-event `mode` field

Audit events carry an optional `mode` string field. Today only `"dry_run"`
is emitted; events without an explicit `mode` value are produced under an
enforcing mode (prevention, audit-only, or detection — distinguishable from
the recorded `decision` and the absence of an approver-related `reason`).

A future detection-mode marker may be introduced; consumers should treat
unknown `mode` values as opaque rather than rejecting them.
