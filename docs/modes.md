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
| `agentfence check --call <jsonl> --dry-run`           | Dry-run             | Implemented             |
| `agentfence proxy --policy <file> -- <tool-server>`   | Prevention          | Implemented             |
| `agentfence proxy --passthrough ...`                  | Detection           | Implemented             |
| `agentfence audit verify --log <file>`                | Integrity check     | Implemented             |

All modes listed above are implemented on `main`.

`audit verify` is not a runtime evaluation mode — it inspects an
already-produced audit log for tamper-evident chain integrity. It is listed
here so the table is exhaustive.

## Worked examples

Each block below is runnable against files bundled in this repo
(`examples/policy.yaml`, `examples/tool-calls.jsonl`) so you can see the exact
flags, output, and audit `mode` field for each mode.

### Prevention — block in real time

Wrap an MCP server and enforce decisions live. The bundled smoke example
(hermetic — no network) shows an allowed read and a denied write:

```console
$ ./examples/proxy-smoke.sh
+ agentfence proxy (prevention mode) wrapping the stub MCP server
…
{"jsonrpc":"2.0","id":1,"result":{…}}                 # read forwarded
{"jsonrpc":"2.0","id":2,"error":{"code":-32001,…}}    # write blocked (BlockedByPolicy)
…
PASS: read forwarded, write blocked by policy (BlockedByPolicy -32001).
```

The denied call gets a JSON-RPC `-32001` error and the tool server never sees
it. Audit events carry no `mode` field (an absent `mode` means an enforcing
mode).

### Audit-only — evaluate a captured trace

Evaluate a recorded JSONL stream. Decisions are reported and audited; there is
no live call to block:

```console
$ agentfence check --policy examples/policy.yaml --call examples/tool-calls.jsonl \
    --output text --no-interactive
call_001 filesystem.read -> allow (tool filesystem.read matched explicit policy rule)
call_002 filesystem.write -> deny (path ".env" denied by pattern ".env")
call_003 github.create_issue -> deny (non-interactive: ask auto-denied)
call_004 github.delete_repo -> deny (tool github.delete_repo matched explicit policy rule)

4 call(s) processed, 0 parse error(s): allow=1 deny=3 ask=0
```

Audit events have no `mode` field. Add `--fail-on deny` (or `deny,ask`) to turn
it into a CI gate — the exit code becomes non-zero when a matching decision
occurs:

```console
$ agentfence check --policy examples/policy.yaml --call examples/tool-calls.jsonl \
    --no-interactive --fail-on deny
…
AgentFence: 3 call(s) matched --fail-on criteria (deny)
error: 3 call(s) matched --fail-on criteria
$ echo $?
1
```

### Dry-run — preview without enforcing

Same evaluation, but every event is marked `"mode": "dry_run"`, `ask` is
recorded verbatim (not converted), and `--fail-on` never changes the exit code:

```console
$ agentfence check --policy examples/policy.yaml --call examples/tool-calls.jsonl \
    --output text --dry-run --no-interactive
call_001 filesystem.read -> allow (…) [dry-run]
call_002 filesystem.write -> deny (…) [dry-run]
call_003 github.create_issue -> ask (…) [dry-run]
call_004 github.delete_repo -> deny (…) [dry-run]

4 call(s) processed, 0 parse error(s): allow=1 deny=2 ask=1
```

Note `ask=1` here versus `ask=0` in the audit-only run above: dry-run preserves
the `ask` decision instead of resolving it. The audit line carries the marker:

```jsonl
{"schema_version":"4",…,"decision":"allow",…,"mode":"dry_run"}
```

### Detection — observe live traffic

> **Note (behaviour caveat):** the `--passthrough` proxy flag currently
> **forwards every message without evaluating policy and without writing audit
> events** — it is a relay/skeleton mode for validating the transport, not a
> detection mode. A true detection mode (evaluate every live call and emit audit
> events, but never block or prompt) is not yet exposed as a distinct proxy
> flag. Reworking this into an explicit no-enforcement label is tracked in
> [issue #174](https://github.com/dgenio/agentfence/issues/174). To *observe*
> what a policy would decide today without enforcing, run the captured stream
> through `check --dry-run` (above).

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
