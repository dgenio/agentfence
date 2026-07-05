# CLAIMS: receipts for what AgentFence promises

AgentFence makes a handful of trust claims. This page turns each one into a
**reproducer** — a command you can run to see the claim hold — plus explicit
**non-claims** so the boundary is clear. Where a claim is a property of the code
rather than a single command, the receipt names the file or behaviour to check.

All commands below run against files bundled in this repo. None require network
access — which is itself the first claim.

## Claim 1 — Local-first, no telemetry

AgentFence evaluates policy entirely on your machine. It opens no network
connection on its own; the only outbound traffic is to endpoints **you**
configure (`--audit-sink <url>` for log shipping, `--upstream <url>` for the
HTTP proxy).

**Receipt.** Every evaluation command works with networking disabled — there is
nothing to phone home to. And the core evaluation packages contain no outbound
HTTP/dial calls outside the operator-configured sink and upstream paths:

```bash
# Evaluation runs fully offline:
agentfence check --policy examples/policy.yaml --call examples/tool-calls.jsonl \
  --no-interactive --output text

# No hidden network egress in the core paths (returns nothing):
grep -rn "net.Dial\|http.Get\|http.Post\|http.DefaultClient" internal/ \
  --include=*.go | grep -v "_test.go" | grep -viE "sink|upstream|httpproxy|oplog"
```

## Claim 2 — Deny by default

With `defaults.decision: deny`, any tool call that matches no rule is denied. A
misconfiguration fails closed, not open.

**Receipt.** A tool that appears nowhere in the policy is denied with a
`default_decision` reason:

```console
$ echo '{"id":"x1","tool":"database.drop_table","arguments":{"table":"users"}}' \
    | agentfence check --policy examples/policy.yaml --call /dev/stdin \
        --output text --no-interactive
x1 database.drop_table -> deny (no rule for database.drop_table; using default decision)

1 call(s) processed, 0 parse error(s): allow=0 deny=1 ask=0
```

## Claim 3 — `ask` fails closed when unattended

An `ask` decision needs a human. With no controlling terminal — CI, a service —
`--no-interactive` auto-denies rather than silently allowing.

**Receipt.** `github.create_issue` is an `ask` rule in `examples/policy.yaml`;
non-interactively it becomes a deny:

```console
$ agentfence check --policy examples/policy.yaml --call examples/tool-calls.jsonl \
    --output text --no-interactive
…
call_003 github.create_issue -> deny (non-interactive: ask auto-denied)
```

## Claim 4 — Secrets are redacted in the audit log

Redaction patterns are applied to arguments before they are written to the audit
log, so a blocked secret-bearing call does not persist the secret.

**Receipt.** `examples/tool-calls.jsonl` includes a write of an
`OPENAI_API_KEY=…` value to `.env`. In the audit log the value is redacted:

```console
$ agentfence check --policy examples/policy.yaml --call examples/tool-calls.jsonl \
    --no-interactive --audit-log audit.jsonl --output text >/dev/null
$ grep call_002 audit.jsonl
{…,"call_id":"call_002","tool":"filesystem.write","decision":"deny",…,"arguments":{"content":"OPENAI_[REDACTED:generic_secret_assignment]","path":".env"}}
```

The raw secret never reaches the log.

## Claim 5 — Tamper-evident audit trail

With `--tamper-evident`, audit events are hash-chained. `agentfence audit verify`
confirms the chain, and any post-hoc edit is detected and located.

**Receipt.** Verify an intact log, then tamper with it and verify again:

```console
$ agentfence check --policy examples/policy.yaml --call examples/tool-calls.jsonl \
    --no-interactive --tamper-evident --audit-log te.jsonl --output text >/dev/null
$ agentfence audit verify --log te.jsonl
OK: 4 event(s) verified

# Flip a decision in the file, then re-verify:
$ sed -i 's/"decision":"deny","reason":"tool github.delete_repo/"decision":"allow","reason":"tool github.delete_repo/' te.jsonl
$ agentfence audit verify --log te.jsonl
FAILED: integrity check failed at event 4 (possible tampering)
error: audit verify: audit: event 4: hash mismatch: …
$ echo $?
1
```

For writer *authentication* (not just tamper-evidence), sign events with
`--sign-key` and verify with `agentfence audit verify --pubkey` — a stronger
claim covered in the [audit event schema](audit-event-schema.md).

## Claim 6 — Policy is validated before use

Invalid policy is rejected with an actionable error, not silently accepted.

**Receipt.**

```console
$ agentfence validate --policy examples/policy.yaml
examples/policy.yaml: OK
```

A malformed policy exits non-zero and names the problem (try removing a required
field and re-running).

## Explicit non-claims

AgentFence is a policy decision point. It is **not**:

- **A sandbox for a malicious MCP server.** It gates the *calls* an agent makes;
  a compromised server can still misbehave within allowed calls. Combine it with
  OS/container/network isolation.
- **A guarantee that your policy is safe.** A wrong or permissive policy is
  enforced faithfully. Review policies like code (see
  [CONTRIBUTING](../CONTRIBUTING.md) on security-sensitive paths).
- **A cloud gateway or hosted monitoring service.** It is a local tool with a
  local audit log; there is no AgentFence backend.
- **A replacement for host, container, or network isolation.** It is one layer
  of a defence-in-depth posture, not the whole of it.

See the [threat model](threat-model.md) for the full scope, trust boundaries,
and residual risks.
