# Integration pattern: policy-checked worker actions (Puppetmaster)

This page describes a reusable pattern: an external supervisor that orchestrates
multiple workers runs each **proposed worker action** through an AgentFence
policy decision point before letting the worker proceed. Puppetmaster is the
motivating example of such a supervisor, but the pattern applies to any
orchestrator that can call out to a decision point.

AgentFence's role here is narrow and deliberate: it is the **decision point**
(allow / deny / ask + audit) for proposed actions. It is **not** a job
supervisor, task queue, or model router — those remain the orchestrator's job.

## The shape

```
┌──────────────┐   proposed action    ┌──────────────┐   allow?   ┌──────────┐
│  supervisor  │ ───────────────────► │  AgentFence  │ ─────────► │  worker  │
│ (Puppetmaster│ ◄─────────────────── │ decision pt. │            │  runs it │
│  + workers)  │   allow / deny / ask  └──────────────┘            └──────────┘
└──────────────┘                             │
                                             ▼
                                      audit log (JSONL)
```

Each worker, before performing a side-effecting action (a file write, a shell
command, an API call), asks the supervisor for clearance. The supervisor turns
the proposed action into a tool-call record and asks AgentFence to decide.

## Two ways to wire the decision point

**1. Batch/per-action via `agentfence check`.** The supervisor writes each
proposed action as a one-line JSON tool-call and evaluates it. This needs no
long-running process — it is a subprocess call per action (or per batch):

```console
$ echo '{"id":"job-42","tool":"shell.exec","arguments":{"command":"rm -rf build"}}' \
    | agentfence check --policy supervisor-policy.yaml --call /dev/stdin \
        --output json --no-interactive --fail-on deny,ask
```

The exit code tells the supervisor whether to proceed: zero → allowed; non-zero
→ the action was denied (or needs approval). The `--output json` decision record
gives the supervisor the reason to log or surface to an operator.

**2. Live via the HTTP proxy.** If workers already speak MCP, put
`agentfence proxy-http` in front of the shared tool server so every worker's
`tools/call` is gated centrally, with one audit trail for the whole fleet. See
the [integration guide](integration-guide.md#wrapping-a-remote-mcp-server-over-http).

## Roll out in dry-run first

Do not switch a fleet straight to enforcement. Run the supervisor's proposed
actions through dry-run so you can see what *would* be blocked without stopping
any worker:

```console
$ agentfence check --policy supervisor-policy.yaml --call proposed-actions.jsonl \
    --dry-run --no-interactive --output text --audit-log rollout.jsonl
job-1 shell.exec -> allow (…) [dry-run]
job-2 shell.exec -> deny (…) [dry-run]
```

Review `rollout.jsonl`, tune the policy, then drop `--dry-run`. See
[Enforcement modes](modes.md) for the full taxonomy and the
[Daily Driver guide](daily-driver.md) for the roll-out loop.

## Handling allow / deny / ask in a supervisor

- **allow** — the supervisor lets the worker proceed.
- **deny** — the supervisor cancels the action and records the reason; the worker
  should treat this as a hard stop, not a retry-able error.
- **ask** — the action needs a human. In an unattended fleet, use
  `--no-interactive` (auto-deny) or `--approval-timeout`, and route the pending
  action to your own approval channel. AgentFence does not provide a fleet
  approval UI — that is the supervisor's responsibility.

## One audit trail for the fleet

Point every decision at a shared, tamper-evident audit log
(`--audit-log fleet.jsonl --tamper-evident`) so the supervisor has a single,
verifiable record of every action it cleared or blocked. Summarize it with
`agentfence audit summarize` and verify integrity with `agentfence audit verify`
(see [CLAIMS](claims.md)).

## Boundaries (what stays with the supervisor)

- **Scheduling, retries, worker lifecycle** — AgentFence decides on a proposed
  action; it does not run, queue, or restart workers.
- **Model/tool routing** — which worker or model handles a task is the
  supervisor's decision.
- **Approval UX** — AgentFence exposes the `ask` decision; the supervisor owns
  how a human is prompted in a fleet context.

Keeping AgentFence to the decision-point role keeps the integration small and
the audit trail meaningful.
