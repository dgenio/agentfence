# Daily Driver: operating AgentFence day to day

The [Quickstart](quickstart.md) gets you to a first gated call. This guide is
for the next stage: running AgentFence in front of your MCP servers as part of a
normal workflow — rolling out a policy safely, triaging decisions, gating CI,
and keeping the audit log healthy.

## When to reach for AgentFence

AgentFence is the **external gate**: a standalone CLI and MCP proxy that sits
outside the agent process and is configured by an operator. Reach for it when
the policy author is not the application author — you want to constrain an agent
or MCP server you did not write.

If you are *building* an agent application and want safety compiled in, that is
the job of an in-process layer such as `agent-kernel`; the two are complementary
(see the README's [Relationship to agent-kernel](../README.md#relationship-to-agent-kernel)
and the [edge-proxy-vs-kernel comparison](edge-proxy-vs-kernel.md)).

## The core loop

Day to day, you cycle through five steps:

```
init/edit ──► validate ──► dry-run ──► enforce (proxy / check) ──► review audit
     ▲                                                                   │
     └───────────────────────── refine policy ◄─────────────────────────┘
```

1. **Author** a policy (`agentfence init --pack …`, then edit
   `agentfence.yaml`).
2. **Validate** it: `agentfence validate --policy agentfence.yaml`.
3. **Dry-run** it against real traffic to see what it *would* do before it
   blocks anything (below).
4. **Enforce** it — live via `agentfence proxy`, or over a captured trace via
   `agentfence check`.
5. **Review** the audit log (`agentfence audit summarize`) and refine.

## Start in dry-run, not prevention

Never point a brand-new policy at production traffic in prevention mode. Run it
in **dry-run** first: every call is evaluated and recorded with a `"mode":
"dry_run"` marker, but nothing is blocked and no approver is invoked.

```bash
agentfence check \
  --policy agentfence.yaml \
  --call captured-calls.jsonl \
  --dry-run \
  --no-interactive \
  --output text \
  --audit-log dry-run.jsonl
```

```
c1 filesystem.read -> allow (…) [dry-run]
c2 filesystem.write -> deny (…) [dry-run]
c3 github.create_issue -> ask (…) [dry-run]
```

The `[dry-run]` suffix and the `mode` field tell you a decision was simulated,
not enforced. `ask` decisions are recorded verbatim (not converted to
allow/deny), so you can see exactly where an operator would have been prompted.
When the dry-run decisions look right, drop `--dry-run` to enforce. See
[Enforcement modes](modes.md) for the full taxonomy.

## Triaging allow / deny / ask

- **allow** — the call matched an explicit allow rule (or the default is
  `allow`, which is not recommended). Nothing to do.
- **deny** — blocked. Read the `reason`/`reason_code` (e.g. `path_denied`,
  `default_decision`, `taint_escalated`). A `default_decision` deny means no
  rule matched and your `defaults.decision: deny` caught it — decide whether to
  add an explicit rule.
- **ask** — needs a human. Live, the proxy prompts on the TTY. Unattended, pass
  `--no-interactive` to auto-deny, or `--approval-timeout 30s` to bound the
  wait before it falls back to deny.

To understand a single decision in isolation, use `explain`:

```bash
agentfence explain --policy agentfence.yaml --tool filesystem.write --args '{"path":".env"}'
```

```
tool:     filesystem.write
decision: deny
reason:   path ".env" denied by pattern ".env"
trace:
  - matched rule "filesystem.write" (decision: ask)
  - checking path constraints for ".env" (normalized: ".env")
  - path ".env" denied by pattern ".env"
```

## Recommended defaults for CI / unattended use

In CI or any process with no controlling terminal:

- **`--no-interactive`** — auto-deny every `ask` instead of hanging on a prompt.
- **`--fail-on deny`** (or `deny,ask`) on `check` — exit non-zero when a matching
  decision occurs, so a bad tool-call trace fails the job:

  ```bash
  agentfence check --policy agentfence.yaml --call calls.jsonl \
    --no-interactive --fail-on deny
  # exit code 1 if any call was denied
  ```

- **`--tamper-evident`** — hash-chain the audit log so it can be verified later.

A ready-to-copy GitHub Actions setup lives in
[`examples/github-action-workflow.yml`](../examples/github-action-workflow.yml);
the composite action is documented in the
[integration guide](integration-guide.md#github-action).

## Reviewing and rotating the audit log

Summarize a log to see the shape of what happened:

```bash
agentfence audit summarize --log audit.jsonl
```

```
Audit summary
  total events:   4
  malformed:      0
  by decision:    allow=1 deny=2 ask=1
  schema versions: 4=4

By reason code:
      1  path_denied
      3  rule_match
  …
```

If you wrote the log with `--tamper-evident`, verify its integrity:

```bash
agentfence audit verify --log audit.jsonl
# OK: N event(s) verified
```

**Rotation.** The proxy and `check` can rotate the audit log for you:
`--audit-max-size <bytes>`, `--audit-max-age <dur>` (e.g. `24h`), and
`--audit-keep <n>` to bound retained segments. Note that enabling
`--tamper-evident` on an existing, unchained log is refused (to avoid a
partial chain) — rotate or archive the old log first. Add `--audit-fsync` when a
decision must survive a crash or power loss.

## When *not* to use AgentFence

AgentFence is a policy gate, not a sandbox. Do not rely on it alone when:

- The upstream MCP server itself is untrusted — AgentFence gates the calls, but
  a malicious server can still misbehave within allowed calls. Sandbox it
  (container, seccomp, network isolation) as well.
- Your authorization model is unclear — a gate only enforces the policy you
  wrote; a wrong policy is enforced faithfully.
- You need OS/container/network isolation — that is a different layer;
  AgentFence complements it, it does not replace it.

See the [threat model](threat-model.md) for the full scope and residual risks,
and [CLAIMS](claims.md) for what AgentFence does and does not promise.
