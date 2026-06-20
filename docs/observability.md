# Observability

AgentFence keeps three output streams deliberately separate so each can be
consumed without contaminating the others:

| Stream | Where | Carries | Format |
|--------|-------|---------|--------|
| **Decision output** | stdout (`check`) / the JSON-RPC channel (proxies) | the gate's decisions / the proxied protocol | `--output text\|json\|jsonl` (`check`) |
| **Audit log** | `--audit-log` file and/or `--audit-sink` | the durable, tamper-evident decision record | JSONL ([schema](audit-event-schema.md)) |
| **Operational log** | stderr | diagnostics: warnings, upstream/approval errors, debug frames | `--log-format text\|json` |

On top of these, the CLI and proxies expose **decision metrics**: counts by
decision, tool, and [reason code](audit-event-schema.md#reason-codes), plus
taint escalations, approval outcomes, evaluation latency, and operational
errors.

Everything here is local and operator-controlled. Nothing is sent anywhere
AgentFence chooses — consistent with the project's no-telemetry posture: you
pick the log destination, the metrics scrape target, and whether either is on at
all.

## Structured operational logging (`--log-format`)

`check`, `proxy`, and `proxy-http` accept `--log-format text|json`:

- **`text`** (default) — human-readable stderr diagnostics. `check`'s text
  stderr contract (gate messages, warnings) is preserved byte-for-byte from
  earlier releases. The proxies now route their diagnostics through the shared
  logger, so the wording/prefixes of their stderr lines have changed; do not
  parse proxy text diagnostics — use `json` for stable machine parsing.
- **`json`** — one structured [`log/slog`](https://pkg.go.dev/log/slog) record
  per line, for ingestion by a log pipeline. Recommended whenever stderr is
  consumed by tooling.

```console
$ agentfence proxy-http --policy policy.yaml --upstream https://mcp.example.com --log-format json
{"time":"...","level":"INFO","msg":"listening","addr":"127.0.0.1:8787","upstream":"https://mcp.example.com"}
{"time":"...","level":"ERROR","msg":"upstream request failed","err":"..."}
```

The operational log never mixes into stdout (reserved for decisions / the
JSON-RPC channel) or the audit log.

## Decision metrics

### CLI (`check --metrics`)

`check --metrics` prints a dependency-free decision summary to **stderr** on
exit (so it never pollutes a `--output json` stream on stdout):

```console
$ agentfence check --policy policy.yaml --call calls.jsonl --output json --metrics
... decisions JSON on stdout ...
Decision metrics
  total decisions: 3
  by decision:     allow=1 deny=2 ask=0
  taint escalations: 0
  by reason code:
        1  default_decision
        1  path_denied
        1  rule_match
  by tool:
        2  filesystem.read
        1  github.delete_repo
```

### Proxy Prometheus endpoint (`--metrics-listen`)

`proxy` and `proxy-http` can expose the same counters as a scrapable
[Prometheus](https://prometheus.io/) endpoint with
`--metrics-listen <addr>` (off by default):

```console
$ agentfence proxy-http --policy policy.yaml --upstream https://mcp.example.com \
    --metrics-listen 127.0.0.1:9090
$ curl -s http://127.0.0.1:9090/metrics
# HELP agentfence_decisions_total Tool-call decisions by tool and decision.
# TYPE agentfence_decisions_total counter
agentfence_decisions_total{tool="filesystem.read",decision="allow"} 12
agentfence_decisions_total{tool="github.delete_repo",decision="deny"} 1
# HELP agentfence_reason_codes_total Decisions by stable reason code.
# TYPE agentfence_reason_codes_total counter
agentfence_reason_codes_total{code="path_denied"} 1
agentfence_reason_codes_total{code="rule_match"} 12
# TYPE agentfence_approval_outcomes_total counter
agentfence_approval_outcomes_total{outcome="approval_timeout"} 2
# TYPE agentfence_eval_latency_seconds_count counter
agentfence_eval_latency_seconds_count 13
# TYPE agentfence_errors_total counter
agentfence_errors_total{kind="upstream"} 1
```

Metric families:

| Metric | Labels | Meaning |
|--------|--------|---------|
| `agentfence_decisions_total` | `tool`, `decision` | Decisions per tool and decision class. |
| `agentfence_reason_codes_total` | `code` | Decisions per stable [reason code](audit-event-schema.md#reason-codes). |
| `agentfence_taint_escalations_total` | — | Decisions adjusted by taint tracking. |
| `agentfence_approval_outcomes_total` | `outcome` | Resolved `ask` outcomes (approved / denied / timeout / …). |
| `agentfence_eval_latency_seconds_sum` / `_count` | — | Evaluation latency sum and observation count (mean = sum/count). |
| `agentfence_errors_total` | `kind` | Operational errors (`upstream`, `proxy`, `audit_write`, `unauthenticated`, …). |

The endpoint serves `GET`/`HEAD` only and is dependency-free (no Prometheus
client library is linked into the binary). When the endpoint is enabled, the
proxy also prints the text summary to stderr on shutdown.

> **Security note:** bind `--metrics-listen` to loopback (or an otherwise
> trusted interface). The endpoint exposes tool names and decision volumes; do
> not expose it to untrusted networks. The same applies to `--listen` for the
> proxy itself (see [`threat-model.md`](threat-model.md)).
