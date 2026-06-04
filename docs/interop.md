# Weaver Stack interop: exporting audit traces

AgentFence is the **external policy edge** of the [Weaver Stack](../README.md#part-of-the-weaver-stack).
Its native audit log is a rich stream of decision records (allow / deny / ask,
reasons, tools, redaction). Those records are exactly the kind of trace that
Weaver Stack consumers — notably **lessonweaver** — turn into reviewed policy
lessons: recurring `deny`/`ask` patterns are evidence that a policy (or an
agent's behaviour) needs attention.

`agentfence audit export` emits those records in the
[weaver-spec](https://github.com/dgenio/weaver-spec) shared trace shape so the
loop **AgentFence findings → lessonweaver → reviewed policy lessons** can run
without bespoke glue.

- **Targeted contract:** weaver-spec **v0** (contract release **0.6.0**).
- **Additive:** the native JSONL audit format is unchanged. Export is a
  separate, read-only view.
- **No hard dependency:** export works from a serialized audit log; AgentFence
  has no build- or run-time dependency on any sibling repository.

## Usage

```bash
# Write a tamper-evident native audit log as usual.
agentfence check --policy policy.yaml --call calls.jsonl \
  --audit-log audit.jsonl --tamper-evident

# The native chain stays verifiable.
agentfence audit verify --log audit.jsonl

# Export the same records as a weaver-spec-aligned trace stream.
agentfence audit export --log audit.jsonl > weaver-trace.jsonl
```

`--format` defaults to `weaver-trace` (currently the only supported format).

## Output shape

For each native audit event the exporter writes **two** JSONL lines:

1. a [`PolicyDecision`](https://github.com/dgenio/weaver-spec/blob/main/contracts/json/policy_decision.schema.json)
   — the authorization verdict, and
2. a matching [`TraceEvent`](https://github.com/dgenio/weaver-spec/blob/main/contracts/json/trace_event.schema.json)
   — the audit-log entry,

linked by a shared `decision_id`. This satisfies weaver-spec **invariant I-02**
("every PolicyDecision has a matching TraceEvent"). A consumer distinguishes the
two by the `event_type` field (present only on `TraceEvent`).

```json
{"decision_id":"pd-demo-2","decision":"deny","capability_id":"filesystem.write","principal":"demo","reason":"path .env matches deny pattern","timestamp":"2026-05-01T10:00:01Z","metadata":{"agentfence_decision":"deny","agentfence_schema_version":"1","audit_log_sequence":2}}
{"event_id":"te-demo-2","event_type":"capability_denied","timestamp":"2026-05-01T10:00:01Z","capability_id":"filesystem.write","principal":"demo","decision_id":"pd-demo-2","outcome":"failure","metadata":{"agentfence_decision":"deny","agentfence_schema_version":"1","audit_log_sequence":2}}
```

A full example is in [`examples/weaver-trace.jsonl`](../examples/weaver-trace.jsonl).

## Field mapping

| AgentFence audit `Event` | weaver-spec `PolicyDecision` | weaver-spec `TraceEvent` |
|--------------------------|------------------------------|--------------------------|
| `session_id` + `seq`     | `decision_id` = `pd-<session>-<seq>` | `event_id` = `te-<session>-<seq>`; `decision_id` links to the PolicyDecision |
| `tool`                   | `capability_id`              | `capability_id` |
| `session_id`             | `principal`                  | `principal` |
| `decision`               | `decision` (see projection below) | `event_type` (see projection below) |
| `decision`               | —                            | `outcome` |
| `reason`                 | `reason`                     | — |
| `timestamp`              | `timestamp`                  | `timestamp` |
| `decision`, `seq`, `mode`, `schema_version`, `prev_hash`, `hash`, `memory_write` | `metadata.*` | `metadata.*` |

Notes:

- **`tool` is empty** (e.g. a synthetic parse-error deny event) → `capability_id`
  is set to `agentfence.unknown`, because weaver-spec requires a non-empty
  `capability_id`.
- **`principal`**: AgentFence has no principal/identity model, so the audit
  `session_id` is used as the closest stable "who".
- **Chain integrity**: the source event's `prev_hash`/`hash` are carried into
  `metadata`, so an exported trace can be cross-checked against the native,
  hash-chained log without the exporter ever touching that log.

### The allow / deny / ask projection

weaver-spec's `PolicyDecision.decision` enum is **`allow` | `deny`** only, and
its authorization event types are `capability_authorized` / `capability_denied`.
AgentFence has a third decision, **`ask`** (escalate for human approval), with no
weaver-spec equivalent. It is projected conservatively:

| AgentFence `decision` | `PolicyDecision.decision` | `TraceEvent.event_type` | `TraceEvent.outcome` | extra metadata |
|-----------------------|---------------------------|-------------------------|----------------------|----------------|
| `allow`               | `allow`                   | `capability_authorized` | `success`            | — |
| `deny`                | `deny`                    | `capability_denied`     | `failure`            | — |
| `ask`                 | `deny`                    | `capability_denied`     | `partial`            | `escalation: "ask"` |

`ask` maps to `deny` because an unresolved approval is **not** an unattended
authorization. The original decision is always preserved verbatim in
`metadata.agentfence_decision`, so no information is lost — a consumer that
understands escalation can recover the `ask` semantics, while a strict
weaver-spec consumer sees a safe `deny`.

## Feeding lessonweaver

The exported stream is plain JSONL of weaver-spec artifacts, so it can be piped
straight into any consumer of the trace contract:

```bash
# Surface recurring deny/ask patterns from a day of AgentFence decisions.
agentfence audit export --log audit.jsonl \
  | lessonweaver ingest --format weaver-trace
```

(Exact lessonweaver invocation depends on that tool; the contract is the
`PolicyDecision` / `TraceEvent` shape above.)

## Limitations

- The export is a **stream of `PolicyDecision` + `TraceEvent`**, not a
  [`TraceBundle`](https://github.com/dgenio/weaver-spec/blob/main/contracts/json/extended/trace_bundle.schema.json).
  A `TraceBundle` requires a `RoutingDecision`, `Frame`s, and `Handle`s, which an
  external policy edge does not produce — those are agent-kernel concepts.
- A malformed line in the source log aborts the export with the offending line
  number rather than being silently dropped: an audit export must be faithful.
