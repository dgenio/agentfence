# Audit event schema

AgentFence writes its audit log as [newline-delimited JSON](https://jsonlines.org/)
(JSONL): one self-contained JSON object per line. The log is the project's
integration surface — it feeds `audit summarize`, `audit verify`, the
weaver-trace export, and any external sink or SIEM you point at it.

This page is the human-readable reference. The machine-readable contract lives
at [`schema/agentfence-audit-event.schema.json`](../schema/agentfence-audit-event.schema.json)
(JSON Schema, draft 2020-12). A unit test
(`internal/audit/schema_test.go`) fails the build if the schema and the Go
`audit.Event` struct ever drift apart, so the two cannot diverge silently.

## Using the schema

Validate a log with any JSON Schema validator, for example
[`check-jsonschema`](https://github.com/python-jsonschema/check-jsonschema):

```bash
# Each line is one event; validate them individually.
while IFS= read -r line; do
  printf '%s' "$line" | check-jsonschema --schemafile schema/agentfence-audit-event.schema.json /dev/stdin
done < audit.jsonl
```

Editors that understand `$schema` can also offer completion and inline
validation when authoring fixtures.

## Fields

| Field | Type | Always present | Description |
|-------|------|----------------|-------------|
| `schema_version` | string | yes | Event schema version. Current writers emit `"4"`. |
| `session_id` | string | yes | Per-run session identifier (UUIDv4 unless overridden). |
| `seq` | integer | yes | Monotonic 1-based sequence within the session. |
| `timestamp` | string | yes | Event time, RFC 3339 / RFC 3339 Nano (UTC). |
| `call_id` | string | yes | Evaluated tool-call ID. `line-N` for parse-error events. |
| `tool` | string | yes | Tool name. Empty for parse-error events. |
| `decision` | string | yes | One of `allow`, `deny`, `ask`. |
| `reason` | string | yes | Human-readable explanation. |
| `reason_code` | string | no | Stable, machine-readable classification of the decision (e.g. `path_denied`, `url_bare_ip`, `taint_escalated`, `approval_timeout`). Mirrors `reason` for reliable grouping; absent on pre-`"4"` events. See [Reason codes](#reason-codes). |
| `arguments` | object | no | Redacted tool-call arguments (only when argument logging is on). |
| `memory_write` | object | no | Safe summary of a durable memory-write call (never the raw payload). |
| `mode` | string | no | `dry_run` for simulated events; absent for enforced events. |
| `prev_hash` | string | no | Hex SHA-256 of the previous event in a tamper-evident chain; empty on a chain root. |
| `hash` | string | no | Hex SHA-256 of this event's canonical encoding; present only in tamper-evident mode. |
| `signature` | string | no | Base64 Ed25519 signature over the event's canonical digest; present only when signing is enabled. |

### `memory_write` object

| Field | Type | Always present | Description |
|-------|------|----------------|-------------|
| `scope` | string | no | Effective durable-write scope: `session`, `project`, `global`. |
| `sensitivity` | string | no | Resolved sensitivity: `low`, `medium`, `high`. |
| `field` | string | no | Argument key that held the durable payload. |
| `size_bytes` | integer | yes | Byte length of the payload as evaluated. |
| `content_fingerprint` | string | no | Short SHA-256 prefix of the payload; never reveals contents. |
| `patterns_matched` | array of string | no | Redaction-pattern names that matched the payload. |

## Reason codes

Every evaluated decision carries a stable `reason_code` alongside the
human-readable `reason`. The free-text `reason` is for an operator reading a
log; the `reason_code` is for machines — `audit summarize` groups by it, the
metrics counters key off it, and any downstream alerting can match it without
parsing prose that may be reworded.

Codes are stable identifiers (defined in
[`internal/policy/reasoncode.go`](../internal/policy/reasoncode.go)); a value,
once shipped, does not change. The current set:

| Code | Meaning |
|------|---------|
| `rule_match` | A rule matched and all of its constraints passed; the decision is the rule's own. |
| `default_decision` | No rule matched; the policy default was applied. |
| `path_missing` / `path_unsafe` / `path_denied` / `path_not_allowed` | Path-constraint outcomes. |
| `arg_missing` / `arg_denied` / `arg_not_allowed` | Argument-constraint outcomes. |
| `url_missing` / `url_invalid` / `url_file_scheme` / `url_bare_ip` / `url_denied` / `url_not_allowed` | URL-constraint outcomes. |
| `command_missing` / `command_empty` / `command_denied` / `command_executable_not_allowed` | Command-constraint outcomes. |
| `memory_scope_invalid` / `memory_scope_exceeded` / `memory_payload_missing` / `memory_size_exceeded` / `memory_sensitivity_invalid` / `memory_sensitivity_exceeded` | Memory-write-constraint outcomes. |
| `taint_escalated` / `taint_denied` | A decision adjusted by taint tracking. |
| `approval_approved` / `approval_denied` / `approval_timeout` / `approval_cancelled` / `approval_io_error` / `non_interactive_denied` | Resolution of an `ask` decision by an approver. |
| `parse_error` | Synthetic deny for an input line that could not be parsed. |

## Canonical digest (hash and signature)

Both `hash` and `signature` attest the **same canonical bytes**: the JSON
encoding of the event with its `hash` and `signature` fields cleared. Go's
`encoding/json` emits struct fields in declaration order and sorts map keys, so
the encoding is deterministic for a given logical event.

- `hash` is the hex SHA-256 of those bytes; `prev_hash` links it to the
  previous event, forming the tamper-evident chain.
- `signature` is the base64 Ed25519 signature over the same SHA-256 digest.
  Because it is computed with `hash` cleared, signing and chaining compose: a
  signed, chained event verifies under both `audit verify` and
  `audit verify --pubkey`.

See [`threat-model.md`](threat-model.md#audit-log-integrity) for how these
combine to detect tampering, deletion, and writer impersonation.
