# AgentFence policy language

## File structure

```yaml
version: "0.1"
imports:
  - ./base-policy.yaml
defaults:
  decision: deny
groups:
  my-group:
    - tool.one
    - tool.*
tools:
  tool.one:
    decision: allow
redaction:
  enabled: true
  patterns: []
audit:
  format: jsonl
  include_redacted_arguments: true
```

## Decisions

- `allow`: permit action.
- `deny`: block action.
- `ask`: require approval flow.

Successful decisions include a reason that identifies whether the tool matched
an exact policy rule, a named group rule, or a wildcard rule.

## Defaults

`defaults.decision` applies when there is no explicit rule for a tool.

## Tool rules

`tools.<tool_name>.decision` defines a direct rule for a tool call.

Example:

```yaml
tools:
  github.delete_repo:
    decision: deny
```

## Wildcard tool name matching

Tool keys in the `tools` map support glob patterns. `filesystem.*` matches any
tool name starting with `filesystem.`.

```yaml
tools:
  filesystem.*:
    decision: ask
```

Full glob syntax is supported: `*.delete_*` matches any tool containing `.delete_`.

### Rule lookup precedence

1. **Exact match** — `tools.filesystem.read` beats everything else.
2. **Group match** — the tool matches a member pattern of a named group that has a `tools` entry.
3. **Wildcard match** — the tool name matches a glob key in `tools` (alphabetical order when multiple patterns match).
4. **Default** — `defaults.decision`.

## Tool groups

Named groups let you apply one rule to many tools:

```yaml
groups:
  filesystem-tools:
    - filesystem.read
    - filesystem.write
    - filesystem.*   # wildcards work inside group member lists too

tools:
  filesystem-tools:
    decision: ask
```

Group names are just keys in the `tools` map — the group takes precedence over
wildcard keys but not over exact tool-name keys.

## Path constraints

Rules can define path allow/deny constraints:

```yaml
tools:
  filesystem.write:
    decision: ask
    constraints:
      paths:
        allow:
          - "./src/**"
        deny:
          - ".env"
          - "**/secrets/**"
```

Behavior:

- Deny path matches always deny.
- If allow list exists, path must match at least one allow pattern.
- Absolute paths, UNC paths, and directory traversal (`../`) are always denied
  whenever a string `path` argument is present, even if `constraints.paths` is
  omitted.

## Argument value constraints

Restrict any string-valued argument field with glob allow/deny lists:

```yaml
tools:
  github.create_issue:
    decision: ask
    constraints:
      args:
        repo:
          allow:
            - "dgenio/*"
            - "myorg/*"
          deny:
            - "dgenio/private-*"
```

Behavior:

- Deny patterns take precedence over allow patterns.
- If an argument named in a constraint is missing from the call, the call is denied.
- Non-string values are converted to string (`fmt.Sprintf("%v", v)`) before matching.

## URL constraints

Restrict browser and HTTP tools to specific domains and schemes:

```yaml
tools:
  browser.navigate:
    decision: allow
    constraints:
      urls:
        allow:
          - "https://docs.github.com/**"
          - "https://*.company.com/**"
        deny:
          - "http://**"
```

Security hard-bans (cannot be overridden by the allow list):

- `file://` scheme is always denied.
- Bare IP address hostnames (e.g. `https://192.168.1.1`) are always denied.
- An invalid or missing `url` argument is denied.

## Shell command constraints

Restrict shell and terminal tools by executable name and command pattern:

```yaml
tools:
  shell.exec:
    decision: ask
    constraints:
      command:
        allow_executables:
          - "git"
          - "go"
          - "make"
        deny_patterns:
          - "rm -rf*"
          - "curl * | bash"
```

Behavior:

- `deny_patterns` are glob-matched against the full command string.
- `allow_executables` checks only the first whitespace-separated token.
- Deny takes precedence over allow.
- A missing or empty `command` argument is denied.

> **WARNING:** This is a best-effort guardrail only — not a sandbox. Shell
> metacharacters (`|`, `;`, `&&`, `$()`) can bypass `allow_executables` and
> `deny_patterns` checks. Do not rely on this as a security boundary.

## Durable memory-write constraints

Agents that write to durable memory can persist information across sessions —
incorrect assumptions, sensitive data, project secrets. The `memory_write`
constraint family lets a policy reason about scope, payload sensitivity, and
size before a memory write is allowed.

```yaml
tools:
  memory.write:
    decision: ask
    constraints:
      memory_write:
        max_scope: project        # session < project < global
        max_sensitivity: medium   # low < medium < high
        max_bytes: 1024
        payload_fields:           # optional; defaults to [value, content]
          - value
          - content
```

A rule opts in to memory-write evaluation when any of `max_scope`,
`max_sensitivity`, `max_bytes`, or `payload_fields` is set. The constraint
is generic across tool names: `memory.write`, `agentmemory.write`,
`notes.store` — anything you wire into your policy.

Evaluation rules:

- **Scope** is read from the call's `scope` argument (defaults to `session`).
  A scope broader than `max_scope` is denied.
- **Sensitivity** is the higher of the call's explicit `sensitivity`
  argument and the redactor's auto-classification (any redaction pattern
  match → `high`). A sensitivity above `max_sensitivity` is denied.
- **Size** is the byte length of the first non-empty payload field. A
  payload larger than `max_bytes` (when `max_bytes > 0`) is denied.
- **Missing payload** in every configured payload field is denied.

Every memory-write evaluation — allow, deny, or ask — adds a
`memory_write` summary to the audit event so downstream tools can see
scope, sensitivity, payload size, and a SHA-256 fingerprint of the
payload without ever logging the payload itself. See the audit schema
below.

## Policy imports

Share rules across projects by importing other policy files:

```yaml
imports:
  - ./base-policy.yaml
  - ./team-overrides.yaml
```

Behaviour:

- Paths are relative to the importing file and may not escape its
  directory (no absolute paths, no `../` past the directory root).
- Import depth is capped at three levels below the root policy.
- Circular imports are detected via canonicalized absolute paths and
  rejected with an error naming the cycle.
- The importing policy's explicit rules override anything inherited:
  `tools` and `groups` are merged with the importing file winning on key
  conflicts; `defaults.decision` and `audit.format` follow the same rule.
- `redaction.patterns` are unioned (every layer's regex runs).
- `redaction.enabled` and `audit.include_redacted_arguments` follow OR
  semantics — once any layer enables them they stay enabled.
- When two sibling imports define the same tool key, the later import
  wins (consistent with the override pattern).

See [`examples/base-policy.yaml`](../examples/base-policy.yaml) and
[`examples/project-policy.yaml`](../examples/project-policy.yaml) for a
worked example.

## Redaction patterns

Regex patterns can redact sensitive-looking values before audit logging:

```yaml
redaction:
  enabled: true
  patterns:
    - name: github_token
      regex: "gh[pousr]_[A-Za-z0-9_]{20,}"
```

## Validation

Use `agentfence validate` (or `agentfence policy validate`) to lint a policy file:

```bash
agentfence validate --policy examples/policy.yaml
# examples/policy.yaml: OK

agentfence policy validate --policy bad-policy.yaml
# bad-policy.yaml: defaults.decision: must be one of allow, deny, ask (got "maybe")
```

All commands that load a policy reject unknown fields. `validate` also reports
semantic issues such as invalid decisions and bad regexes before the policy is
used.

## Policy testing

Write declarative test fixtures to verify policy behavior:

```yaml
# examples/policy-tests.yaml
tests:
  - id: allow-readme-read
    tool: filesystem.read
    arguments:
      path: README.md
    expect: allow
  - id: deny-env-write
    tool: filesystem.write
    arguments:
      path: .env
    expect: deny
```

Run with:

```bash
agentfence policy test --policy examples/policy.yaml --tests examples/policy-tests.yaml
# PASS: allow-readme-read
# PASS: deny-env-write

agentfence policy test --policy examples/policy.yaml --tests examples/policy-tests.yaml --verbose
# PASS: allow-readme-read (tool filesystem.read matched explicit policy rule)
```

- Exit code 0 when all tests pass.
- Exit code 1 when any test fails; all tests are always run.

## CI usage

Use `--fail-on` to make `check` exit 1 when gated decisions are encountered:

```bash
# Fail the pipeline if any tool call is denied or requires approval.
agentfence check --policy agentfence.yaml --call tool-calls.jsonl --fail-on deny,ask

# Fail only on outright denials.
agentfence check --policy agentfence.yaml --call tool-calls.jsonl --fail-on deny
```

## Explain command

Debug why a tool call received its decision:

```bash
agentfence explain --policy examples/policy.yaml \
  --tool filesystem.write \
  --args '{"path":".env"}'

# tool:     filesystem.write
# decision: deny
# reason:   path ".env" denied by pattern ".env"
# trace:
#   - matched rule "filesystem.write" (decision: ask)
#   - checking path constraints for ".env" (normalized: ".env")
#   - path ".env" denied by pattern ".env"

# Machine-readable output:
agentfence explain --policy examples/policy.yaml --tool filesystem.write \
  --args '{"path":".env"}' --output json
# {
#   "tool": "filesystem.write",
#   "decision": "deny",
#   "reason": "path \".env\" denied by pattern \".env\"",
#   "trace": [...]
# }
```

## Audit event schema

Each evaluated call produces one JSONL audit event with the following fields
(schema version `2`):

| Field            | Type    | Description |
|------------------|---------|-------------|
| `schema_version` | string  | On-wire schema identifier. Currently `"2"`. |
| `session_id`     | string  | UUIDv4 generated once per `agentfence` run. |
| `seq`            | integer | Monotonic 1-based sequence number within the session. |
| `timestamp`      | string  | RFC 3339 nano UTC timestamp of the decision. |
| `call_id`        | string  | The tool call's `id` from the input. |
| `tool`           | string  | The tool name. |
| `decision`       | string  | `allow`, `deny`, or `ask`. |
| `reason`         | string  | Human-readable explanation. |
| `arguments`      | object  | Redacted arguments (omitted when `audit.include_redacted_arguments` is false). |
| `mode`           | string  | Optional evaluation-mode marker. Currently `"dry_run"` for dry-run events; omitted for enforced events. |
| `memory_write`   | object  | Safe summary of a durable memory-write call. Only present when the matched rule has `constraints.memory_write` set. Contains `scope`, `sensitivity`, `field`, `size_bytes`, `content_fingerprint`, and `patterns_matched`. Never includes the raw payload. |
| `prev_hash`      | string  | Previous event's `hash`. Only present when `--tamper-evident` is set. Omitted for the first event in a chain. |
| `hash`           | string  | This event's SHA-256 (hex). Only present when `--tamper-evident` is set. |

### Tamper-evident chaining

Run `agentfence check --tamper-evident --audit-log audit.jsonl ...` to write
events with a SHA-256 hash chain, then verify integrity with:

```bash
agentfence audit verify --log audit.jsonl
# OK: 42 event(s) verified
```

A modified or deleted event causes verification to exit non-zero with the
1-based event number that failed. A non-chained log produces a warning rather
than an error. A *mixed* log — one whose chain does not cover every event —
exits non-zero with a `PARTIAL` summary, e.g.:

```text
PARTIAL: 5 event(s); chain starts at event 3; events 1..2 are not integrity-protected
```

This makes it impossible for `audit verify` to silently report `OK` on a log
whose prefix is unprotected. See
[`docs/threat-model.md`](threat-model.md#audit-log-integrity) for the threat
model.

`--audit-log` opens logs in append mode and creates new files with owner-only
permissions on Unix (`0600`). When `--tamper-evident` appends to an existing
chained log, the next event links to the previous event's hash so verification
continues across runs. To preserve full-log integrity, `--tamper-evident` is
**refused** on a non-empty log that has no chain at all — converting an
unchained log mid-stream would produce exactly the mixed log the verifier
flags as `PARTIAL`. Rotate the log (move or archive the current file) before
enabling `--tamper-evident`.

## Complete example

See [examples/policy.yaml](../examples/policy.yaml) for a full starter policy and
[examples/policy-tests.yaml](../examples/policy-tests.yaml) for a matching test fixture.

