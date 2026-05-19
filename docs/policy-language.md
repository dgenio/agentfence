# AgentFence policy language (MVP)

## File structure

```yaml
version: "0.1"
defaults:
  decision: deny
tools:
  filesystem.read:
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
- `ask`: require approval flow (simulated in MVP).

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

Use `agentfence validate` to lint a policy file before using it:

```bash
agentfence validate --policy examples/policy.yaml
# examples/policy.yaml: OK

agentfence validate --policy bad-policy.yaml
# bad-policy.yaml: defaults.decision: must be one of allow, deny, ask (got "maybe")
```

Strict validation catches:

- **Unknown fields** — typos in field names (e.g. `decisoin` instead of `decision`) that would otherwise be silently ignored
- **Invalid decision values** — any value other than `allow`, `deny`, or `ask`
- **Invalid redaction regexes** — patterns that fail to compile
- **Invalid audit format** — any format other than `jsonl`
- **Missing `version` field** — required for future compatibility checks

All errors are reported together (not just the first). Exit code is 0 on success, 1 on any validation error.

Use in CI to catch policy mistakes before deployment:

```bash
agentfence validate --policy agentfence.yaml || exit 1
```

## Complete example

See `/examples/policy.yaml` for a full starter policy.
