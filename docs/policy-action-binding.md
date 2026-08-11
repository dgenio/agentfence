# Policy and approval action binding

> **Status:** design proposal for [#222](https://github.com/dgenio/agentfence/issues/222). The only runtime hardening already implemented from this work is [#229](https://github.com/dgenio/agentfence/pull/229), which prevents a late TTY response to a timed-out call from approving a later call.

AgentFence should be able to answer two forensic questions unambiguously:

1. **Which effective policy made this decision?**
2. **Which exact action did the operator approve?**

Today the engine loads a resolved policy and evaluates a concrete `ToolCall`, but the public audit event does not identify the effective policy content and the interactive prompt displays only the tool name and call ID. The current approval path is synchronous and does not issue reusable approval tokens, which limits replay risk, but the human still needs an explicit, stable binding to the exact action under review.

This design defines that binding without turning AgentFence into an identity provider or a secrets-bearing approval UI.

## Security invariants

### P-01 — decision-to-policy binding

Every enforced decision should be attributable to a deterministic digest of the **effective resolved policy** that the engine actually evaluated.

If imports change the effective policy, the digest changes. Two source graphs that resolve to the same effective semantics may share the same effective-policy digest; optional source-manifest evidence can distinguish provenance/configuration history separately if needed.

### P-02 — approval-to-action binding

An approval for action A must never authorize action B.

The binding must cover the exact policy-relevant action representation, not only a human-readable tool name or request ID.

### P-03 — policy change invalidates approval

If the effective policy changes between approval and execution, the approval is no longer valid for that execution.

The current synchronous in-process flow should make this a simple invariant: policy is loaded into the engine before evaluation and no reusable approval is cached. Future remote/cached approval mechanisms must preserve the same rule explicitly.

### P-04 — argument change invalidates approval

If any canonical action field changes after approval, the action digest changes and a new approval is required.

### P-05 — stale/late input cannot cross calls

A terminal response received after call A timed out/cancelled belongs to A and must never be reinterpreted as approval for call B.

This invariant is implemented by #229.

### P-06 — approval display does not leak secrets

The operator should see enough information to make an informed decision, but AgentFence must not dump raw secret-bearing arguments to the terminal or audit solely for approval UX.

### P-07 — policy/configuration protection is a deployment responsibility

AgentFence cannot protect a policy file from an agent that has an independent OS/native path capable of rewriting that policy. Documentation and preflight must make that deployment boundary explicit.

The runtime should still make policy identity visible so a changed policy is detectable in receipts/review.

## Effective policy digest

`policy.LoadFile` already resolves imports, applies merge precedence, clears the `Imports` field, and reapplies defaults before constructing the engine. That resolved `policy.Policy` is therefore the correct semantic object to fingerprint.

### Canonical semantic projection

Do not hash the original YAML bytes:

- YAML comments/whitespace are not policy semantics;
- imports may be reordered or refactored while resolving to the same policy;
- defaults must be represented in their effective form;
- a digest should follow what the engine evaluates, not how the author formatted it.

Define a versioned canonical JSON projection of the resolved policy containing every evaluation-relevant field:

```text
version
defaults
groups
tools + all constraints
redaction configuration
audit include-arguments behavior where it changes generated evidence
taint configuration
```

Whether purely output-format fields such as `audit.format` belong in the **authorization** digest or a separate evidence/config digest should be decided explicitly. A conservative first version can hash the complete resolved `Policy` structure, then split semantic/evidence digests later only with a version bump.

### Canonicalization

Requirements:

- map key order must not affect the digest;
- YAML formatting/comments must not affect the digest;
- explicit defaults and omitted values that resolve identically must produce the same digest;
- equivalent import graphs that resolve to the same effective `Policy` must produce the same digest;
- the canonicalization version is public contract metadata;
- SHA-256 is sufficient for content identity once the canonical bytes are defined.

Candidate identifier:

```text
agentfence-policy-v1:sha256:<hex>
```

Do not expose a bare digest without the canonicalization/version prefix once it becomes a durable public artifact.

## Action digest

The action digest should bind the policy-relevant request without logging raw secrets.

### Current request representation

The existing engine evaluates:

```go
policy.ToolCall{
    ID:        callID,
    Tool:      toolName,
    Arguments: arguments,
}
```

`ID` is correlation evidence, not authority. Two otherwise identical actions with different JSON-RPC request IDs should normally have the same semantic action digest.

The v1 action projection should therefore cover:

```text
canonical tool name
canonical full arguments object
```

and, once #221 lands:

```text
upstream reference/config identity
tool descriptor identity
```

The **approval binding** combines action and policy identity:

```text
action_digest
+ effective_policy_digest
+ upstream/tool identity evidence when available
--------------------------------
approval_binding_digest
```

A session/call ID can be recorded alongside that digest and can be part of a future one-shot token envelope, but it should not replace content binding.

### Secret handling

Compute the action digest from the canonical **raw** argument values so a secret/value change invalidates the approval. Store only the digest in normal audit/approval metadata.

Separately produce a redacted human display using the existing redactor. The redacted display is for operator understanding; it is not the cryptographic/content identity of the action.

This lets AgentFence say:

```text
human saw:   filesystem.write {path:".env", content:"[REDACTED:...]"}
action id:   sha256:abc...
policy id:   sha256:def...
```

without putting the secret into the receipt.

## Approval request contract

The current `Approver` interface accepts only `policy.ToolCall`:

```go
Request(ctx context.Context, call policy.ToolCall) (bool, error)
```

A future implementation slice should replace this with an explicit immutable request value, for example conceptually:

```go
type Request struct {
    Call              policy.ToolCall
    RedactedArguments map[string]interface{}
    ActionDigest      string
    PolicyDigest      string
    UpstreamRef       string // optional until #221
    DescriptorDigest  string // optional until #221
}
```

Exact types/names are implementation details. The important property is that the approver receives the same bound evidence that will be recorded and checked before forwarding.

## TTY approval UX

The current prompt:

```text
AgentFence: approve filesystem.write [c2]? (y/N):
```

is insufficiently informative for high-risk actions.

A bounded future prompt should show a redacted deterministic summary:

```text
AgentFence approval
  call:    c2
  tool:    filesystem.write
  args:    {"content":"[REDACTED:generic_secret_assignment]","path":".env"}
  action:  sha256:abc123...
  policy:  sha256:def456...
approve? (y/N):
```

Requirements:

- serialized redacted arguments are deterministic so repeated prompts are reviewable;
- output is size-bounded; large payloads use a safe summary plus action digest rather than flooding the terminal;
- secret patterns are applied before display;
- malformed/unserializable display data fails closed rather than falling back to raw values;
- the approval digest shown is the same digest recorded in the audit event.

## Execution invariant after approval

For an approved call, the proxy should forward only the exact original request whose parsed/canonical action produced the approval binding.

Current proxies evaluate parsed request data and forward the original request frame/body on allow. Implementation should pin this with tests:

1. parse original request;
2. compute action digest from parsed semantics;
3. evaluate policy and obtain policy digest;
4. request approval over that binding;
5. immediately before forwarding, assert the stored binding still corresponds to the call/request being forwarded;
6. write the resolved audit event before forwarding, preserving the current audit-before-side-effect invariant.

There should be no mutable shared `map` or other caller-accessible object that can alter approved arguments between steps 3 and 5 without changing/rechecking the digest.

## Current late-response fix

Before #229, `TTYApprover` deliberately reused an in-flight terminal read after timeout. A late `y` for call A could therefore become the response consumed by call B.

#229 changes the invariant:

```text
call A prompt
  -> timeout/deny
  -> old read may still complete
  -> next Request drains/discards A's response
  -> only then display call B prompt
  -> only fresh B response can approve B
```

This is fail-closed even though blocking terminal reads cannot be cancelled portably.

## Future reusable/remote approvals

AgentFence does not currently issue reusable approval tokens. If it ever adds a remote UI, cached approvals, policy-based grants derived from human decisions, or another asynchronous mechanism, the token/grant must contain or authenticate at least:

```text
approval_binding_digest
issued_at
expires_at
one_shot / reuse scope
approver identity evidence where the channel actually authenticates it
nonce / unique approval id
```

and verification must reject:

- expired approval;
- already-consumed one-shot approval;
- action digest mismatch;
- policy digest mismatch;
- upstream/tool identity mismatch when #221 evidence is required;
- missing/invalid authenticating evidence for a channel that claims authenticated approval.

Do not add a general-purpose approval cache before this contract exists.

## Audit schema additions

Once implemented, an enforced event should be able to expose safe evidence such as:

```json
{
  "policy_digest": "agentfence-policy-v1:sha256:...",
  "action_digest": "agentfence-action-v1:sha256:...",
  "approval": {
    "required": true,
    "outcome": "approved",
    "binding_digest": "agentfence-approval-v1:sha256:...",
    "channel": "tty"
  }
}
```

The existing human `reason` and stable `reason_code` remain useful; these fields answer a different question: **what exact configuration/action did the record refer to?**

Adding these fields requires an audit schema-version bump, JSON Schema update, schema drift tests, example receipt updates, and downstream/interop review.

Do not record an `approver_identity` for local TTY unless the channel actually authenticates a human identity. `channel: tty` describes the mechanism, not who typed `y`.

## Policy file placement / self-modification

Within one running engine today, the resolved policy is loaded into memory before evaluation; rewriting the source file does not transparently rewrite that in-memory policy. The larger deployment risk is the next run/restart, or another configuration reload mechanism in the future.

`doctor` / deployment guidance in #89 should therefore warn when:

- the policy or imported policy files live inside a workspace the protected agent can modify through an unmediated/native capability;
- parent-directory permissions make replacement trivial;
- a symlink/config path resolves into an agent-writable area;
- the active policy digest differs from an operator-expected/pinned value when such a pin is configured.

These are best-effort diagnostics, not a replacement for filesystem ACLs, containers, read-only mounts, or deployment separation.

## Implementation slices

### Slice A — pure policy/action canonicalization

- add versioned canonical effective-policy digest;
- add versioned canonical action digest;
- unit/fuzz/property tests for map order, omitted/default fields, import equivalence, numeric/string distinctions, nested argument maps/arrays;
- no audit schema change yet.

### Slice B — audit evidence

- add policy/action digest fields to audit events;
- bump audit schema;
- update JSON Schema, schema drift guard, fixtures, summaries/interop where applicable;
- verify raw secret values never appear solely because digesting was added.

### Slice C — approval request binding

- introduce explicit bound approval request value;
- show size-bounded redacted args + action/policy digest in TTY prompt;
- tests prove argument/policy mutation requires a new binding;
- keep #229 stale-response invariant.

### Slice D — identity + preflight integration

- include #221 upstream/tool identity evidence in the action/approval binding;
- expose active policy digest and policy-placement warnings through #89;
- update #214 real integration walkthrough.

### Slice E — external review

- include the canonicalization/binding and terminal concurrency behavior in #223's independent review scope.

## Required tests

### Effective policy

- YAML comments/whitespace do not change digest;
- map key order does not change digest;
- omitted defaults vs explicitly equivalent defaults -> same digest;
- two import graphs resolving to the same policy -> same digest;
- effective rule/constraint/redaction/taint change -> different digest;
- malformed/unknown policy never yields an apparently valid digest.

### Action

- JSON argument key order -> same digest;
- array order -> different digest;
- number vs string -> different digest;
- nested secret value change -> different digest while audit/display remains redacted;
- call/request ID change alone -> same semantic action digest unless a future token envelope deliberately binds the one-shot request ID separately.

### Approval

- approved binding A cannot authorize B;
- argument change after prompt invalidates/requires new approval;
- policy change invalidates/requires new approval;
- late response after timeout cannot approve next call (#229 regression);
- stale-input drain timeout fails closed;
- prompt never emits raw redacted secrets;
- prompt uses deterministic/size-bounded display.

## Open design questions before Slice A/B become public contract

1. Use an AgentFence-specific deterministic JSON encoder or a published canonical JSON standard for policy/action digests?
2. Should `audit.format` and other evidence-only policy fields be part of the primary effective-policy digest or a separate configuration digest?
3. Should the audit event store `action_digest` on every decision, or only when approval/identity binding is active?
4. What maximum redacted argument display size keeps TTY approval useful without creating terminal/log DoS?
5. Should an operator be able to pin an expected policy digest at startup, and if so should mismatch be a hard startup failure or a configurable preflight/enforcement mode?

The implementation should resolve these narrowly. The goal is not a new approval platform; it is a precise binding between the existing deterministic decision, the exact action, and the human approval path.
