# MCP server/tool identity binding

> **Status:** design proposal for [#221](https://github.com/dgenio/agentfence/issues/221). Nothing in this document should be read as an implemented guarantee until the corresponding runtime work lands.

AgentFence currently authorizes a mediated request primarily from the submitted tool name, arguments, and policy. That is not enough for a strong authorization claim: a different server or changed tool descriptor can keep the same tool name and silently inherit a grant intended for something else.

This design defines the evidence AgentFence should bind to before it describes a decision as authorizing an **identified capability**.

## Protocol constraints

The design must work with current MCP rather than assuming a client always performs discovery first.

MCP `2026-07-28` is stateless: every request is self-describing, the old mandatory initialize/session handshake is gone, and `server/discover` is optional. Streamable HTTP exposes protocol version, method, and tool name in headers so gateways can route/authorize without parsing the body. List results are cacheable and deterministic. A client may also already possess a tool definition and issue a call without a fresh `tools/list` round trip.

Primary references:

- https://blog.modelcontextprotocol.io/posts/2026-07-28/
- https://modelcontextprotocol.io/specification/draft/server/tools
- https://ts.sdk.modelcontextprotocol.io/v2/migration/support-2026-07-28

Consequences for AgentFence:

1. `Mcp-Name` / the `tools/call.params.name` string is useful routing evidence, not capability identity by itself.
2. Passive observation of `tools/list` is useful but cannot be the only way to establish a descriptor.
3. An authorization deployment that requires descriptor binding needs an explicit operator-owned pin/lock path for clients that call from preloaded definitions.
4. Authentication and enterprise identity remain surrounding MCP/IAM responsibilities. AgentFence consumes trustworthy identity context where available; it does not mint its own identity system.

## Threats this contract addresses

### Same name, different upstream

A policy grants `filesystem.write`, but the configured upstream is replaced or redirected to a different server exposing the same name.

### Descriptor drift

A server keeps a tool name but changes its description, input schema, output schema, annotations, extension metadata, or other descriptor fields in a way that changes what the tool means or what the model is encouraged to send.

### Stale discovery

The operator reviews one descriptor while the client or proxy uses a cached/changed server definition later.

### Wrapper/package drift

A stdio command remains textually identical but resolves to a different local executable, package version, or wrapper behavior.

### Header/body inconsistency

For modern HTTP, the request-visible `Mcp-Name`/method/protocol headers disagree with the JSON-RPC body.

### Silent repinning

A mismatch is treated as a normal upgrade and the new capability automatically inherits the old grant.

## What this contract does not prove

A stable digest does **not** prove that an implementation is benign, vulnerability-free, or published by a trustworthy party. It only lets AgentFence say that the capability evidence it evaluated matches evidence the operator previously reviewed/pinned.

This is identity **binding**, not software provenance or code signing.

## Evidence model

The runtime should distinguish evidence instead of flattening everything into one `tool_id` string.

### 1. Upstream reference

An operator-owned reference for the server boundary AgentFence is configured to mediate.

Suggested fields:

```text
transport                 stdio | http
upstream_ref              stable operator name
upstream_config_sha256    digest of canonical non-secret connection config
```

For stdio the canonical connection config should cover at least the configured command and argv. Environment values that are credentials must never be copied into the lock or receipt; the canonical representation may include environment **names** where relevant without secret values.

Where the executable resolves to a local file, AgentFence may additionally record an optional binary digest as stronger local evidence. It must not claim that hashing `npx`, `uvx`, a shell wrapper, or another launcher proves the identity of whatever package/code it later downloads or executes. Preflight should warn when an ostensibly pinned stdio server still depends on an unpinned package/version or mutable wrapper.

For HTTP the canonical config should cover normalized scheme/host/port/base path and non-secret routing configuration. TLS/OAuth/EMA identity belongs to the surrounding authenticated transport. If trustworthy issuer/audience/subject/server context is available, AgentFence may record/consume it as additional evidence without becoming the identity provider.

### 2. Request-visible tool identity

For every modern HTTP tool call AgentFence should validate that the request-visible protocol/method/name evidence it relies on is internally consistent with the JSON-RPC body before policy evaluation.

For stdio, the JSON-RPC method and `params.name` remain the request-visible evidence.

### 3. Tool descriptor digest

An operator-reviewed tool definition should have a deterministic digest.

The first version should favor security over minimizing churn: hash the **complete canonical tool descriptor object returned by MCP discovery/listing**, including extension metadata, rather than cherry-picking only `name` + `inputSchema` and silently ignoring a prompt-facing or extension field that changes meaning.

Canonicalization requirements:

- JSON object key order must not affect the digest;
- insignificant serialization whitespace must not affect the digest;
- array order remains significant unless the MCP field explicitly defines it as unordered;
- numbers/strings/booleans/null must retain their JSON meaning without lossy float/string coercion;
- the canonicalization algorithm and version are part of the lock-file schema;
- the raw descriptor may be stored in a reviewable lock file, but audit events normally need only the digest/evidence status.

Do not invent a custom cryptographic primitive. SHA-256 is sufficient for deterministic content identity; the hard part is defining the canonical bytes and the evidence source.

### 4. Effective policy identity

The decision receipt should eventually include the effective-policy digest from [#222](https://github.com/dgenio/agentfence/issues/222), so the evidence tuple becomes approximately:

```text
upstream reference/config digest
+ authenticated context where supplied by standard MCP/IAM layers
+ request-visible method/tool name
+ pinned/observed tool descriptor digest
+ exact arguments digest
+ effective policy digest
--------------------------------
decision + reason
```

# Operator-owned lock file

Because discovery is optional, strict identity binding needs an explicit reviewed artifact rather than relying on whatever the client happened to list during a session.

Proposed shape (illustrative, not yet a public schema):

```json
{
  "schema_version": "1",
  "canonicalization": "agentfence-tool-json-v1",
  "upstreams": {
    "workspace-filesystem": {
      "transport": "stdio",
      "upstream_config_sha256": "sha256:...",
      "tools": {
        "filesystem.read": {
          "descriptor_sha256": "sha256:..."
        },
        "filesystem.write": {
          "descriptor_sha256": "sha256:..."
        }
      }
    }
  }
}
```

A future capture command may also retain a normalized descriptor alongside each digest so the PR diff shows exactly what changed. The lock must never contain credentials.

## Refresh is an explicit security event

A mismatch must never silently update the lock.

Expected workflow:

```text
server/tool changes
    -> AgentFence reports mismatch
    -> DENY (strict mode) or warning (observation mode)
    -> operator inspects descriptor/config diff
    -> explicit lock refresh
    -> policy tests / review
    -> new digest becomes trusted
```

A lock refresh belongs in code review/configuration management like a dependency-lock update.

## Enforcement modes

Identity binding should be independently configurable from ordinary tool policy so teams can migrate without turning compatibility mode into an implicit security guarantee.

Suggested states:

### `unbound`

Legacy compatibility. Tool name/arguments are evaluated as today. Audit/preflight explicitly reports that capability identity is not pinned.

### `observe`

Capture/compare evidence and emit warnings/audit fields, but do not alter an otherwise allowed decision. Useful for establishing a lock before enforcement.

### `require`

A protected call is eligible for ordinary policy evaluation only when required upstream/tool evidence matches the operator-owned lock. Unknown/missing/mismatched evidence fails closed before the call is forwarded.

For production security claims, documentation should recommend `require` once the feature is implemented and validated. Backward compatibility should never be described as equivalent protection.

## Stable failure reasons

Identity failures should have typed reason codes rather than free-text-only diagnostics. Candidate categories:

```text
upstream_identity_unknown
upstream_identity_mismatch
tool_identity_unknown
tool_descriptor_unknown
tool_descriptor_mismatch
request_identity_mismatch
identity_lock_invalid
```

Exact names should follow the existing `ReasonCode` conventions.

## Discovery/capture strategy

### Passive observation

When the proxied client performs `tools/list`, AgentFence can observe the response and compare descriptors with the lock. This is useful evidence and should support both legacy and modern clients.

It is not sufficient alone because a client may use a cached/preloaded definition and call immediately.

### Explicit preflight

The preflight work in [#89](https://github.com/dgenio/agentfence/issues/89) should have an explicit path to resolve/capture the configured upstream's tool definitions when the server/protocol supports it.

For modern MCP this may use `server/discover` and/or `tools/list`; for older stateful servers an initialization exchange may be required. The implementation must follow the negotiated/current protocol rather than injecting a request shape that only works for one era.

### Operator-supplied lock

When live discovery is unavailable or intentionally skipped, strict mode can use a lock that was generated out-of-band from a trusted review workflow. AgentFence must still be able to determine whether the live upstream evidence it can observe is consistent with that lock; a lock is not useful if it can never be checked against the running boundary.

## HTTP-specific invariant

For MCP `2026-07-28` Streamable HTTP, `MCP-Protocol-Version`, `Mcp-Method`, and `Mcp-Name` are part of the modern request envelope. AgentFence already preserves current request metadata in its maintained fixtures; identity enforcement should additionally treat a disagreement between those headers and the JSON-RPC body as a request-identity failure rather than forwarding/evaluating contradictory identities.

This is still request consistency, not server provenance.

## Stdio-specific caveat

A command/argv digest is configuration identity, not implementation identity. Examples:

```text
npx -y @vendor/server
uvx some-server
bash ./start-server.sh
python -m package.server
```

can resolve to different code over time without the argv changing.

Preflight should therefore surface whether the configuration is reproducible (for example an exact package/version, immutable artifact, or stable local binary) and avoid claiming stronger provenance than it has.

## Audit receipt additions

Once implemented, the audit event should be able to carry safe identity evidence such as:

```json
{
  "upstream_ref": "workspace-filesystem",
  "upstream_config_digest": "sha256:...",
  "tool_descriptor_digest": "sha256:...",
  "tool_identity_status": "matched"
}
```

Do not store auth tokens, raw credential-bearing connection config, or an entire tool descriptor in every audit line.

A schema bump and JSON Schema/interop updates are required when these fields become public audit contract.

## Relationship to policy

The first implementation should avoid copying descriptor hashes into every individual tool rule if one reviewed lock can bind a whole upstream catalog. Policy can refer to an `upstream_ref` and ordinary tool name while the identity layer verifies that the live evidence matches the lock before the existing rule engine runs.

Conceptually:

```text
request
  -> transport/request consistency
  -> upstream/tool identity binding
  -> ordinary AgentFence policy
  -> approval if needed
  -> audit
  -> forward only on final allow
```

That keeps identity verification orthogonal to path/arg/URL policy semantics.

## Implementation slices

### Slice A — pure canonicalization + lock schema

- define versioned descriptor canonicalization;
- lock-file parser/strict validation;
- unit/fuzz tests for map order, whitespace, unknown fields/schema versions, malformed descriptors;
- no runtime behavior change.

### Slice B — evidence in audit/preflight

- compute upstream config digest;
- compare available descriptors to lock in observation mode;
- expose safe status/digests through preflight/audit;
- no silent repinning.

### Slice C — fail-closed enforcement

- `require` mode blocks unknown/mismatched identity before ordinary policy allow can forward;
- stdio + HTTP tests prove the upstream does not receive a mismatched call;
- modern HTTP header/body mismatch is rejected before policy evaluation.

### Slice D — real integration proof

- update [#214](https://github.com/dgenio/agentfence/issues/214) to show the actual evidence on a real client/server path;
- include lock refresh/change review in the walkthrough;
- include the identity surface in the independent review [#223](https://github.com/dgenio/agentfence/issues/223).

## Required tests

At minimum:

- same descriptor with different JSON key order -> same digest;
- any semantically retained descriptor field changes -> different digest;
- same tool name on different upstream ref/config -> distinct identity;
- unknown descriptor in `require` mode -> deny;
- changed descriptor in `require` mode -> deny;
- changed descriptor in `observe` mode -> warning/audit but ordinary policy result unchanged;
- explicit operator refresh is required before changed descriptor becomes accepted;
- HTTP method/name header/body disagreement -> fail closed;
- lock parser rejects unknown schema/canonicalization versions;
- lock/audit never serializes configured credentials.

## Open design questions before Slice A

1. Which canonical JSON algorithm should be the stable public contract: a small AgentFence-specific canonical projection/encoder or a published standard such as JCS/RFC 8785?
2. Should full `_meta` be included in v1 descriptor identity despite potential churn, or should the lock define an explicit security-relevant projection and fail closed on unknown extensions?
3. What is the smallest reproducible stdio upstream identity that works well for package launchers without pretending the wrapper executable identifies downloaded code?
4. How should authenticated server identity supplied by HTTP/OAuth/EMA be represented without coupling AgentFence to one IdP/provider?
5. Which legacy MCP revisions are worth active descriptor-capture support versus documented lock-only compatibility?

These are review questions, not invitations to broaden the product. The outcome should remain a small deterministic identity check in front of the existing policy engine.
