# AgentFence roadmap

_Last updated: 2026-08-11._

This is a **directional** roadmap, not a commitment or a dated release plan. The authoritative source of truth is the issue tracker, especially the [`roadmap`](https://github.com/dgenio/agentfence/labels/roadmap) label. When this document and the tracker disagree, the tracker wins.

> **Pre-launch naming note:** [#234](https://github.com/dgenio/agentfence/issues/234) records the decision to rename **AgentFence -> VeriCordon** before broad launch because `AgentFence` is already ambiguous across unrelated AI-security/package/research surfaces. The target launch identity is **VeriCordon**; the current repository/binary name remains temporarily in use while #239–#242 complete the compatibility-preserving migration. Do not spend broad distribution effort on the current brand.

## Product thesis

The project should stay narrow:

> **A small, local, deterministic authorization primitive for mediated tool calls, with the exact upstream/tool evidence, effective policy, exact action and approval bound into a fail-closed decision and independently verifiable evidence.**

The project should not try to win by accumulating every adjacent AI-security feature. Identity/IAM, prompt/DLP detection, runtime behavioral drift probing, sandboxing/OS containment, and arbitrary shell interpretation are separate layers that should compose with this project where useful.

See [`docs/positioning.md`](docs/positioning.md), [`docs/tool-identity.md`](docs/tool-identity.md), and [`docs/policy-action-binding.md`](docs/policy-action-binding.md) for the current boundary/design contracts.

## Completed foundations

The original phased roadmap is substantially complete:

- **Phase 0 — Harden the MVP** ([#2](https://github.com/dgenio/agentfence/issues/2)): contributor guidance, CI, validation, structured output, strict YAML handling, safer path behavior, and release tooling.
- **Phase 1 — Expand the policy language** ([#3](https://github.com/dgenio/agentfence/issues/3)): groups/wildcards, argument/URL/command constraints, `policy test`, `explain`, and imports/packs.
- **Phase 2 — MCP proxy support** ([#4](https://github.com/dgenio/agentfence/issues/4)): stdio interception, interactive approval, timeout, and integration guidance.
- **Phase 3 — Trustworthy audit logs** ([#5](https://github.com/dgenio/agentfence/issues/5)): versioned events, sequencing/session IDs, hash chaining, verification, threat-model expansion, and fuzzing.

Additional shipped foundations include streamable-HTTP proxying, Ed25519 audit signing, audit anchors/rotation/sinks, SBOM/signed release artifacts, typed decision reason codes, metrics/logging, taint/confused-deputy defense-in-depth, and the maintained blocked-call proof. The cross-call late-approval substitution bug discovered during the adoption red-team was fixed in [#229](https://github.com/dgenio/agentfence/pull/229). See [CHANGELOG.md](CHANGELOG.md) for release-level specifics.

## Current gates

The next phase is **not primarily more features**. It is proving that the authorization primitive is distinct, truthful, deployable, independently reviewable, and useful enough that unrelated users keep it enabled.

### G0 — Brand identity before distribution

- [#234](https://github.com/dgenio/agentfence/issues/234): **VeriCordon selected** as the collision-checked target launch identity.
- [#239](https://github.com/dgenio/agentfence/issues/239): migrate repository, Go module and CLI identity.
- [#240](https://github.com/dgenio/agentfence/issues/240): migrate release/container/install-channel identifiers.
- [#241](https://github.com/dgenio/agentfence/issues/241): migrate public docs/examples/ecosystem references.
- [#242](https://github.com/dgenio/agentfence/issues/242): review durable machine identifiers so branding does not break historical evidence/contracts.

Security implementation can continue under the current repository while the migration is prepared. Broad brand/distribution work should wait until the transition is coherent.

### G1 — Prove differentiation, not category membership

- [#235](https://github.com/dgenio/agentfence/issues/235): prove the evidence-bound authorization primitive rather than shipping another MCP policy proxy.

`MCP proxy`, `allow / deny / ask`, `local policy`, `tool drift`, and `audit receipt` are individually established patterns/products. The project must make the **combined binding invariant** testable: upstream/tool evidence + exact action + effective policy + exact approval -> deterministic decision -> audit before effect -> independently verifiable evidence.

### G2 — Boundary truth and launch proof

- [#115](https://github.com/dgenio/agentfence/issues/115): make the narrow mediated-action category and bypass/non-goals explicit.
- [#74](https://github.com/dgenio/agentfence/issues/74): finish result-centered launch artifacts **after** naming/differentiation gates are satisfied.

Success means a stranger understands what is mediated and what is not without reading the implementation, and launch copy does not fall back to generic `AI firewall` / `MCP gateway` positioning.

### G3 — Deployment preflight

- [#89](https://github.com/dgenio/agentfence/issues/89): the planned preflight/doctor capability must verify policy/proxy/upstream/audit/approval setup and make the actual mediation boundary visible.

A correct engine is not sufficient if the operator accidentally configured a bypass path, writable policy, untrusted approval channel, wrong upstream, or identity lock that is not actually enforceable.

### G4 — Preserve exact request semantics

- [#232](https://github.com/dgenio/agentfence/issues/232): preserve JSON number precision before exposing an exact action fingerprint.

A security identifier must not be built after lossy `float64` parsing. This is a prerequisite for #222 action binding.

### G5 — Server/tool identity binding

- [#221](https://github.com/dgenio/agentfence/issues/221): implement the design in [`docs/tool-identity.md`](docs/tool-identity.md): operator-owned upstream/tool evidence, explicit descriptor/config drift handling, no silent repinning, and fail-closed `require` mode.

A matching tool-name string must not silently inherit authority when the capability underneath it changes.

### G6 — Policy, action and approval binding

- [#222](https://github.com/dgenio/agentfence/issues/222): implement the design in [`docs/policy-action-binding.md`](docs/policy-action-binding.md): effective-policy identity, exact action identity, bounded redacted approval display, and approval bound to the same evidence that enforcement/audit use.

Changing action arguments, effective policy, or required tool identity evidence must invalidate the previous binding. Local TTY approval must never be presented as authenticated human identity.

### G7 — Real integration proof

- [#214](https://github.com/dgenio/agentfence/issues/214): prove one real MCP client -> project boundary -> real MCP server path, with a useful ALLOW and a blocked high-risk call, while explicitly showing any unmediated client path.

The hermetic stub remains the CI regression proof; this gate establishes practical integration evidence for the differentiated primitive.

### G8 — Independent security evidence

- [#223](https://github.com/dgenio/agentfence/issues/223): obtain an independent review of the policy/parser/proxy/approval/audit/identity-binding boundary and publish scoped findings/disposition.

Strong tests and maintainer-run coding-agent reviews are valuable, but they are not independent security review.

### G9 — Retained adoption

- [#225](https://github.com/dgenio/agentfence/issues/225): validate that unrelated users connect real workflows, customize policy, and keep the boundary enabled after evaluation.
- [`docs/adoption-evidence.md`](docs/adoption-evidence.md): no-telemetry evidence protocol and kill/pivot discipline.

Use public/voluntary signals only. Weak retention is product evidence, not automatically a distribution problem. A retained user who merely needed any approval proxy is weaker validation of #235 than a user who specifically values independent local bound authorization/evidence.

### G10 — Human contributor viability

- [#224](https://github.com/dgenio/agentfence/issues/224): completed process gate — claimed external `help wanted` / `good first issue` work is protected from maintainer-agent races, and the active maintainer automation honors that reservation policy.

Continue measuring this qualitatively: can useful outside work land before maintainer automation makes it obsolete?

## Deliberately lower priority until the gates above have evidence

### Policy examples, not universal `safe` packs

- [#208](https://github.com/dgenio/agentfence/issues/208): assumption-explicit coding-workflow examples.
- [#211](https://github.com/dgenio/agentfence/issues/211): small tested high-risk capability examples.

These are onboarding material. A community policy marketplace/auto-update ecosystem should wait until retained adoption exists and there is a deliberate provenance/version-pinning trust model.

### Conservative shell handling

- [#203](https://github.com/dgenio/agentfence/issues/203): prefer structured argv/tool fields and gate ambiguous shell/interpreter strings conservatively.

The project should not become an incomplete Bash/PowerShell/cmd interpreter or claim to infer every side effect of arbitrary shell programs. Sandboxing/OS controls remain the containment layer after forwarding.

### Broader detection/enforcement surfaces

Features such as response-side policy, deeper DLP-like inspection, more heuristic taint analysis, runtime drift probing, dashboards, hosted control planes, and broad security scanning should not outrank the gates above merely because they expand the feature matrix. Mature adjacent products already exist in several of those categories; composition is preferable to undifferentiated feature accumulation.

## Product kill/pivot discipline

A healthy adoption funnel is roughly:

```text
discover differentiated primitive
  -> reproduce bound ALLOW/DENY evidence
  -> connect real client/server
  -> customize policy/identity lock
  -> keep the boundary enabled
  -> value the independent evidence/control enough to retain/share/contribute
```

Revisit the thesis if any of these patterns dominate:

```text
cool demo -> star -> never used
```

```text
native MCP/client authorization is sufficient -> separate boundary removed
```

```text
broader gateway/sandbox solves the same need with lower operational cost -> boundary removed
```

```text
bound-evidence semantics are too fragile/complex to operate -> users disable strict mode
```

Do **not** compensate for weak evidence by adding generic security features. Narrow the project or pivot based on what retained users actually value.

## Smaller work

CLI ergonomics, performance, tests, benchmarks, and documentation improvements continue to live in the tracker without necessarily carrying the `roadmap` label. Browse [open issues](https://github.com/dgenio/agentfence/issues), [`help wanted`](https://github.com/dgenio/agentfence/labels/help%20wanted), and [`good first issue`](https://github.com/dgenio/agentfence/labels/good%20first%20issue) for entry points.
