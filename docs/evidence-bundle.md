# VeriCordon authorization evidence bundle

The evidence bundle is a deliberately small product experiment built on the
existing AgentFence enforcement and audit primitives.

It turns a policy, optional policy fixtures, and a set of tool calls into two
review surfaces:

- a human-readable `report.md`;
- a versioned machine-readable `report.json`.

The report is **scoped engineering evidence**. It is not a security score,
certification, compliance attestation, sandbox result, or proof that every call
in the surrounding agent was mediated.

The launch identity selected for the product is **VeriCordon**; the repository,
module, CLI, and durable machine identifiers remain AgentFence-compatible.

## What it answers

For the inputs supplied to the run, the bundle can report:

- whether the supplied policy validated;
- whether supplied policy fixtures passed;
- counts of allow / deny / ask decisions for the calls actually evaluated;
- whether the supplied tamper-evident audit chain verifies;
- the fraction of supplied audit events that carry both `action_digest` and
  `policy_digest`;
- exactly which local artifacts support those statements;
- explicit limits for every evidence check.

Missing binding fields become `partial` or `not_evaluated`. They never become a
pass by absence.

## Ten-minute GitHub Actions path

A repository that already has an AgentFence policy and representative/test call
JSONL can add:

```yaml
name: Agent authorization evidence

on:
  push:
  pull_request:

permissions:
  contents: read

jobs:
  evidence:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: dgenio/agentfence/evidence-action@v0.10.0
        with:
          policy: agentfence.yaml
          calls: testdata/tool-calls.jsonl
          tests: testdata/policy-tests.yaml
          context: ${{ github.repository }}@${{ github.sha }}
```

The initial `push` trigger is intentional: it lets a brand-new repository run
the workflow on the same branch that first introduces the workflow file. After
that bootstrap, `pull_request` runs provide the normal review path.

Pin `v0.10.0` for the released consumer surface. Environments that require an
immutable third-party Action reference can pin the exact release commit SHA
instead.

The action:

1. builds the local AgentFence binary and report generator;
2. validates the policy;
3. runs optional policy fixtures;
4. evaluates the supplied calls non-interactively;
5. writes a tamper-evident local audit log;
6. verifies that local chain;
7. generates Markdown + JSON reports;
8. uploads a safe aggregate artifact;
9. preserves validation/test/CI-gate failures after the artifact is generated.

`fail-on` is empty by default, making the first run diagnostic. Set it to
`deny`, `ask`, or `deny,ask` when the same workflow should act as a CI gate.

### Minimal inputs

The Action needs only a policy and representative call JSONL. Policy fixtures
are optional.

```yaml
# agentfence.yaml
version: "0.1"
defaults:
  decision: deny
tools:
  demo.read:
    decision: allow
  demo.write:
    decision: ask
```

```jsonl
{"id":"read-1","tool":"demo.read","arguments":{"path":"README.md"}}
{"id":"write-1","tool":"demo.write","arguments":{"path":"notes.txt","content":"hello"}}
```

In non-interactive CI, an `ask` policy decision is resolved to `deny`; policy
fixtures still report the underlying policy result when you supply them.

## What missing evidence looks like

VeriCordon reports evidence state instead of converting absence into a pass.
A maintained pre-release run from #268 had four audit events but **0/4** carried
both `action_digest` and `policy_digest`; the report therefore emitted:

```json
{
  "id": "exact_action_policy_binding",
  "status": "partial"
}
```

That missing binding was then fixed in #269. The maintained gate now requires
all representable evaluated events to be bound rather than accepting a fixed
cardinality.

## What exact action + policy binding looks like

The fresh-consumer release test evaluated three representative calls. All
**3/3** resulting audit events carried both the exact-action digest and the
resolved/effective-policy digest, so the report emitted:

```json
{
  "id": "exact_action_policy_binding",
  "status": "observed",
  "summary": "All 3 supplied audit events carry both action_digest and policy_digest."
}
```

This is evidence about those supplied evaluated calls only. It does not prove
that every capability in the surrounding agent was mediated.

## Safe artifact boundary

By default the uploaded artifact contains aggregate/review material such as:

```text
report.md
report.json
decisions.json
policy-validation.txt
gate-summary.json
policy-tests.json          # when supplied
audit-verification.json
```

The raw `audit.jsonl` is **not uploaded by default**. Audit events may contain
argument values unless configured redaction matches them, so turning on
`include-raw-audit: true` is an explicit data-handling decision.

The raw audit still exists ephemerally on the runner long enough to calculate
binding coverage and verify the chain.

## Status semantics

The machine report schema is
[`schema/vericordon-evidence-report.schema.json`](../schema/vericordon-evidence-report.schema.json).

Each check uses one of four states:

| Status | Meaning |
| --- | --- |
| `observed` | The supplied artifact directly supports the narrowly worded statement. |
| `partial` | Some relevant evidence is present but the complete narrow condition was not observed. |
| `not_evaluated` | The run did not contain enough evidence to evaluate the check. |
| `failed` | The supplied validation/fixture/integrity evidence explicitly failed. |

These are evidence states, not severity levels and not a security score.

## Security and scientific non-claims

The bundle deliberately repeats these limits in every generated report:

- it covers only calls supplied/evaluated through the AgentFence/VeriCordon
  boundary;
- it does not prove complete mediation of the agent, framework, host, or tool
  surface;
- it is not a sandbox and does not prevent prompt injection;
- an `allow` decision does not prove what a downstream tool/service did;
- policy validation and passing fixtures do not prove the policy is sufficient
  for a real deployment;
- local hash-chain verification does not prove complete collection or external
  anchoring;
- it does not authenticate a human identity unless that identity is actually
  provided and bound by the approval channel;
- it does not certify AIUC-1 or another standard.

For the underlying evidence boundaries, see
[`claims.md`](claims.md), [`threat-model.md`](threat-model.md), and
[`aiuc-1-evidence-mapping.md`](aiuc-1-evidence-mapping.md).

## Commercial experiment

The current-run bundle remains free/open source. The experiment is whether teams
value the **evidence workflow** enough to pay for convenience around it, rather
than whether the project can hide local security controls behind a paywall.

Initial hypotheses, intentionally not yet built:

| Package | Hypothesis |
| --- | --- |
| Free | Local/current-run evidence bundle and CI output. |
| Pro | €49–99/month for retained private history, cross-run evidence comparison, and low-touch diagnostics. |
| Team | €299–499/month for multiple repositories, shared policy/evidence history, review packs, and CI policy management. |

A €79 one-off paid evidence/history pilot is also a valid first revenue signal
before recurring billing exists.

If those capabilities would be worth paying for, register the buying intent on
[product experiment #267](https://github.com/dgenio/agentfence/issues/267).
Do **not** attach private policies, audit logs, proprietary schemas, credentials,
or customer data to a public issue.

No billing, hosted proxy, account system, or enterprise control plane should be
built until that experiment produces concrete commercial pull.

## Kill rule

Do not expand this because the report looks polished.

If qualified users can produce and understand the evidence but do not rerun it,
do not keep CI enabled, or will not pay for history/private/team workflow, the
correct response is to narrow, reposition, or stop commercial investment — not
to build a larger control plane.
