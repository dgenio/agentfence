# VeriCordon evidence Action

Generate inspectable authorization evidence for the exact calls and policy
AgentFence evaluated.

```yaml
- uses: dgenio/agentfence/evidence-action@v0.10.0
  with:
    policy: agentfence.yaml
    calls: testdata/tool-calls.jsonl
    tests: testdata/policy-tests.yaml   # optional
    context: ${{ github.repository }}@${{ github.sha }}
```

For a brand-new repository, make the workflow run on `push` as well as
`pull_request` so the workflow can bootstrap on the branch that first adds it.
See [`../docs/evidence-bundle.md`](../docs/evidence-bundle.md) for the complete
copy/paste workflow and minimal inputs.

By default the uploaded artifact includes the Markdown/JSON report, decisions,
policy validation, optional fixture results, the CI gate summary, and audit
verification. Raw `audit.jsonl` is excluded unless `include-raw-audit: true` is
set explicitly.

Evidence states are `observed`, `partial`, `not_evaluated`, and `failed`.
Missing evidence is never treated as a pass.

This Action does not establish complete agent mediation, sandboxing,
prompt-injection prevention, downstream execution safety, compliance
certification, or policy suitability for the operator's environment.
