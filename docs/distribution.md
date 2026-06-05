# Distribution & outreach

This page tracks the distribution work for AgentFence and records the parts
that **cannot** be done from a pull request (they need repository-admin access,
an external account, or a sibling repository). It is the in-repo half of issues
[#74](https://github.com/dgenio/agentfence/issues/74),
[#79](https://github.com/dgenio/agentfence/issues/79), and
[#76](https://github.com/dgenio/agentfence/issues/76).

## Demo (#74)

[`examples/demo-blocked-call.sh`](../examples/demo-blocked-call.sh) is the
recordable demo: it runs AgentFence in prevention mode against a set of
prompt-injected calls (a secret-bearing `.env` write and a `github.delete_repo`)
and shows the blocked decisions plus a redacted, hash-chained, verified audit
trail.

To record the README GIF/asciinema:

```bash
# asciinema (then upload, or convert to GIF with agg):
asciinema rec demo.cast -c './examples/demo-blocked-call.sh'
agg demo.cast docs/img/demo.gif      # https://github.com/asciinema/agg
```

Embed the resulting GIF at the top of the README. (Recording and committing the
binary asset is a manual step; the script that drives it lives in the repo so
the demo stays reproducible.)

### Listing copy (for registry / awesome-list submissions)

> **AgentFence** — an open, local, no-telemetry policy gate for MCP tool calls.
> Drop it in front of any MCP server (stdio or streamable HTTP) to allow / deny
> / ask on each `tools/call`, redact secrets, and keep a tamper-evident audit
> trail. Optional confused-deputy (taint) detection escalates calls whose
> arguments derive from untrusted tool output.

### Submission checklist (external — needs a maintainer)

These require pushing to other repositories or registry accounts and cannot be
done from this repo's CI:

- [ ] Official MCP registry entry.
- [ ] `awesome-mcp-servers` (and other prominent awesome-MCP lists).
- [ ] An MCP-security / agent-security curated list.
- [ ] `awesome-ai-agents`.
- [ ] GitHub Marketplace listing for the Action (see below).

## Repository admin (#79)

These are GitHub **Settings** actions; no file in the repo can perform them:

- [ ] Set repository **topics**: `mcp`, `model-context-protocol`, `ai-agents`,
  `agent-security`, `policy-engine`, `security`, `go`, `firewall`,
  `weaver-stack`.
- [ ] Confirm **private vulnerability reporting** is enabled
  (Settings → Security → "Private vulnerability reporting"), since
  `SECURITY.md` routes disclosures to the advisory form.

## GitHub Action / Marketplace (#73)

The composite action ships in this repo ([`action.yml`](../action.yml)) and is
documented in [`integration-guide.md`](integration-guide.md#github-action).
Publishing it to the GitHub Marketplace is a one-time manual release step
(GitHub UI, on a tagged release) and is not a file change.

## Shared policy contract with agent-kernel (#76)

The "write once, enforce in-process and at the edge" story depends on a shared,
authorable policy + safety-class contract **defined in `dgenio/weaver-spec`**,
which does not exist yet (weaver-spec v0 defines policy *outputs* —
`PolicyDecision`, `RiskAssessment` — but no authorable policy language). That
contract must land in weaver-spec first; see the
[blocking comment on #76](https://github.com/dgenio/agentfence/issues/76) for
the proposed weaver-spec issue. Once it exists, the AgentFence side is a loader
that maps the shared contract onto `policy.Policy`, plus a consistent-decision
fixture set — straightforward to add then, but out of scope for this repo until
the prerequisite ships.

The output half of the interop story is already done: see
[`interop.md`](interop.md) for weaver-spec-aligned trace export
(`agentfence audit export`).
