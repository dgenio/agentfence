# Launch brief: exact MCP tool-call authorization before side effects

Status: **draft until the flagship-demo PR is merged and a release is tagged**.
Every claim below is intentionally bounded by the committed fixture and tests.

## Product claim

**AgentFence is the small, operator-owned policy gate for exact MCP tool names
and arguments: allow, deny, or ask before forwarding, then keep a redacted
receipt of the decision.**

The outsider problem is concrete: _“How do I allow normal MCP tool calls while
blocking sensitive paths or destructive arguments before execution?”_ Useful
search language is therefore **MCP tool-call policy**, **MCP allow/deny**,
**argument-aware MCP authorization**, and **MCP audit receipt**. Do not lead
with “the Weaver Stack”.

## Reproducible launch result

```bash
git clone https://github.com/dgenio/agentfence.git
cd agentfence
./examples/demo-blocked-call.sh
```

The same maintained scenario produces both outcomes:

```text
AgentFence flagship MCP demo
ALLOW filesystem.read path=project-notes.txt -> upstream
DENY filesystem.write path=.env -> BlockedByPolicy before upstream
PROOF upstream received tools: ["filesystem.read"]
PASS safe read executed; injected .env write blocked before side effect.
```

The full command follows this stable summary with the normalized redacted
receipt and hash-chain verification.

The [policy](../examples/hero-policy.yaml),
[MCP requests](../examples/hero-requests.jsonl), and
[expected receipt](../examples/hero-expected-audit-receipt.jsonl) are
versioned. CI reruns the real stdio proxy and fails if the decision, reason,
redaction, receipt shape, or upstream non-delivery proof changes.

This proves that the configured AgentFence boundary handled those exact
requests as shown. It does **not** prove that all agent actions crossed that
boundary, that the upstream server is safe, or that the policy is correct for a
different workload.

## Category and honest alternatives

Do not claim a generic “AI agent firewall” category. That category is already
served by broader projects. The useful distinction is integration point and
job to be done:

- Use [Pipelock](https://github.com/luckyPipewrench/pipelock) when the primary
  need is broad content/egress inspection, DLP, prompt-injection scanning,
  tool-poisoning detection, or process containment across MCP, HTTP, A2A, and
  WebSocket. AgentFence should integrate with this layer rather than compete on
  heuristic content detection.
- Use [Docker MCP Gateway](https://docs.docker.com/ai/mcp-catalog-and-toolkit/mcp-gateway/)
  when Docker-native server lifecycle, catalog management, credential
  injection, and container isolation are the main requirements.
- Use [agentgateway](https://github.com/agentgateway/agentgateway) or
  [IBM ContextForge](https://github.com/IBM/mcp-context-forge) when the problem
  is fleet-scale federation, identity, routing, multi-protocol governance, and
  centralized observability.
- Use [Snyk Agent Scan](https://github.com/snyk/agent-scan) when the immediate
  job is discovering and assessing installed agents, skills, MCP servers, and
  their definitions before runtime.
- Use an OS/container/network sandbox when a process must be unable to bypass
  the proxy. AgentFence is not that isolation layer.

Use AgentFence when a small local boundary, an explicit reviewable policy over
tool names and arguments, deterministic fixtures, and operator-owned audit
evidence are the dominant needs—and when running a broader control plane would
be unnecessary.

## GitHub Release draft

### Title

`AgentFence vX.Y.Z — a tool call the MCP server never sees`

### Body

This release adds one maintained proof of AgentFence's core boundary.

An allowed `filesystem.read(project-notes.txt)` reaches a local MCP server and
returns prompt-injected text. The deterministic agent fixture then requests
`filesystem.write(.env, OPENAI_API_KEY=…)`. AgentFence evaluates the exact tool
and arguments, returns `BlockedByPolicy`, and the server's diagnostic endpoint
confirms that it received only the read.

The audit log records the ALLOW and DENY, redacts the fake secret, and verifies
as a hash chain. The policy, MCP `2026-07-28` requests, normalized expected
receipt, and complete runner are committed under `examples/hero-*` and run in
CI.

Reproduce it:

```bash
./examples/demo-blocked-call.sh
```

Security boundary: AgentFence mediates submitted calls that pass through its
configured proxy or CLI gate. It does not prevent prompt injection, sandbox an
MCP server, validate that every action used the proxy, or make an incorrect
policy safe. `ask` adds safety only with a trustworthy approval path.

## Technical article draft

### The MCP tool call the server never saw

Tool-capable agents turn text into effects. A note in a repository, an issue
body, or a tool response can tell an agent to write a credential file or run a
destructive operation. Detecting every hostile sentence is a difficult and
probabilistic problem. Controlling which effects are reachable can be much
more deterministic.

That is the narrow job AgentFence is built for. It sits between an MCP client
and server, evaluates the submitted tool name and arguments against an
operator-owned policy, and decides whether to forward the request. It does not
try to make the model trustworthy. It controls one boundary the model must
cross.

The launch fixture starts with a legitimate operation:

```text
filesystem.read(path="project-notes.txt") -> ALLOW
```

The local MCP stub returns project notes containing an injected instruction to
write a fake API key into `.env`. The deterministic agent fixture follows that
instruction and submits:

```text
filesystem.write(
  path=".env",
  content="OPENAI_API_KEY=sk-demo-not-a-real-secret-1234567890"
)
```

The complete policy is deliberately small. Reads are bounded to the fixture.
Writes are allowed only under `workspace/**`, while `.env` is explicitly
denied. This matters: the demo is not convincing because it blocks everything;
it is convincing because the same boundary allows the expected call and rejects
the sensitive arguments.

AgentFence returns JSON-RPC `BlockedByPolicy (-32001)` without forwarding the
write. A diagnostic request to the stub then reports that it received only
`filesystem.read`. That is the strongest part of the proof: the deny is not an
error produced after a side effect. The upstream never received the request.

The audit evidence is just as concrete. It contains an ALLOW receipt for the
read and a DENY receipt for the `.env` write, including stable reason code
`path_denied`. The fake key is recorded as
`OPENAI_[REDACTED:generic_secret_assignment]`, and the two events form a
verifiable hash chain. Runtime timestamps, session IDs, and hashes are
normalized for the golden fixture; every policy-relevant field remains exact.
CI compares the live result with that fixture, so the demo cannot silently
drift into marketing-only output.

The fixture uses the current stateless MCP `2026-07-28` request shape: there is
no initialization handshake, and client metadata travels with each request.
The stdio proxy preserves the complete allowed frame. The HTTP proxy also has
tests proving that the required protocol, method, and tool-name headers survive
the boundary unchanged.

This is intentionally not a claim of complete prompt-injection prevention.
AgentFence did not recognize or remove the injected sentence. The model could
still be manipulated in ways that lead to allowed calls. A malicious server
could misuse the permissions of a call that policy allows. A process with
direct filesystem or network access could bypass the MCP boundary entirely.
Use a sandbox or network policy when bypass resistance is required, and use a
broader content-security layer when DLP or injection scanning is the primary
problem.

The result is smaller but testable: for calls that cross the configured
boundary, an operator can review a deterministic policy, reproduce the exact
ALLOW and DENY, inspect why the decision happened, and verify the receipt
without a hosted dashboard.

Run the proof yourself:

```bash
git clone https://github.com/dgenio/agentfence.git
cd agentfence
./examples/demo-blocked-call.sh
```

## Hacker News / technical-community post draft

### Title

`Show HN: AgentFence – deterministic allow/deny/ask for MCP tool calls`

### Body

I built AgentFence as a small local policy boundary in front of MCP tools. The
narrow goal is to authorize the exact tool name and arguments before the server
sees the request, then leave a redacted receipt—not to claim that prompt
injection has been solved.

The maintained demo allows a bounded file read whose result contains an
injected instruction, then blocks the resulting `.env` write. The stub MCP
server reports that it received only the allowed read, and CI compares the
redacted hash-chained audit output with a committed expected receipt:

```bash
git clone https://github.com/dgenio/agentfence.git
cd agentfence
./examples/demo-blocked-call.sh
```

The policy and requests are intentionally tiny and use the stateless MCP
`2026-07-28` shape. The README also states the boundary up front: this is not a
sandbox, it does not prevent prompt injection, and it cannot govern calls that
bypass the proxy.

Repository: https://github.com/dgenio/agentfence

I would especially value technical feedback on the policy semantics, the
receipt evidence, and cases where a simpler allowlist or a broader gateway is
the more honest solution.

## Distribution guardrails and next integration

- Publish the release/article/post only after the exact-head CI for the merged
  flagship scenario is green.
- Do not submit AgentFence to the official MCP Registry. The registry is for
  publicly installable/accessibly hosted MCP servers; AgentFence is a proxy
  around an operator-selected server.
- Do not mass-submit to lists. Pick at most one security-focused list and one
  technically justified integration after checking each contribution policy.
- Validate a nested local path such as `AgentFence -> Pipelock -> MCP server`.
  If the policies compose cleanly, contribute a neutral integration recipe
  upstream: AgentFence for exact tool/argument authorization; Pipelock for
  bidirectional content and egress inspection. If the composition adds only
  duplication or confusing failure modes, document that and do not submit a
  PR.
