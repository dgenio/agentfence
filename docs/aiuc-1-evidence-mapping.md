# AIUC-1 evidence mapping

This document maps AgentFence controls to the kinds of evidence an AIUC-1-style
agent governance review asks for. It is organized around reviewer questions, not
compliance claims.

> **This is not a certification claim.** AgentFence is not AIUC-1 certified, and
> running AgentFence does not make an agent or a system AIUC-1 certified or
> "compliant." AIUC-1 is an independent standard maintained by the Artificial
> Intelligence Underwriting Company; AgentFence is an unaffiliated open-source
> tool. What follows is an alignment aid: it shows which reviewer questions
> AgentFence can produce reproducible local evidence for, which it can only
> partially inform, and which sit entirely outside its enforcement and evidence
> boundary.

## How to read this document

Each row answers one reviewer question with the same five columns:

| Column | Meaning |
|---|---|
| Review question | The question a governance reviewer tends to ask. |
| AgentFence control | The mechanism that speaks to it, if any. |
| Evidence artifact | The concrete thing a reviewer can inspect. |
| How to produce / inspect it | The command or file that emits or holds the artifact. |
| Limits / non-goals | What the artifact does and does not establish. |

Every row carries a status:

- **Supports evidence**: AgentFence emits an artifact a reviewer can reproduce.
- **Partial**: AgentFence informs the question but does not answer it on its own.
- **Out of scope**: the question is outside AgentFence's enforcement and
  evidence boundary. No honest artifact exists, and none is invented here.

The mapping follows AIUC-1's six control domains, which the standard labels
A through F: A. Data & Privacy, B. Security, C. Safety, D. Reliability,
E. Accountability, F. Society (see [Sources](#sources)). This document maps at
the domain and reviewer-question level. It does not reproduce or cite individual
AIUC-1 requirement identifiers, and it does not assert that any AgentFence
artifact satisfies a specific numbered requirement.

### On the example fragments

Every fragment below was emitted by the current build (`go build ./cmd/agentfence`)
run against the files bundled in [`examples/`](../examples). None of them is
aspirational, and none uses an invented field. Audit-event fragments follow the
repository's existing convention from
[`examples/hero-expected-audit-receipt.jsonl`](../examples/hero-expected-audit-receipt.jsonl):
volatile per-run values (`session_id`, `timestamp`, `hash`, `prev_hash`) are
shown as `<session_id>`, `<timestamp>`, `<hash>`, `<prev_hash>` while every
structural field is exactly as written to the log. The machine-readable contract
for these events is [`schema/agentfence-audit-event.schema.json`](../schema/agentfence-audit-event.schema.json),
described in [audit-event-schema.md](audit-event-schema.md).

---

## A. Data & Privacy

### Are sensitive values kept out of the recorded log?

**Status: Partial.**

| Review question | AgentFence control | Evidence artifact | How to produce / inspect it | Limits / non-goals |
|---|---|---|---|---|
| Are sensitive argument values redacted before they reach the audit log? | Configured redaction patterns applied to arguments prior to write | A recorded event whose argument value is replaced by a `[REDACTED:<pattern>]` marker | `agentfence check --policy examples/policy.yaml --call examples/tool-calls.jsonl --no-interactive --audit-log audit.jsonl` then inspect the event | Redacted by configured rules only. A secret that matches no pattern is not redacted, so this does not make an artifact categorically secret-safe. Redaction covers the audit log, not the tool call itself. |

The write of an `OPENAI_API_KEY=…` value to `.env` is denied, and the value is
redacted in the recorded event:

```json
{"schema_version":"5","session_id":"<session_id>","seq":2,"timestamp":"<timestamp>","call_id":"call_002","tool":"filesystem.write","decision":"deny","reason":"path \".env\" denied by pattern \".env\"","reason_code":"path_denied","arguments":{"content":"OPENAI_[REDACTED:generic_secret_assignment]","path":".env"}}
```

The raw secret never reaches the log. It is still true that a value matching no
configured pattern would be logged verbatim when argument logging is on. See
[claims.md, Claim 4](claims.md) for the reproducer and its boundary.

### Can what an agent persists to durable memory be constrained and recorded?

**Status: Supports evidence.**

| Review question | AgentFence control | Evidence artifact | How to produce / inspect it | Limits / non-goals |
|---|---|---|---|---|
| Can durable memory writes be bounded by scope, sensitivity, and size, and recorded with a payload-free summary? | `memory_write` constraints in policy | A recorded event carrying a payload-free `memory_write` summary object | `agentfence check` on a `memory.write` call; inspect the event's `memory_write` field | Governs writes mediated by AgentFence only. It does not govern data the model already holds or persists through a path the gate never sees. Payload-free applies to the `memory_write` summary, which is a fingerprint of the content; the surrounding event may still carry the raw `arguments.content` when argument logging is enabled, as the example below shows. |

```json
{"schema_version":"5","session_id":"<session_id>","seq":1,"timestamp":"<timestamp>","call_id":"m1","tool":"memory.write","decision":"deny","reason":"non-interactive: ask auto-denied","reason_code":"non_interactive_denied","arguments":{"content":"user prefers dark mode","scope":"project","sensitivity":"low"},"memory_write":{"scope":"project","sensitivity":"low","field":"content","size_bytes":22,"content_fingerprint":"058e6f30768b"}}
```

The `memory_write` summary records scope, sensitivity, byte size, and a short
content fingerprint. It never includes the raw payload (see the schema's
`memoryWriteSummary` definition).

### Data retention schedules, training-data governance, PII inventory, subject requests

**Status: Out of scope.**

AgentFence keeps no data store, runs no model training, and holds no subject
records. It is not a data-loss-prevention or data-governance system. These
questions are answered by other systems and process, not by an AgentFence
artifact.

---

## B. Security

### Was a tool call authorized before it executed?

**Status: Supports evidence.**

| Review question | AgentFence control | Evidence artifact | How to produce / inspect it | Limits / non-goals |
|---|---|---|---|---|
| Was a tool call mediated by AgentFence evaluated against policy before it was allowed to run? | Policy decision engine (`check`, `proxy`, `proxy-http`) | A recorded event with `decision`, `reason`, and `reason_code` | `agentfence check --policy … --call … --audit-log …`, or run behind `agentfence proxy` | Records a local pre-execution decision at the AgentFence boundary. A recorded event proves the mediated call was evaluated; it does not prove that every tool call in the surrounding system traversed the AgentFence boundary, and it does not prove what the downstream tool or service did after an `allow`. |

```json
{"schema_version":"5","session_id":"<session_id>","seq":1,"timestamp":"<timestamp>","call_id":"call_001","tool":"filesystem.read","decision":"allow","reason":"tool filesystem.read matched explicit policy rule","reason_code":"rule_match","arguments":{"path":"README.md"}}
```

### What happens to a tool call that matches no rule?

**Status: Supports evidence.**

| Review question | AgentFence control | Evidence artifact | How to produce / inspect it | Limits / non-goals |
|---|---|---|---|---|
| Does an unrecognized tool call fail closed rather than open? | Deny-by-default (`defaults.decision: deny`) | A decision with `reason_code` `default_decision` | Send a tool that appears nowhere in the policy through `agentfence check` | Fails closed to the policy default. It is only as safe as the policy: a permissive or wrong policy is enforced faithfully. |

```console
$ echo '{"id":"x1","tool":"database.drop_table","arguments":{"table":"users"}}' \
    | agentfence check --policy examples/policy.yaml --call /dev/stdin \
        --output text --no-interactive
x1 database.drop_table -> deny (no rule for database.drop_table; using default decision)
```

See [claims.md, Claim 2](claims.md).

### Can the agent reach disallowed paths, URLs, commands, or arguments?

**Status: Supports evidence.**

| Review question | AgentFence control | Evidence artifact | How to produce / inspect it | Limits / non-goals |
|---|---|---|---|---|
| Are constraints on paths, URLs, argument values, and commands enforced and explainable? | Per-tool `constraints` (paths, urls, args, command) with stable reason codes | The decision trace and the `reason_code` (`path_denied`, `url_bare_ip`, `command_denied`, `arg_denied`, and the rest) | `agentfence explain --policy … --tool … --args …`; reason codes in the audit log | Shell command matching is a best-effort guardrail, not a sandbox. Shell metacharacters can bypass a `command` constraint. URL and path checks act on the argument strings presented to the gate. |

```console
$ agentfence explain --policy examples/policy.yaml --tool filesystem.write \
    --args '{"path":".env","content":"x"}' --output json
{
  "tool": "filesystem.write",
  "decision": "deny",
  "reason": "path \".env\" denied by pattern \".env\"",
  "trace": [
    "matched rule \"filesystem.write\" (decision: ask)",
    "checking path constraints for \".env\" (normalized: \".env\")",
    "path \".env\" denied by pattern \".env\""
  ]
}
```

The full reason-code taxonomy is in
[audit-event-schema.md, Reason codes](audit-event-schema.md#reason-codes). The
shell caveat is stated in [`examples/policy.yaml`](../examples/policy.yaml) and
[threat-model.md](threat-model.md).

### Is the enforcement point itself access-controlled?

**Status: Partial.**

| Review question | AgentFence control | Evidence artifact | How to produce / inspect it | Limits / non-goals |
|---|---|---|---|---|
| Is the network-facing proxy protected against unauthenticated callers? | `proxy-http --auth-token` bearer check plus a non-loopback bind guardrail | The `agentfence_errors_total{kind="unauthenticated"}` counter and a startup warning when a non-loopback listener has no token | Run `agentfence proxy-http` with and without `--auth-token`; scrape `--metrics-listen` | A single shared bearer token only. AgentFence does not manage identities, roles, or per-caller authorization. The stdio `proxy` has no network surface and no token. |

### Are prompt injection and model jailbreaks prevented?

**Status: Out of scope.**

AgentFence evaluates the tool calls an agent emits. It does not inspect model
prompts or model outputs, and it does not detect or prevent prompt injection or
jailbreak of the model. A compromised or manipulated agent that stays within
allowed calls is not stopped by AgentFence. This is stated as an explicit
non-claim in [claims.md](claims.md) and covered in
[threat-model.md](threat-model.md). Pair AgentFence with model-side and
system-level controls.

---

## C. Safety

### Can a human approve or refuse a sensitive action before it runs?

**Status: Supports evidence.**

| Review question | AgentFence control | Evidence artifact | How to produce / inspect it | Limits / non-goals |
|---|---|---|---|---|
| Is there a human-in-the-loop gate for actions the policy marks `ask`? | `ask` decision resolved by an interactive approver | A recorded event with an approval reason code (`approval_approved`, `approval_denied`, `approval_timeout`, `non_interactive_denied`) | Run `agentfence check` or `agentfence proxy` on an `ask` rule at a real terminal | Local single-operator TTY approval. It is not an organizational approval workflow, ticketing system, or multi-party sign-off. The event records the outcome, not the approver's identity. |

### Does an unattended approval fail safely?

**Status: Supports evidence.**

| Review question | AgentFence control | Evidence artifact | How to produce / inspect it | Limits / non-goals |
|---|---|---|---|---|
| When no human is present, does an `ask` decision deny rather than silently allow? | `--no-interactive` auto-deny and `--approval-timeout` | A recorded deny with `reason_code` `non_interactive_denied` or `approval_timeout` | `agentfence check --policy examples/policy.yaml --call examples/tool-calls.jsonl --no-interactive` | Fails closed to deny. It does not queue the action for later human review; the call is refused. |

```console
$ agentfence check --policy examples/policy.yaml --call examples/tool-calls.jsonl \
    --output text --no-interactive
call_001 filesystem.read -> allow (tool filesystem.read matched explicit policy rule)
call_002 filesystem.write -> deny (path ".env" denied by pattern ".env")
call_003 github.create_issue -> deny (non-interactive: ask auto-denied)
call_004 github.delete_repo -> deny (tool github.delete_repo matched explicit policy rule)
```

See [claims.md, Claim 3](claims.md).

### Are harmful model outputs detected or blocked?

**Status: Out of scope.**

AgentFence does not read, score, or moderate model output content. It gates
tool calls. Content-safety review of what the model says or generates is a
separate control that AgentFence does not provide.

---

## D. Reliability

### Can policy behavior be tested before deployment?

**Status: Supports evidence.**

| Review question | AgentFence control | Evidence artifact | How to produce / inspect it | Limits / non-goals |
|---|---|---|---|---|
| Can the expected decision for known tool calls be asserted and checked in CI? | `agentfence policy test` against an expected-decision fixture, and `agentfence validate` for policy well-formedness | `PASS`/`FAIL` lines per test case; a non-zero exit on any failure; `validate` `OK` output | `agentfence policy test --policy examples/policy.yaml --tests examples/policy-tests.yaml`; `agentfence validate --policy examples/policy.yaml` | Tests the policy's decisions, not the agent's model behavior. A passing suite says the policy decides as intended, not that the agent will make safe calls. |

```console
$ agentfence policy test --policy examples/policy.yaml --tests examples/policy-tests.yaml
PASS: allow-readme-read
PASS: deny-env-read
PASS: ask-write-src
PASS: deny-create-issue-private-repo
PASS: deny-shell-rm-rf
PASS: deny-memory-write-secret-payload
… (20 cases)
```

### Are decisions deterministic and traceable to an exact action and policy?

**Status: Partial.**

| Review question | AgentFence control | Evidence artifact | How to produce / inspect it | Limits / non-goals |
|---|---|---|---|---|
| Can a decision be reproduced and tied to the exact tool arguments and the exact resolved policy? | Decision trace (`explain`) and the schema-5 `action_digest` / `policy_digest` fields | The `explain` trace; the two digest fields on an event | `agentfence explain …`; inspect `action_digest` and `policy_digest` in the audit log | The digests are optional in schema 5. Current writers may omit them until the binding path can produce them fail-closed, so a reviewer must not assume every event carries them. Determinism holds for a fixed policy and input. |

This is an honest gap. The audit schema defines `action_digest`
(`tool-action-json-v1:sha256:…`) and `policy_digest`
(`resolved-policy-json-v1:sha256:…`), but
[audit-event-schema.md](audit-event-schema.md#exact-decision-binding-fields)
states plainly that they are optional in this schema slice and that adding an
optional field must not create a false claim that every evaluation is already
bound. Treat exact per-event binding as in progress, not as a settled property
of every recorded event today.

### Does AgentFence test the model's tendency to make unsafe calls or hallucinate?

**Status: Out of scope.**

AgentFence does not exercise, prompt, or score a model. Hallucination testing
and unsafe-tool-call red-teaming of the agent itself are separate activities.
AgentFence can enforce and record the boundary those activities are measured
against, but it does not perform them.

---

## E. Accountability

### Is there a durable record of each decision?

**Status: Supports evidence.**

| Review question | AgentFence control | Evidence artifact | How to produce / inspect it | Limits / non-goals |
|---|---|---|---|---|
| Is every mediated decision written to a durable, structured record? | JSONL audit log | One self-contained JSON event per decision, conforming to the published schema | `--audit-log <file>`; summarize with `agentfence audit summarize --log <file> --output json` | Records the calls that passed through the AgentFence boundary. A call that never reached AgentFence produces no event, so the log is a record of the boundary, not of the whole system. |

`agentfence audit summarize` aggregates a log without recomputation:

```json
{
  "total": 4,
  "by_decision": { "allow": 1, "deny": 3 },
  "by_schema_version": { "5": 4 },
  "by_reason_code": { "non_interactive_denied": 1, "path_denied": 1, "rule_match": 2 }
}
```

### Can the record be checked for post-hoc modification?

**Status: Supports evidence.**

| Review question | AgentFence control | Evidence artifact | How to produce / inspect it | Limits / non-goals |
|---|---|---|---|---|
| Can a reviewer detect and locate an edit to a recorded event? | `--tamper-evident` hash chain, verified by `agentfence audit verify` | An `OK` line for an intact chain, or a `FAILED` line naming the first broken event | `agentfence check … --tamper-evident --audit-log te.jsonl`; then `agentfence audit verify --log te.jsonl` | Tamper-evident after capture. It detects modification of recorded events. It does not prove that no event was suppressed before it was written, or that no call bypassed the boundary. |

```console
$ agentfence audit verify --log te.jsonl
OK: 4 event(s) verified
```

A single flipped decision is detected and located:

```console
$ agentfence audit verify --log te.jsonl
FAILED: integrity check failed at event 4 (possible tampering)
```

See [claims.md, Claim 5](claims.md) and
[threat-model.md](threat-model.md#audit-log-integrity).

### Can the record's writer be authenticated?

**Status: Supports evidence.**

| Review question | AgentFence control | Evidence artifact | How to produce / inspect it | Limits / non-goals |
|---|---|---|---|---|
| Can a reviewer confirm the events were written by a holder of a known key? | Ed25519 signing (`--sign-key`), verified with `agentfence audit verify --pubkey` | A `SIGNATURES: N verified, M unsigned` line | `agentfence audit keygen …`; sign with `--sign-key`; verify with `--pubkey` | Authenticates events signed by that key. Unsigned events are counted and reported, not rejected, so signing must be enabled at write time to carry weight. |

```console
$ agentfence audit verify --log signed.jsonl --pubkey key.pub
OK: 4 event(s) verified
SIGNATURES: 4 verified, 0 unsigned
```

### Can whole-log deletion or truncation be detected?

**Status: Supports evidence.**

| Review question | AgentFence control | Evidence artifact | How to produce / inspect it | Limits / non-goals |
|---|---|---|---|---|
| Can a reviewer detect that a tail of the log was silently dropped? | Publishable anchor (`agentfence audit anchor`), checked by `audit verify --anchor` | An `ANCHOR: log still contains anchored event seq=N` line, or an anchor failure | `agentfence audit anchor --log te.jsonl --out anchor.json`; later `agentfence audit verify --log te.jsonl --anchor anchor.json` | Detects truncation only relative to an anchor that was published somewhere the writer does not control. An anchor kept next to the log offers no protection. |

```console
$ agentfence audit verify --log te.jsonl --anchor anchor.json
OK: 4 event(s) verified
ANCHOR: log still contains anchored event seq=4
```

### Ownership, incident response, vendor due diligence, disclosure

**Status: Out of scope.**

These are organizational process controls. AgentFence produces evidence that can
feed an incident review, but it does not own an incident-response plan, a vendor
assessment, or a disclosure mechanism. Point a reviewer at process
documentation for these, not at an AgentFence artifact.

---

## F. Society

### Misuse guardrails and catastrophic-risk assessment

**Status: Out of scope.**

AgentFence is a local policy decision point. It enforces the operator's policy on
tool calls and records the outcome. It does not assess societal-scale misuse,
model capability, or catastrophic risk. Those questions belong to model
evaluation and organizational governance, not to this tool.

---

## Coverage summary

Across 20 reviewer questions in this document:

| Status | Count | Reviewer questions |
|---|---|---|
| Supports evidence | 11 | authorization before execution; deny-by-default; path/URL/command/argument constraints; human approval gate; unattended fail-closed; policy testing and validation; durable decision record; tamper-evident record; writer authentication; truncation detection; durable-memory constraint and summary |
| Partial | 3 | argument redaction; enforcement-point access control; determinism and exact action/policy binding |
| Out of scope | 6 | data retention and governance; prompt injection and jailbreak prevention; harmful-output moderation; model unsafe-call and hallucination testing; incident response and vendor process; societal misuse and catastrophic risk |

The out-of-scope count is deliberate. AgentFence is one layer of a
defence-in-depth posture. A reviewer should read the six out-of-scope answers as
a map of where other controls have to carry the weight, not as gaps to be
papered over with an AgentFence artifact.

## What this document does not claim

- It does not claim AIUC-1 certification or formal compliance with any standard.
- It does not claim that any AgentFence artifact satisfies a specific AIUC-1
  requirement. The mapping is at the domain and reviewer-question level.
- It does not claim AgentFence proves the behavior of systems outside its
  enforcement and evidence boundary. An `allow` records a decision, not the
  downstream effect.
- It adds no cloud or network dependency. Every command above runs locally
  against files in this repository.

For the full trust boundary, residual risks, and non-claims, read
[threat-model.md](threat-model.md) and [claims.md](claims.md).

## Sources

- AIUC-1 standard and its six control domains (A to F): the Artificial Intelligence
  Underwriting Company, <https://www.aiuc-1.com/>. Retrieved 2026-08-21. Domain
  names and letter grouping are used here for organization only; this document
  does not reproduce AIUC-1 requirement text or identifiers.
