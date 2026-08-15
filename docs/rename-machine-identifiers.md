# AgentFence -> VeriCordon machine-identifier compatibility

> **Status:** migration contract for [#242](https://github.com/dgenio/agentfence/issues/242). The public product/repository/binary is being renamed to **VeriCordon** before broad launch, but durable evidence and machine interfaces must not be rewritten casually merely to match the new brand.

The rule is simple:

> **Rename brand surfaces aggressively while the project is young; preserve or explicitly migrate evidence/wire contracts deliberately.**

A historical AgentFence audit record that was hashed or signed must remain verifiable after the VeriCordon rename. Renaming a title is cheap; silently changing metrics, environment variables, JSON metadata, schema identifiers, or signed bytes is not.

## Compatibility classes

Each identifier belongs to one of four classes.

### A — brand/user-facing

Rename directly to VeriCordon. No durable machine compatibility is implied.

Examples: README prose, CLI help headings, terminal prompt/error brand text, binary/man/completion names, repository/module URL, package descriptions, demo headings.

### B — pre-launch machine surface with low historical value

Move to a canonical VeriCordon identifier deliberately. A bounded legacy read/alias may be useful when migration cost is low, but do not carry duplicate names forever.

Examples: environment variables, default config filename, Prometheus metric namespace, install/package identifiers.

### C — durable evidence/wire contract

Preserve historical semantics and bytes. Do not rename existing records in place. Introduce a new identifier only through an explicit schema/contract version transition when there is a substantive format change.

Examples: audit schema v1–v4 records, signed/hash-chained event bytes, anchors, numeric JSON-RPC error codes, stable reason-code values.

### D — external interop namespace

Preserve the existing exported contract unless the receiving contract/version changes deliberately. If a new VeriCordon namespace is introduced, provide a versioned migration rather than silently changing keys.

Example: weaver-spec export metadata such as `agentfence_decision`.

## Compatibility matrix

| Surface | Current identifier | Class | Migration decision |
|---|---|---:|---|
| Repository | `dgenio/agentfence` | A | Rename to `dgenio/vericordon` under #239; verify GitHub redirects after the server-side rename. |
| Go module/import path | `github.com/dgenio/agentfence` | A/B | Move to `github.com/dgenio/vericordon` pre-launch. Build/test all packages on the new canonical path. Do not preserve the old import path as the product identity indefinitely. |
| Binary/CLI | `agentfence` | A/B | Canonical binary becomes `vericordon`. A short-lived compatibility executable/alias is optional under #239; if shipped, give it an explicit expiry. |
| Default policy filename | `agentfence.yaml` | B | New `init` writes `vericordon.yaml`. Existing explicit `--policy <path>` remains valid regardless of filename. If auto-detection/default-file behavior exists or is added, prefer `vericordon.yaml` and accept legacy `agentfence.yaml` only through an explicit transition with a warning. Never overwrite either implicitly. |
| Proxy auth env | `AGENTFENCE_PROXY_AUTH_TOKEN` | B/security-sensitive | Introduce `VERICORDON_PROXY_AUTH_TOKEN`. For a bounded transition, accept the legacy variable as fallback. If both are set and values differ, fail closed instead of guessing. Never print either value. |
| Other future env vars | `AGENTFENCE_*` | B | New variables use `VERICORDON_*`. Any existing variable gets an explicit alias/deprecation decision; do not blanket-replace without tests. |
| Prometheus namespace | `agentfence_*` (e.g. `agentfence_decisions_total`, `agentfence_reason_codes_total`) | B/operational API | Rename to `vericordon_*` before broad launch. This is an intentional pre-launch breaking observability change rather than permanent duplicate metric emission. Document it in CHANGELOG. Do not expose both namespaces indefinitely because double series can be accidentally double-counted. |
| JSON-RPC policy-block code | `-32001` | C | **Keep numeric code unchanged.** The number identifies the protocol condition, not the marketing brand. |
| Other AgentFence server-error codes | `-32002` … `-32005` | C | **Keep numeric values unchanged.** Rename Go constant comments/names only as source-level cleanup when appropriate; wire numbers remain stable. |
| JSON-RPC error message text | strings such as `blocked by AgentFence policy` / `AgentFence proxy error` | A | May change to VeriCordon because clients must key on structured/numeric errors, not brand prose. Keep tests focused on semantic/error-code guarantees unless exact text is intentionally documented. |
| Audit event `schema_version` | currently `"4"` | C | **Do not bump only for branding.** A future bump should correspond to real serialized-contract changes (for example #221/#222 binding evidence), not the display name. |
| Audit JSON field names | `schema_version`, `decision`, `reason_code`, `hash`, `signature`, etc. | C | Keep. They are already brand-neutral and should not churn. |
| Audit reason-code values | `rule_match`, `path_denied`, `approval_timeout`, etc. | C | Keep existing values. New binding/identity reason codes should also be brand-neutral. |
| Audit schema v4 filename/$id | `schema/agentfence-audit-event.schema.json`; `$id` under `github.com/dgenio/agentfence/...` | C/historical | Preserve the v4 schema artifact and historical `$id`. Do not rewrite an old schema identity merely because the repository is renamed. GitHub redirect may continue resolving the URL; retain/copy the historical schema if needed for durable access. |
| Future audit schema with #221/#222 fields | TBD | C/new contract | When the serialized contract substantively changes, introduce the new schema/version under the **VeriCordon** canonical repository/filename. Do not retroactively relabel v1–v4 records. |
| Audit hash chain | `prev_hash` / `hash` over canonical event bytes | C/evidence | **Never rewrite historical events.** Existing logs must verify byte-for-byte after rename. Brand migration must not require log conversion. |
| Ed25519 event signatures | signature over existing canonical event digest | C/evidence | **Never rewrite or resign historical events for branding.** Verification remains independent of current product name. |
| Audit anchors | commitments to existing log/event state | C/evidence | Preserve format and verification semantics. A historical anchor remains an AgentFence-era artifact but is valid under VeriCordon tooling. |
| Native audit-log filename/path chosen by operator | arbitrary | C/user config | No forced migration. Tooling reads whatever path is supplied. |
| Weaver export unknown capability/principal sentinels | `agentfence.unknown`, `agentfence.unknown-session` | D | Preserve for the existing weaver-spec v0 / AgentFence export contract. They are already serialized interop values. Change only in a deliberately versioned exporter/contract revision. |
| Weaver export metadata keys | `agentfence_decision`, `agentfence_schema_version` | D | Preserve in the current v0 exporter for compatibility and provenance. A future contract can add neutral/VeriCordon keys under a new documented mapping; do not silently rename current keys. |
| Weaver `decision_id` / `event_id` format | `pd-<principal>-<seq>`, `te-<principal>-<seq>` | D | Keep; these IDs are already brand-neutral. |
| Weaver source hashes | `prev_hash`, `hash` metadata | D/evidence | Keep unchanged so exported records continue to cross-check the native historical chain. |
| Policy YAML schema keys/decision values | `version`, `defaults`, `tools`, `allow|deny|ask`, constraints | C-ish user config | Keep. They are brand-neutral; no reason to make policies incompatible because of branding. |
| Policy file content imports | paths chosen by users | B/C | Do not rewrite arbitrary user import paths automatically. Examples can migrate; user files remain explicit configuration. |
| Planned policy/action/tool canonicalization IDs (#221/#222) | not public yet | C/new contract | **Use brand-neutral algorithm/version identifiers where practical.** Prefer identifiers describing semantics/version over embedding `AgentFence` or `VeriCordon`, so future brand changes do not invalidate content identities. |
| Metrics JSON snapshot field names | `total`, `by_decision`, `by_tool`, etc. | C-ish automation API | Keep because they are brand-neutral. Only the Prometheus metric-name namespace changes. |
| Operational log structured field names | current generic slog fields | C-ish automation API | Keep brand-neutral keys. Human text prefixes can rename. |
| GitHub Action/package/release IDs | AgentFence-branded paths/names | B | Migrate under #240 with explicit availability checks and a bounded compatibility story. |

## Audit schema strategy

The current audit JSON Schema is explicitly branded in its filename, `$id`, title and description, while the event payload itself is largely brand-neutral. It also describes schema version 4.

The migration should therefore **separate historical schema identity from future schema identity**:

```text
schema v1-v4
  -> historical AgentFence schema artifact remains available
  -> existing logs/signatures/hashes remain untouched

future substantive schema version (e.g. binding evidence)
  -> canonical VeriCordon schema artifact
  -> new repository URL / title / docs
  -> migration notes explain that earlier versions were produced under AgentFence
```

Do not create schema version 5 merely to change `title: AgentFence audit event` to `VeriCordon audit event`. Let #221/#222 serialized binding evidence drive a real schema bump.

## Environment-variable migration

Security-sensitive configuration needs deterministic precedence.

For `AGENTFENCE_PROXY_AUTH_TOKEN` -> `VERICORDON_PROXY_AUTH_TOKEN`, the safe transition behavior is:

```text
new only     -> use new
legacy only  -> use legacy + deprecation warning
both equal   -> use value; warn legacy is deprecated
both differ  -> startup failure (fail closed)
neither      -> existing no-token behavior/guardrails
```

Never include token values in the warning/error.

Apply the same principle to any other security-relevant environment variable discovered during #239/#240 rather than relying on environment-variable iteration/order.

## Metrics migration

Prometheus metric names are machine contracts, but this project is still pre-launch and has no retained-user evidence justifying a permanent dual namespace.

Therefore:

```text
agentfence_decisions_total
-> vericordon_decisions_total
```

and likewise for the rest of the family in one deliberate breaking pre-launch change.

Requirements:

- update metric tests/docs together;
- record the rename in CHANGELOG;
- do not emit old + new counters simultaneously indefinitely;
- if a temporary dual-emission release is chosen, tests must ensure values are identical and docs must warn that summing both double-counts the same events.

Default recommendation: **clean pre-launch rename, no long-lived dual metrics**.

## Error contract migration

JSON-RPC clients should be able to distinguish policy denial/transport/proxy failure from the numeric error code. The current implementation uses the AgentFence brand only in human-readable message text for some errors.

Migration rule:

```text
Code: -32001              -> keep
Message: blocked by ...   -> may rename to VeriCordon
```

Likewise for `-32002` through `-32005`: keep numbers; user-facing prose may change.

If existing tests parse human text as an API, update the tests to distinguish intentional documented text from accidental string coupling.

## Weaver interoperability

The current v0 exporter deliberately emits `agentfence_*` metadata and `agentfence.unknown*` sentinel values. Those are serialized external contract values, not README prose.

Do not silently emit `vericordon_decision` instead under the same contract version.

Short-term rule:

- current v0 mapping continues to produce existing `agentfence_*` keys/sentinels;
- docs say these are historical protocol/provenance names retained for compatibility;
- a future weaver-spec contract version may define neutral or VeriCordon-native fields, at which point the exporter can provide a separately tested mapping.

This is intentionally asymmetric: **the product can be VeriCordon while an old wire-format metadata key remains `agentfence_decision`.** Evidence compatibility is more important than cosmetic consistency.

## Canonicalization identifiers for #221/#222

Those contracts are not public yet, so the rename is an opportunity to avoid future branding coupling entirely.

Avoid identifiers such as:

```text
agentfence-action-v1
vericordon-action-v1
```

when a durable semantic identifier can instead describe the algorithm/contract, for example conceptually:

```text
tool-action-json-v1
resolved-policy-json-v1
mcp-tool-descriptor-json-v1
```

Exact names remain a design decision. The principle is that a content digest should not change because marketing changes.

## Required migration tests

Before #242 can close, the actual rename implementation must prove:

- [ ] a historical v4 hash-chained audit fixture still verifies under the renamed binary;
- [ ] a historical signed v4 audit fixture still verifies under the renamed binary/pubkey;
- [ ] an existing anchor still verifies;
- [ ] JSON-RPC `-32001` … `-32005` values are unchanged;
- [ ] existing reason-code values are unchanged;
- [ ] current Weaver v0 export keeps its existing metadata/sentinel contract;
- [ ] legacy auth env fallback follows deterministic precedence and conflicting values fail closed if the alias is implemented;
- [ ] new Prometheus namespace is exactly `vericordon_*` with no accidental mixed names;
- [ ] old policy YAML semantics remain readable when passed explicitly;
- [ ] future #221/#222 canonicalization version identifiers are brand-neutral before becoming public.

## Search/cleanup rule

A final repository-wide search for `agentfence` is **not** expected to return zero results.

Remaining occurrences are correct when they are intentionally:

- historical changelog/release text;
- v1-v4 schema identity/artifacts;
- Weaver v0 compatibility metadata/sentinels;
- legacy env/config compatibility handling;
- migration documentation;
- `formerly AgentFence` context.

Every remaining occurrence should be explainable by this matrix. Unknown/unclassified occurrences are migration bugs until reviewed.
