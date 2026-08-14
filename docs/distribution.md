# Distribution & outreach

This page tracks the distribution work for AgentFence and records the parts
that **cannot** be done from a pull request (they need repository-admin access,
an external account, or a sibling repository). It is the in-repo half of issues
[#74](https://github.com/dgenio/agentfence/issues/74),
[#79](https://github.com/dgenio/agentfence/issues/79), and
[#76](https://github.com/dgenio/agentfence/issues/76).

## Demo (#74)

[`examples/demo-blocked-call.sh`](../examples/demo-blocked-call.sh) is the
recordable flagship demo. It runs the real AgentFence stdio proxy in front of
the bundled MCP stub, allows a bounded read that returns prompt-injected text,
and then denies the injected secret-bearing `.env` write before the stub sees
it. A diagnostic request to the stub proves only `filesystem.read` crossed the
boundary. The redacted, hash-chained runtime events must match the committed
[`hero-expected-audit-receipt.jsonl`](../examples/hero-expected-audit-receipt.jsonl)
or the demo and CI fail.

The complete maintained evidence set is the
[`hero policy`](../examples/hero-policy.yaml),
[`request fixture`](../examples/hero-requests.jsonl),
[`expected terminal summary`](../examples/hero-expected.txt),
[`expected audit receipt`](../examples/hero-expected-audit-receipt.jsonl), and
[`boundary explanation`](../examples/hero-demo.md).
The bounded release, article, and technical-community copy lives in the
[`launch brief`](launch-brief.md); it must not be published before the exact
merged demo and CI are green.

Two further hermetic, runnable demos back this up (no network or npm — they wrap
the bundled [`examples/stub-mcp-server`](../examples/stub-mcp-server)):

- [`examples/proxy-smoke.sh`](../examples/proxy-smoke.sh) — the live stdio proxy
  forwarding an allowed read and blocking a denied write.
- [`examples/taint-scenario/`](../examples/taint-scenario/) — the confused-deputy
  guard blocking a write whose argument came from untrusted tool output.

These are supporting examples; `demo-blocked-call.sh` is the canonical launch
path and the only one that should appear in the README hero.

To record the README GIF/asciinema:

```bash
# asciinema (then upload, or convert to GIF with agg):
asciinema rec demo.cast -c './examples/demo-blocked-call.sh'
agg demo.cast docs/img/demo.gif      # https://github.com/asciinema/agg
```

The recording must show the complete `PASS` result and must be regenerated from
the script rather than edited into a stronger claim. The text representation in
the README remains the accessible, copy/pasteable source of truth.

### Listing copy (for registry / awesome-list submissions)

> **AgentFence** — an open, local, no-telemetry policy gate for MCP tool calls.
> Drop it in front of any MCP server (stdio or streamable HTTP) to allow / deny
> / ask on each `tools/call`, redact secrets, and keep a tamper-evident audit
> trail. Optional confused-deputy (taint) detection escalates calls whose
> arguments derive from untrusted tool output.

### Submission checklist (external — needs a maintainer)

These require pushing to other repositories or registry accounts and cannot be
done from this repo's CI:

- [x] Official MCP Registry eligibility reviewed (2026-08-10): **N/A**. The
      [official registry](https://modelcontextprotocol.io/registry/about) is a
      metadata catalog for publicly installable or accessible MCP *servers*.
      AgentFence is a policy proxy around a server chosen by the operator, not
      a standalone server product. Do not manufacture a server wrapper only to
      obtain a listing.
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

## Installation channels

The release pipeline (`.goreleaser.yml` + `.github/workflows/release.yml`)
produces all of the following on each tagged release.

### Install script (#105)

```bash
curl -fsSL https://raw.githubusercontent.com/dgenio/agentfence/main/scripts/install.sh | sh
```

[`scripts/install.sh`](../scripts/install.sh) detects OS/arch, downloads the
matching archive, verifies it against `checksums.txt`, and **fails closed on a
mismatch**. Override with `AGENTFENCE_VERSION` (e.g. `v0.9.0`) and
`AGENTFENCE_INSTALL_DIR`.

### Homebrew (#105)

```bash
brew install dgenio/tap/agentfence
```

GoReleaser publishes a Homebrew **cask** to `dgenio/homebrew-tap` that installs
the binary, the bash/zsh/fish completions, and the man page.

### Scoop and winget (#120)

```powershell
scoop bucket add dgenio https://github.com/dgenio/scoop-bucket
scoop install agentfence
# or
winget install dgenio.agentfence
```

GoReleaser publishes a Scoop manifest to `dgenio/scoop-bucket` and opens a
winget manifest PR against `microsoft/winget-pkgs`.

### Container image (#104)

A minimal, non-root, multi-arch (linux/amd64 + linux/arm64) image is published
to `ghcr.io/dgenio/agentfence` (tagged per release and `latest`), built from
[`Dockerfile.goreleaser`](../Dockerfile.goreleaser) on a distroless static base.

```bash
# Smoke test
docker run --rm ghcr.io/dgenio/agentfence:latest version

# Run the HTTP proxy with a mounted policy and an audit-log volume
docker run --rm -p 8787:8787 \
  -v "$PWD/policy.yaml:/policy/policy.yaml:ro" \
  -v "$PWD/audit:/audit" \
  ghcr.io/dgenio/agentfence:latest \
  proxy-http --upstream http://upstream:9000 \
    --policy /policy/policy.yaml --listen 0.0.0.0:8787 \
    --audit-log /audit/audit.jsonl
```

For a from-source build, the top-level [`Dockerfile`](../Dockerfile) (used by
`make docker`) compiles the binary itself. **Security note:** bind the HTTP
proxy to a trusted network and terminate TLS at a trusted layer — see
[`threat-model.md`](threat-model.md).

### Shell completions and man page (#107)

The binary generates its own completions and man page, so release archives can
never drift from the CLI:

```bash
agentfence completion bash > /etc/bash_completion.d/agentfence
agentfence completion zsh  > "${fpath[1]}/_agentfence"
agentfence completion fish > ~/.config/fish/completions/agentfence.fish
agentfence man             > /usr/local/share/man/man1/agentfence.1
```

Release archives bundle them under `completions/` and `manpages/`; the Homebrew
cask installs them automatically. Regenerate locally with `make completions`
and `make man`.

## Verifying a release (#111)

Each release is cosign-signed (keyless, via GitHub OIDC) and ships an SBOM.

```bash
# Verify the checksums signature (keyless / Fulcio + Rekor):
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/dgenio/agentfence/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  checksums.txt

# Then verify your archive against the signed checksums:
sha256sum --check --ignore-missing checksums.txt

# Verify the container image signature:
cosign verify ghcr.io/dgenio/agentfence:latest \
  --certificate-identity-regexp 'https://github.com/dgenio/agentfence/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

The per-archive SBOM (CycloneDX/SPDX via Syft) is attached to the release.

### Release prerequisites (external — needs a maintainer)

The publish steps require repository-admin setup that cannot be done from a PR:

- [ ] Create the `dgenio/homebrew-tap` repository and a
  `HOMEBREW_TAP_GITHUB_TOKEN` secret with write access to it (#105).
- [ ] Create the `dgenio/scoop-bucket` repository and a
  `SCOOP_BUCKET_GITHUB_TOKEN` secret (#120).
- [ ] Create a `dgenio/winget-pkgs` fork and a `WINGET_GITHUB_TOKEN` secret for
  the winget manifest PR (#120).
- [ ] No secret is needed for GHCR (uses the workflow `GITHUB_TOKEN` with
  `packages: write`) or for cosign signing (uses OIDC `id-token: write`); both
  permissions are already set in `release.yml` (#104, #111).
