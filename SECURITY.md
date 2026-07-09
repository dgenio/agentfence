# Security Policy

AgentFence is a security tool. We take vulnerabilities in it seriously and
appreciate coordinated disclosure.

## Supported Versions

AgentFence is pre-1.0 and under active development. Security fixes are applied
to the latest released minor version; older versions are not maintained.

| Version | Supported          |
| ------- | ------------------ |
| 0.4.x   | :white_check_mark: |
| < 0.4   | :x:                |

## Reporting a Vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately using GitHub's
[private vulnerability reporting](https://github.com/dgenio/agentfence/security/advisories/new)
— the **"Report a vulnerability"** button under the repository's **Security**
tab. This opens an advisory visible only to the maintainers.

Where possible, include:

- a description of the issue and its impact,
- steps to reproduce or a proof of concept,
- affected version(s) and configuration,
- any suggested remediation.

### What to expect

- **Acknowledgement** within 3 business days.
- An **initial assessment** and severity triage within 10 business days.
- **Coordinated disclosure:** we will agree a disclosure timeline with you and
  credit reporters who wish to be named.

## Supply-chain hygiene

AgentFence keeps a deliberately small dependency footprint and automates the
rest:

- **Dependency and Action updates** are proposed automatically by Dependabot
  (`.github/dependabot.yml`) for both the Go module and pinned GitHub Actions.
- **Vulnerability scanning** runs `govulncheck` in CI on every change (and
  `make vuln` locally).
- **Static analysis** runs `gosec` and `golangci-lint` in CI (`make lint`).
  Intentional `gosec` findings are annotated inline with
  `// #nosec <rule> -- <reason>` rather than disabled globally.
- **Release artifacts** are signed with cosign and ship an SBOM (see
  [`docs/distribution.md`](docs/distribution.md)).

## Scope

AgentFence enforces policy *before* a tool call executes; it is **not a
sandbox** and does not contain a call already forwarded to a tool server (see
[`docs/threat-model.md`](docs/threat-model.md)). Behavior explicitly documented
as out of scope in the threat model may be closed as informative — but if in
doubt, report it and let us decide.
