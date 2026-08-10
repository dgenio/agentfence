# Dependency automation policy

AgentFence keeps dependency automation deliberately reviewable:

- routine compatible Go and GitHub Actions updates are grouped;
- security updates are grouped separately;
- unrelated breaking Action upgrades remain separate;
- the closely-coupled Docker Action stack may move together;
- third-party GitHub Actions are pinned to immutable commit SHAs, with version comments retained for readability;
- Dependabot updates the immutable Action pins instead of relying on mutable major tags.

This keeps the review queue quiet without hiding breaking changes inside broad catch-all groups.
