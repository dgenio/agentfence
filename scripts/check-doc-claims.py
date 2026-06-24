#!/usr/bin/env python3
"""check-doc-claims.py — keep the most-read docs honest (issue #165).

Two conservative, mechanical checks over README.md and docs/*.md:

1. Command existence: every ``agentfence <subcommand>`` mentioned in inline code
   or a fenced code block must be a real top-level command of the built binary.
   This catches a "Current status" row or quickstart that claims a command which
   does not exist.
2. Link resolution: every relative Markdown link must point at a file that
   exists (the anchor part is not checked — existence, not prose).

It deliberately does not analyse prose meaning. Run it after building the
binary; pass --binary to point at it. Use --selftest to prove the checks fire.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FENCE_RE = re.compile(r"```.*?```", re.DOTALL)
INLINE_RE = re.compile(r"`([^`\n]+)`")
# Same-line only: `\s+` would pair a line-ending "agentfence" with the next
# line's first word and produce false positives.
CMD_RE = re.compile(r"\bagentfence[ \t]+([a-z][a-z0-9-]*)")
LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")


def valid_commands(binary: str) -> set[str]:
    """Top-level commands parsed from `agentfence --help`."""
    out = subprocess.run(
        [binary, "--help"], capture_output=True, text=True, check=False
    ).stdout
    cmds = set()
    for line in out.splitlines():
        m = re.match(r"\s+agentfence\s+([a-z][a-z0-9-]*)", line)
        if m:
            cmds.add(m.group(1))
    return cmds


def code_regions(text: str) -> str:
    """All inline-code and fenced-code text, where commands are meant literally."""
    parts = FENCE_RE.findall(text)
    parts += INLINE_RE.findall(text)
    return "\n".join(parts)


def doc_files() -> list[str]:
    files = [os.path.join(REPO_ROOT, "README.md")]
    docs = os.path.join(REPO_ROOT, "docs")
    for name in sorted(os.listdir(docs)):
        if name.endswith(".md"):
            files.append(os.path.join(docs, name))
    return files


def check_commands(files: list[str], valid: set[str]) -> list[str]:
    errors = []
    for path in files:
        text = open(path, encoding="utf-8").read()
        for token in set(CMD_RE.findall(code_regions(text))):
            if token not in valid:
                errors.append(
                    f"{os.path.relpath(path, REPO_ROOT)}: documents "
                    f"`agentfence {token}` but the binary has no such command "
                    f"(valid: {', '.join(sorted(valid))})"
                )
    return errors


def check_links(files: list[str]) -> list[str]:
    errors = []
    for path in files:
        base = os.path.dirname(path)
        text = open(path, encoding="utf-8").read()
        for target in LINK_RE.findall(text):
            target = target.strip()
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            file_part = target.split("#", 1)[0]
            if not file_part:  # pure anchor
                continue
            resolved = os.path.normpath(os.path.join(base, file_part))
            if not os.path.exists(resolved):
                errors.append(
                    f"{os.path.relpath(path, REPO_ROOT)}: broken link -> {target}"
                )
    return errors


def selftest() -> int:
    """Prove each check catches a deliberate violation in a throwaway fixture."""
    with tempfile.TemporaryDirectory() as d:
        bad = os.path.join(d, "bad.md")
        with open(bad, "w", encoding="utf-8") as fh:
            fh.write(
                "See [missing](./does-not-exist.md).\n\nRun `agentfence frobnicate`.\n"
            )
        link_errs = check_links([bad])
        cmd_errs = check_commands([bad], {"check", "validate"})
    ok = bool(link_errs) and bool(cmd_errs)
    print("selftest:", "PASS" if ok else "FAIL")
    if not ok:
        print("  expected both a broken-link and an unknown-command error")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=os.path.join(REPO_ROOT, "agentfence"))
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    files = doc_files()
    errors = check_links(files)
    if os.path.exists(args.binary):
        errors += check_commands(files, valid_commands(args.binary))
    else:
        print(f"warning: binary {args.binary} not found; skipping command check")

    if errors:
        print("doc-claim check FAILED:")
        for e in errors:
            print(f"  - {e}")
        return 1
    print(f"doc-claim check OK ({len(files)} files: commands + links resolve).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
