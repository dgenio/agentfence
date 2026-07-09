#!/usr/bin/env bash
# check-examples.sh — exercise every bundled example against the built binary so
# the examples/ directory can never silently drift from the current schema/CLI
# (issue #181). Hermetic: no network, writes only to a temp dir.
#
# Usage:
#   ./scripts/check-examples.sh                 # builds ./agentfence if needed
#   AGENTFENCE=/path/to/agentfence ./scripts/check-examples.sh
set -euo pipefail

cd "$(dirname "$0")/.."

AGENTFENCE="${AGENTFENCE:-./agentfence}"
if [ ! -x "$AGENTFENCE" ]; then
  echo "+ building agentfence"
  go build -o ./agentfence ./cmd/agentfence
  AGENTFENCE=./agentfence
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

fail=0
run() { # run "<description>" cmd...
  local desc="$1"; shift
  if "$@" >"$workdir/out.txt" 2>&1; then
    echo "  ok   $desc"
  else
    echo "  FAIL $desc (exit $?)"
    sed 's/^/       | /' "$workdir/out.txt"
    fail=1
  fi
}

echo "+ validate every example policy"
for p in policy base-policy project-policy unsafe-policy; do
  run "validate examples/$p.yaml" "$AGENTFENCE" validate --policy "examples/$p.yaml"
done

echo "+ policy fixture tests"
run "policy test (policy.yaml + policy-tests.yaml)" \
  "$AGENTFENCE" policy test --policy examples/policy.yaml --tests examples/policy-tests.yaml

echo "+ batch check over the recorded tool calls"
run "check (policy.yaml + tool-calls.jsonl)" \
  "$AGENTFENCE" check --policy examples/policy.yaml --call examples/tool-calls.jsonl \
  --no-interactive --audit-log "$workdir/check-audit.jsonl"

echo "+ audit subcommands over the bundled audit log"
run "audit summarize (audit-log.jsonl)" "$AGENTFENCE" audit summarize --log examples/audit-log.jsonl
run "audit verify (audit-log.jsonl)"    "$AGENTFENCE" audit verify    --log examples/audit-log.jsonl
run "audit export weaver-trace"          "$AGENTFENCE" audit export    --log examples/audit-log.jsonl --format weaver-trace

echo "+ end-to-end demo (build + check + tamper-evident verify)"
run "examples/demo-blocked-call.sh" env AGENTFENCE="$AGENTFENCE" bash examples/demo-blocked-call.sh

if [ "$fail" -ne 0 ]; then
  echo "examples validation FAILED — an example drifted from the current CLI/schema." >&2
  exit 1
fi
echo "All examples validated."
