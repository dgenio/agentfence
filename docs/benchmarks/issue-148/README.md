# Issue #148 large-trace engine baseline

This packet records a reproducible baseline for
`BenchmarkEvaluateLargeTrace`. It is measurement evidence for issue #148, not a
performance claim or a regression threshold.

This baseline is infrastructure for a later before/after comparison. It does
not complete issue #148's candidate-measurement acceptance criterion.

## Workload

The benchmark generates every policy and tool call in memory. No trace fixture
is committed. Each tier has:

- `N` deterministic calls in the trace pool;
- `M` named groups, each with a group rule and one member wildcard;
- `M` wildcard tool rules; and
- one exact tool rule.

Calls cycle through four paths in equal proportions: group allow, wildcard ask,
exact allow, and default deny. One benchmark operation is one complete
`Engine.Evaluate` call. Setup and corpus generation occur outside the timer.
The command fixes `b.N` at 50,000, so the 10,000-call pool is traversed five
times per sample and the 50,000-call pool once per sample.

This measures the whole evaluation path, including decision evaluation,
redaction, audit-event construction, and any repeated rule lookup. It does not
isolate `lookupRule`.

## Recheck the baseline

Checkout benchmark source commit
`2698daecf61d9b3843d0843a612bd2aa6287973a`, confirm the working tree is clean,
and run this one-line command in PowerShell, Bash, or another shell:

```bash
go test ./internal/engine -run '^$' -bench '^BenchmarkEvaluateLargeTrace$' -benchmem -benchtime=50000x -count=5
```

The committed raw output is
[`baseline-windows-amd64-go1.25.11.txt`](baseline-windows-amd64-go1.25.11.txt).
The command, source revision, toolchain, OS, CPU, logical processor count, and
memory are recorded in
[`environment-windows-amd64-go1.25.11.json`](environment-windows-amd64-go1.25.11.json).

Verify the two evidence inputs before comparing them:

```text
baseline-windows-amd64-go1.25.11.txt
  266d696e18ac1d62ba463db641b569922272c7bb6a24f5f25da252c1b5f6e5d5
environment-windows-amd64-go1.25.11.json
  a1709509ec17f0952c7cd260834e662fbebfacfc026bc847edcc755620e94124
```

Use `sha256sum` on Unix-like hosts or `Get-FileHash -Algorithm SHA256` in
PowerShell. The same paths and hashes also appear in
[`measurement-packet.json`](measurement-packet.json).

## Observed baseline

The interval below is the minimum and maximum of five local samples, not a
confidence interval. The median is included as a compact center. Every sample
contains 50,000 evaluated calls.

| Tier | Median ns/call | Observed ns/call range | Observed B/call range | allocs/call |
|---|---:|---:|---:|---:|
| N=10,000 / M=16 | 129,650 | 124,456 to 135,499 | 211,690 to 211,696 | 2,336 |
| N=50,000 / M=64 | 418,562 | 417,139 to 423,296 | 840,450 to 840,453 | 9,222 |

These values describe Windows amd64, Go 1.25.11, and the host in the environment
file. They do not establish results for Linux, macOS, hosted CI, or another Go
release.

## Before and after procedure

The machine-readable packet intentionally has `comparison.status` set to
`baseline_only`; its candidate source, artifact, and delta are `null`. To
evaluate a future optimization:

1. Use the same machine, power conditions, Go toolchain, command, and clean
   working-tree requirement.
2. Run the baseline commit and save its raw output without editing it.
3. Run the candidate commit and save its raw output without editing it.
4. Record the candidate commit, environment, command, and SHA-256 hashes.
5. Compare all five samples per tier. Report the interval and denominator, not
   only a best run or percentage.

No CI threshold is proposed here. Threshold selection needs repeated evidence
from the actual CI runners, including their variance and false-positive rate.

## What this packet does not prove

- It does not demonstrate an optimization or speedup because no candidate is
  present.
- It does not attribute the measurements only to `lookupRule`.
- It does not show production latency under concurrency, I/O, or proxy load.
- It does not justify a regression threshold from one host and five samples.
- It does not require Forum or any non-Go tool to reproduce the benchmark.
