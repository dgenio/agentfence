# Issue #148 large-trace engine baseline

This packet records a reproducible baseline for
`BenchmarkEvaluateLargeTrace`. It is measurement evidence for issue #148, not a
performance claim or a regression threshold.

The packet now carries both sides: the original go1.25.11 baseline, and a
measured before/after comparison for the `lookupRule` precompute (see
"Before and after: lookupRule precompute" below). Whether this satisfies
issue #148's acceptance criteria is the maintainer's call.

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

Note: commit `2698daecf61d9b3843d0843a612bd2aa6287973a` was the pre-squash PR
commit. The benchmark landed in upstream `main` at
`5c675cb4477c9b396443018cd8743b99c8339a52` (the #253 squash), which also
carries this packet and a slightly extended `benchmark_test.go`. New
measurements should anchor on the merged commit.

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

## Before and after: lookupRule precompute (measured 2026-08-21)

The `TODO(perf)` in `lookupRule` is now resolved: `engine.New` precomputes the
sorted group-name list and the sorted non-group pattern-key list, so a rule
lookup no longer allocates or sorts per call. This section records the
before/after comparison the baseline packet was built for.

- Baseline source commit: `5c675cb4477c9b396443018cd8743b99c8339a52`
  (upstream `main`, the merged #253 benchmark).
- Candidate source commit: `2867339b615914f6c6a0dddfedc96935f3bc995a`
  (the precompute change).
- Toolchain: go1.26.7 windows/amd64, same host as the go1.25.11 baseline
  (see
  [`environment-windows-amd64-go1.26.7.json`](environment-windows-amd64-go1.26.7.json)).
  Because the toolchain moved from go1.25.11, the baseline was re-measured at
  the merged commit instead of comparing against the go1.25.11 numbers above.

### Method

Sequential `-count=10` runs on this host showed session-to-session drift up to
roughly 1.4x in ns/op, enough to swamp the effect under test. The comparison
therefore uses interleaved A/B sampling: both test binaries were built once
with `go test -c ./internal/engine`, then executed alternately, baseline then
candidate, for ten pairs. Each invocation ran:

```text
<binary> -test.run '^$' -test.bench '^BenchmarkEvaluateLargeTrace$' -test.benchmem -test.benchtime 50000x
```

That yields ten samples per side per tier, 50,000 evaluated calls per sample.
Raw outputs are committed unedited:
[`baseline-interleaved-windows-amd64-go1.26.7.txt`](baseline-interleaved-windows-amd64-go1.26.7.txt)
and
[`candidate-interleaved-windows-amd64-go1.26.7.txt`](candidate-interleaved-windows-amd64-go1.26.7.txt).
The benchstat comparison is
[`benchstat-windows-amd64-go1.26.7.txt`](benchstat-windows-amd64-go1.26.7.txt).

### Results

Ten samples per side per tier; every sample evaluates 50,000 calls with the
fixed mix of one quarter each group, wildcard, exact, and default-deny lookups.
Medians and spreads are benchstat's.

| Tier | Side | ns/op median | ns/op spread | B/op observed range | allocs/op |
|---|---|---:|---:|---:|---:|
| N=10,000 / M=16 | baseline | 124,956 | ±26% | 211,621 to 211,624 | 2,336 |
| N=10,000 / M=16 | candidate | 123,389 | ±8% | 209,720 to 209,721 | 2,331 |
| N=50,000 / M=64 | baseline | 445,071 | ±11% | 840,399 to 840,402 | 9,222 |
| N=50,000 / M=64 | candidate | 434,928 | ±24% | 832,867 to 832,870 | 9,217 |

benchstat deltas, candidate vs baseline:

| Tier | sec/op | B/op | allocs/op |
|---|---|---|---|
| N=10,000 / M=16 | ~ not significant (p=0.631) | -0.90% (p=0.000) | -5/op, 2,336 to 2,331 (-0.21%, p=0.000) |
| N=50,000 / M=64 | ~ not significant (p=0.280) | -0.90% (p=0.000) | -5/op, 9,222 to 9,217 (-0.05%, p=0.000) |

Reading of the numbers, on this host and toolchain only:

- Per-call allocations dropped by exactly 5 in both tiers, in every one of the
  ten samples per side. Per-call bytes dropped 0.90% in both tiers. These are
  the direct effect of removing the per-call slice, map, and sort work.
- Wall time shows no statistically significant change on either tier. The
  point estimates are slightly negative, but host noise dominates. An earlier
  sequential count=10 pair during a quieter session measured -9.23% sec/op on
  the N=50,000 tier (p=0.002); the interleaved comparison did not confirm it,
  so this packet claims no time improvement. The honest result on time is a
  null.

The allocation win is real but small relative to the total, because
`matchesGlob` falls back to compiling a regular expression for every
non-matching glob comparison, and that fallback dominates the allocation count
in this workload. The precompute removes only the per-call slice, map, and
sort work that the TODO named. Regex caching in `matchesGlob` is a separate,
larger optimization that this change deliberately does not attempt.

### Verify the comparison artifacts

```text
baseline-interleaved-windows-amd64-go1.26.7.txt
  d9f62827cefa56d4114c3a16e9d56dc02c187720a0012421b8e55c5f96417dda
candidate-interleaved-windows-amd64-go1.26.7.txt
  600522b568513291b285c656375d9c068c89a70c02fe90a49e05867166f3f72d
benchstat-windows-amd64-go1.26.7.txt
  4a4c88f40194fef503a27a6e5ad74dcf60dd72a98b74f1da224c4e04e4541357
environment-windows-amd64-go1.26.7.json
  0dc7e485449a358f5c27526395c6a0b1b4c27cc216f999804352d1f9df692d4f
```

## Optional CI regression guard (documented, not enforced)

Issue #114 asks for benchmarks with a CI step that is "informational, or gated
with a tool like benchstat/benchcheck against a baseline". This packet
documents a threshold derived from the measured variance; it does not wire any
CI. Adopting or rejecting it is a maintainer decision on #114.

- `allocs/op` on these fixed tiers is near-deterministic: zero spread within
  the interleaved runs, and at most 1 allocation of spread across every run
  recorded while preparing this packet. A hard informational guard of
  **allocs/op must not exceed the recorded candidate values (2,331 for
  N=10,000/M=16 and 9,217 for N=50,000/M=64) by more than 2%** would have had
  zero false positives on every recorded run and still catches any
  reintroduced per-call allocation many times that size.
- `ns/op` is not a sound absolute gate. On a single otherwise-idle-looking
  desktop, session-to-session medians moved up to ~1.4x with no code change.
  A time gate needs same-run interleaved baseline/candidate execution (as
  above) and a statistical test; benchstat's p-value against the merge-base,
  run on the same CI job, reported as informational output, is the workable
  form. Hosted-runner variance still needs its own measurement before any
  hard time threshold.

## What this packet does not prove

- The comparison attributes the delta to the candidate commit on one host and
  one toolchain; it does not establish cross-platform or hosted-CI numbers.
- It does not attribute the measurements only to `lookupRule`; one benchmark
  operation is a full `Engine.Evaluate`, including redaction and audit-event
  construction.
- It does not show production latency under concurrency, I/O, or proxy load.
- It does not demonstrate a wall-time improvement on either tier: the sec/op
  deltas are within host noise (p=0.631 and p=0.280). Only the allocation and
  byte reductions are established.
- It does not justify enforcing a CI threshold; the guard above is documented,
  not wired, per the optional wording of #148 and #114.
- It does not require Forum or any non-Go tool to reproduce the benchmark.
