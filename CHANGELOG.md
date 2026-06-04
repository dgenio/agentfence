# Changelog

All notable changes to AgentFence are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-06-04

### Added
- `audit export --format weaver-trace` emits audit decision records as a
  [weaver-spec](https://github.com/dgenio/weaver-spec) v0 (contract 0.6.0)
  aligned JSONL trace stream (a `PolicyDecision` and matching `TraceEvent` per
  event), so AgentFence findings can feed Weaver Stack consumers such as
  lessonweaver. The export is read-only over the native log, so the
  hash-chained audit remains verifiable. See [`docs/interop.md`](docs/interop.md). (#77)

## [Unreleased]

[Unreleased]: https://github.com/dgenio/agentfence/compare/v0.5.0...HEAD
