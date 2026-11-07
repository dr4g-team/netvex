# Changelog

All notable changes to NetVex are documented in this file. The project follows
[Semantic Versioning](https://semver.org/) and
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [1.0.2] - 2026-11-07

### Added

- Opt-in AIMD concurrency, learned TCP timeouts, selective prescreen retries,
  staged target matrices, minimal working-list evidence, and TLS session reuse.
- Bounded, expiring caches for deterministic gateway failures, successful auto
  protocol detection, and public Digest challenges.

### Changed

- A successful TCP prescreen now transfers its live socket into the first
  validation attempt, removing a redundant DNS lookup and TCP handshake.
- SOCKS5 auto-detection continues negotiation on its sniff socket instead of
  reconnecting for authentication and CONNECT.
- The `fast` profile enables connection reuse and conservative gateway,
  protocol, and Digest challenge caches; all runtime-adaptive controls remain
  opt-in.

### Security

- Authentication caching stores only server challenges. Proxy credentials and
  generated authorization values are never retained.
- Cancellation drains ownership of buffered prescreen sockets, preventing
  descriptor leaks during interrupted high-concurrency runs.
- Static analysis runs on the fully patched Go 1.26.10 toolchain, avoiding
  incompatibilities when analysis tools inspect newer toolchain internals;
  release binaries remain built with Go 1.27.3.

## [1.0.1] - 2026-11-03

### Changed

- CI, native portability, CodeQL, scheduled fuzzing, and release publication
  now share one event-aware GitHub Actions workflow instead of four independent
  definitions.
- The repository moved to `drag-team/netvex-go`. The Go module path is now
  `github.com/drag-team/netvex-go`, and schema `$id`s, build metadata, and
  documentation links follow it. Old repository URLs redirect to the new
  location.

### Fixed

- Branch, tag, scheduled, and manual events now select only their relevant jobs,
  preventing ordinary CI from accidentally entering release or fuzzing paths.
- The first successful consolidated run performs the requested one-time cleanup
  of superseded Actions runs; later runs retain normal audit history.
- Ignore root Windows binaries (`*.exe`), checkpoints (`*.checkpoint.jsonl*`),
  and Prometheus metrics snapshots in `.gitignore`.

## [1.0.0] - 2026-11-01

### Added

- Complete HTTP, TLS-encrypted HTTP proxy, CONNECT, SOCKS4, SOCKS4a, and
  SOCKS5 validation with Basic, Digest, user-ID, and username/password
  authentication evidence.
- Streaming text, commercial colon, CSV, JSON, JSONL, gzip, and bzip2 input;
  streaming table, TXT, CSV, JSON, and JSONL output.
- Bounded concurrency, rate limiting, per-target pressure, retries, target
  matrices, quorum qualification, preflight checks, direct canaries, and an
  optional wide TCP prescreen.
- TLS, latency, throughput, response-integrity, anonymity, exit rotation,
  offline country/ASN/network, and pool-diversity evidence.
- Atomic private working lists, resumable checkpoints, compressed local run
  history, filtering, exports, run comparison, retention, Prometheus textfile
  metrics, JUnit reports, JSON Schema, and shell completion.
- Static multiplatform builds, reproducibility checks, fuzzing, race detection,
  CodeQL, vulnerability analysis, an SPDX SBOM, and build provenance.

### Changed

- NetVex now uses the stable `1.Y.Z` release line. Backward-compatible features
  increment the minor version and compatible fixes increment the patch version.
- Result and run-summary schema version 7 is the stable v1 evidence format.
- Saved credentialed proxy IDs use a local keyed identity so accounts sharing
  one gateway stay distinct without exposing a credential verifier.
- Large inputs, responses, outputs, and saved runs remain streamed and bounded;
  optional compression uses low-overhead settings appropriate for the result loop.

### Fixed

- Path validation now covers CPU and memory profiles plus checkpoint sidecars
  before any file is created, preventing `--force` from truncating an input or
  overlapping two requested outputs.
- Profile finalization failures now return an operational exit code.
- Socket-dependent tests skip cleanly when the execution sandbox forbids local
  listeners instead of reporting a product failure.
- CI uses the compiler selected by each matrix entry instead of silently
  replacing it through Go toolchain auto-selection.
- Retention ages reject duration overflow rather than wrapping to a different age.

### Security

- Percent-encoded control characters and invalid UTF-8 are rejected in proxy
  credentials before they can reach Digest headers or working-list templates.
- Persisted results, summaries, metadata, TLS evidence, and HTTP evidence are
  validated or sanitized before terminal presentation.
- Identity keys must contain exactly 32 bytes and remain private regular files.
- Destination and proxy gateway policy blocks loopback, private, link-local,
  metadata, transition, documentation, multicast, and other special-purpose
  addresses unless the corresponding deliberate exception is enabled.
- TLS verification remains enabled for proxy and destination connections;
  optional certificate pins detect interception by otherwise trusted roots.

[Unreleased]: https://github.com/drag-team/netvex-go/compare/v1.0.2...HEAD
[1.0.2]: https://github.com/drag-team/netvex-go/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/drag-team/netvex-go/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/drag-team/netvex-go/releases/tag/v1.0.0
