# Changelog

All notable changes to NetVex are documented in this file. The project uses
[Semantic Versioning](https://semver.org/) and follows the structure of
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `--save-gzip` stores runs compressed. Every command reads both formats.
- HTTP Digest proxy authentication with MD5 and SHA-256 over CONNECT.
- `--pin-sha256` detects TLS interception by a CA this host trusts.
- `--no-cleartext-credentials` never sends a password without encryption.
- `runs prune --older-than`, suggestions for mistyped commands, and shell completion
  for every command.

### Changed

- **Breaking:** redirects from HTTPS to plain HTTP are refused with
  `redirect_downgrade`. `--allow-redirect-downgrade` restores them.
- `check --help` groups options by task.
- `check` explains missing input on a terminal instead of waiting for it.
- Pooled request buffers nearly halve the memory of a validation.
- `--keep-partial` now also publishes saved runs and reports after an interruption,
  marked `interrupted` in the summary. Result schema version 7.
- `inspect` no longer writes the proxy, including credentials, to a temporary file,
  accepts `-` to read it from standard input, and accepts flags before the proxy.
- When this host runs out of sockets or descriptors, new attempts pause briefly
  instead of failing together.
- Redirects reuse the destination DNS cache, keyed by origin so remote paths cannot
  grow it.
- `--expect-json` paths accept array indexes, as in `items.0.id=7`.
- `doctor` reports effective prescreen workers.
- `--output-status` accepts a comma-separated list.
- Saving results reuses one buffer, about halving per-result allocation.

### Fixed

- `--save-status` was refused when saving came from the configuration or
  `NETVEX_SAVE` rather than the `--save` flag.
- Time to first byte ignored earlier hops of a redirect.
- `--rate` lost capacity on Windows, where timer overshoot exceeded the catch-up
  window: 5,000/s delivered 3,439/s.
- Commit history on `main` after `427e7fe` was rewritten to remove co-author
  trailers, so tag `v0.7.0` is not an ancestor of `main`. Its tree is identical to
  the commit `4313964` on `main`.

## [0.7.0] - 2026-11-01

### Changed

- **Breaking:** proxy gateways on private, loopback, link-local, carrier-grade NAT,
  and reserved addresses are refused at connect time. Use `--allow-private-proxies`
  for your own local proxies.
- **Breaking:** result schema version 6. `id` now separates accounts sharing one
  gateway using a keyed hash, so credentialed IDs differ from earlier versions.
  Resuming an older checkpoint revalidates those proxies.
- **Breaking:** Go 1.26 is the minimum; release archives use Go 1.27.3. Go 1.24 was
  unsupported and govulncheck reported 24 reachable standard-library issues.
- A gateway now proves TCP reachability before occupying a destination slot, which
  doubles effective workers at defaults. Queue time is reported as `queue_ms` and no
  longer counts toward latency or the request timeout.
- `auto` stops at the first TCP failure and fingerprints the protocol with one
  connection, reducing dials per dead proxy from 6.3 to 2.
- The `fast` profile enables `--prescreen`.
- `elite` now requires an echoed header set; a body with only an address is
  `undetermined`. More forwarding headers count as evidence.
- `check` is reorganized around a session, and the CLI and engine are split by
  responsibility.

### Fixed

- `--resume` skipped every other account on a shared gateway after the first.
- `--resume` never retried interrupted proxies, and a cancelled proxy could record a
  failure it never earned.
- Resume now reads through the handle holding the checkpoint lock and truncates
  without an append-only handle. Windows locks are mandatory, so the earlier approach
  was expected to fail there; this was inferred from the code and no such failure
  was observed.
- Fast transfers on Windows could measure zero duration, which recorded zero
  throughput and failed `--min-throughput-kbps` on healthy proxies. This was the
  observed cause of the Windows test failure present since the job was added.
- One long `Proxy-Authenticate` header aborted a whole `--save` run.
- Ctrl-C hung while stdin stayed open; a second Ctrl-C now ends a stuck shutdown.
- `--rate` was capped near 900/s by accumulating timer overshoot.
- Flags after a file name were opened as files, after validating the list.
- Exhausted descriptors or sockets were reported as dead proxies; they now produce
  `inconclusive` with `local_resource_exhausted` and a warning.
- Plain-text echo targets gave no exit IP.
- Single-measurement runs had no median, so `--max-latency` filtered nothing.
- `NETVEX_DATA_DIR` was ignored by commands that read saved runs.
- Retry backoff doubled one retry later than intended.

### Added

- `--prescreen`, `--prescreen-concurrency`, `--prescreen-retries`, and
  `--prescreen-timeout` for a wide TCP-only stage before validation.
- `--no-connect-retry` and `--tls-classical-kex`.
- `--working-dir`, `--working-template`, and `--resume` with working output.
- Checkpoint configuration fingerprints and `--resume-any-config`.
- `--canary-interval` for direct target checks during a run.
- `--save-status`, and `netvex diff` for comparing saved runs.
- `--cpu-profile`, `--mem-profile`, and a live terminal progress line with ETA.
- `netvex schema` with JSON Schema derived from the model, published in `docs/schemas`.
- Result `capabilities`, `--probe-udp`, and `--expect-country`.
- govulncheck, staticcheck, a coverage floor, weekly fuzzing, SOCKS and
  authentication-challenge fuzz targets, an SPDX bill of materials, and signed build
  provenance.

### Development since 0.4.0

#### Added

- A complete NetVex product identity across the executable, Go module,
  configuration namespace, artifacts, CI, documentation, and repository metadata.
- A deterministic binary build gate using commit-derived timestamps, read-only
  module resolution, trimmed paths, and explicit VCS metadata control.
- Explicit `--keep-partial` interruption handling that atomically publishes
  already validated proxies while preserving the safe abort default.
- Bounded destination-address fallback across up to four policy-approved DNS
  answers for upstream, SOCKS, and TLS failures attributable to one target IP.
- GitHub Actions dependencies pinned to verified immutable commits, with
  checkout credentials disabled after source retrieval.
- A bounded, single-flight proxy-gateway DNS cache with address rotation,
  shared connect deadlines, and a one-minute default in the `fast` profile.
- Buffered result serialization that batches small JSONL, CSV, TXT, and table
  writes while preserving broken-pipe error propagation.
- A lower-allocation response evidence loop and boundary-only streaming ASCII
  matcher that avoid copying complete network blocks.
- Credential-bearing result strings are now constructed only for an explicitly
  requested private working-proxy export.
- Streaming UTF-8 BOM handling for text, CSV, JSON, JSONL, and automatic input
  detection, improving compatibility with Windows and spreadsheet exports.
- Hostile structured-input fuzz coverage across CSV, JSON, JSONL, automatic
  detection, deduplication, rejection diagnostics, and UTF-8 BOM handling.
- Streaming JSON-array result output alongside JSONL, CSV, TXT, and terminal tables.
- Transparent bzip2 proxy-dataset input using the Go standard library, including
  nested format detection for names such as `proxies.csv.bz2`.
- Atomic aggregate Prometheus textfile metrics for completed checks and
  Prometheus exposition from saved summaries via `stats --prometheus`.
- A versioned `capabilities --json` document for deployment and wrapper feature detection.
- Streaming multi-pattern response matching for ASCII content assertions,
  avoiding full-body retention and a second lowercase copy while preserving a
  Unicode-compatible bounded path.
- Strict declarative scenarios with named targets, per-target rules, matrix execution, and quorum qualification.
- Direct target preflight with report and strict modes.
- Exit-IP rotation/sticky classification, cross-run stability history, and pool diversity analysis.
- Destination and proxy TLS version, cipher, ALPN, certificate fingerprint, and expiry evidence.
- Custom destination and proxy CA bundles that extend the system trust store.
- Response-body SHA-256 assertions and stored integrity evidence.
- Automatic bounded concurrency recommendations based on CPU and file-descriptor limits.
- Resumable synchronized JSONL checkpoints with incomplete-tail recovery.
- Deterministic credential-preserving dataset sharding and bounded result-run merging.
- Strict JSON quality gates and atomic JUnit XML reports for CI.
- Interactive saved-result exploration with a non-interactive `results` fallback.
- Label, rotation class, and unique-exit filtering and sorting.
- Negotiated proxy authentication-method evidence.
- Hostile HTTP response fuzzing and a repeatable bounded-header parser benchmark.
- Public contribution, security, governance, CI, and release documentation.
- Transparent gzip input for files and standard input, including nested format detection.
- Atomic `--summary-output` JSON for CI and non-persistent automation.
- `--require-count` for minimum validated-proxy thresholds.
- Environment variables for every persistent engine setting.
- Repeatable plain and gzip parser microbenchmarks.
- Commercial `host:port:username:password` input normalization.
- Reordered commercial CSV columns with protocol and credentials.
- TLS-encrypted HTTPS proxy transport with certificate verification.
- Case-insensitive required and rejected response-content assertions.
- Exact dot-path JSON response assertions.
- Response-body byte, duration, and throughput measurements.
- Evidence-based elite, anonymous, and transparent classifications.
- Offline longest-prefix country, city, ASN, organization, and network-type metadata.
- Score, throughput, country, ASN, and network-type result/export filters.
- Explicit `-` standard-input sources for check and import pipelines.
- Canonical version file, documented release locations, and hardened release validation.
- Native Linux ARM64, macOS ARM64, and Windows x64 CI plus multiplatform release archives.
- Windows-native exclusive checkpoint locks and atomic file replacement.
- A bounded, sequential `make cross-check` portability gate for seventeen
  OS/architecture targets.
- Release and CI coverage for Linux 386, ARMv7, and RISC-V 64 systems.
- Configurable per-candidate protocol auto-detection time budgets and
  port-informed candidate ordering.
- A configurable bounded intelligence-body capture with visibility in
  observations, run configuration, and `doctor` diagnostics.
- A preflight 512 MiB concurrent response-capture safety budget.
- An end-to-end CLI fixture that traverses a controlled local HTTP CONNECT
  proxy and validates the resulting machine-readable evidence.

#### Changed

- Result schema advanced to version 5.
- Development version advanced to 0.7.0.
- Persisted IDs now identify only protocol/host/port; credential-sensitive deduplication uses ephemeral process-local seeded fingerprints.
- Plain endpoint parsing uses allocation-minimized host/port and commercial-format fast paths.
- HTTP response parsing uses one bounded buffered reader and preserves prefetched tunnel bytes without copying complete headers.
- Target execution is calculated in constant space instead of materializing per-proxy attempt matrices.
- `--no-deduplicate` now bypasses fingerprint and map initialization completely.
- `--max-response-bytes` exposes the existing bounded response limit directly on the CLI and in run summaries.
- Ordinary output and saved history now redact proxy usernames as well as passwords.
- Saved results are capped at 16 MiB per record and history commits synchronize metadata before publication.
- Configuration, scenarios, quality policies, CA bundles, checkpoints, and history reads have explicit size or record limits.
- Input cardinality is bounded independently of byte size, with a one-million-record default.
- Target matrices are rejected when they exceed 1,000 planned attempts per proxy.
- JSON proxy objects now preserve explicitly supplied username/password fields.
- Input byte limits are aggregate across sources and apply after decompression.
- Output/input collision checks resolve symbolic-link aliases.
- Explicit false CLI booleans now override profiles, environment, and files.
- Configuration initialization now uses atomic synchronized replacement.
- CSV exports include exit, anonymity, transfer, and metadata fields.
- Failed response assertions retain protocol timing and body evidence.
- File exports now use synchronized atomic replacement.
- Platform-specific signal, descriptor-limit, directory-sync, and path
  comparison behavior replaces Unix-only assumptions.
- Observation storage preallocates only the common bounded attempt window,
  reducing repeat-test growth without reserving full large matrices.
- Response byte counts, SHA-256, and throughput now use pooled streaming reads;
  full response retention occurs only for JSON or Unicode content assertions.
- Network failures now distinguish reset connections, broken pipes, closed
  connections, unexpected EOF, and operating-system timeouts.
- Shell completion options are generated from the actual check flag set so new
  flags cannot silently drift out of completion scripts.
- Connection cancellation uses context callbacks instead of one waiting
  goroutine and channel per live socket, reducing scheduler pressure at high
  concurrency without weakening interruption behavior.
- Destination safety prefixes are parsed once and split by address family;
  cached DNS lookups continue independently of whichever caller initiated them.

#### Fixed

- Overall expiration during protocol auto-detection now remains a classified
  timeout instead of degrading to a generic `operation_failed` result.
- JSON and JSONL rejected items now count toward the aggregate record limit.
- HTTP CONNECT and SOCKS handshakes tolerate valid short socket writes and
  reject zero-progress writers instead of silently sending partial messages.
- SOCKS5 reserved bytes, empty bound hostnames, and reply categories receive
  stricter validation and proxy-versus-destination failure classification.
- Multiple HTTP proxy authentication challenges are parsed without mistaking
  Digest parameters or quoted commas for authentication schemes.

#### Security

- Target names and pool labels reject terminal control characters.
- Scenario target names distinguish same-origin paths without persisting sensitive URL paths or queries.
- Checkpoint, working, summary, JUnit, and input collision checks use canonical paths.
- Existing checkpoints must be owner-only regular files; symbolic links are rejected before any repair or truncation.
- Checkpoints use an exclusive non-blocking file lock to prevent concurrent writers from interleaving results.
- Doctor output sanitizes target paths and queries and validates configured CA and metadata files.
- Compressed inputs cannot bypass the configured decompressed-byte budget.
- Incomplete runs preserve existing summary files rather than replacing them.
- Forwarding evidence no longer persists header values that may contain a local IP.
- Metadata enrichment is offline by default and sends no exit IPs to a provider.
- Redirects without `Location` are rejected explicitly; intermediate redirect and authentication bodies are not downloaded.
- Verbose rejected-input and credential-file diagnostics quote terminal control characters.
- Destination resolution deduplicates and retains at most 64 unique answers,
  rejects invalid service addresses even with private-target mode, and blocks
  additional non-global, transition, documentation, and discard prefixes from
  the current IANA special-purpose registries.

## [0.4.0] - 2026-10-25

### Added

- Configurable minimum success ratios and explicit `unreliable` results.
- Per-target attempt, success, failure, timeout, and latency summaries.
- Preview-first local history retention with `runs prune`.
- Bash, Zsh, and Fish completion generation.
- Streamed automatic TXT, CSV, JSON, JSONL, and NDJSON input detection.

### Changed

- Reliability qualification is independent of the latency score.
- Early termination avoids measurements that cannot change qualification.
- Result schema advanced to version 3.
- Documentation and build automation were prepared for public distribution.

### Security

- Persisted target data is reduced to scheme and authority.
- Redirect resolution remains outside the configured-target DNS cache.
- Credential-bearing working lists use atomic mode-0600 replacement.

## [0.3.0] - 2026-10-24

### Added

- DNS lookup collapse and bounded approved-answer caching.
- Rate limiting, bounded queues, retry backoff, and permanent-failure controls.
- Credential-preserving atomic `--working-output` exports.

### Changed

- Deduplication keys use compact binary identities.
- JSONL output is encoded incrementally.

## [0.2.0] - 2026-10-24

### Added

- HTTP, HTTPS CONNECT, SOCKS4, SOCKS4a, and SOCKS5 validation.
- Optional local JSONL run history, filters, statistics, and exports.
- Controlled scheduler benchmarks and fixed-memory latency histograms.

## [0.1.0] - 2026-10-24

### Added

- Initial terminal-only validation engine and destination security policy.

[Unreleased]: https://github.com/drag-team/netvex/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/drag-team/netvex/releases/tag/v0.4.0
[0.3.0]: https://github.com/drag-team/netvex/releases/tag/v0.3.0
[0.2.0]: https://github.com/drag-team/netvex/releases/tag/v0.2.0
[0.1.0]: https://github.com/drag-team/netvex/releases/tag/v0.1.0
