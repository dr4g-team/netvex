# Project status

Last verified: 2026-11-01

## Objective and architecture

NetVex is an on-demand, terminal-only proxy validation and intelligence
application for authorized datasets. It is a dependency-free Go executable with
a streaming parser, bounded worker engine, destination policy, protocol
connectors, evidence model, local metadata lookup, optional JSONL history, and
human or machine output.

Build metadata is derived from the source commit, and
`make reproducibility-check` verifies byte-identical binaries for a fixed tree.

The development line is `0.8.0-dev`; the latest published tag is `v0.7.0`, and
result schema version 7 is current. The project is in active development and
the implemented command surface is usable.
It is not represented as a completed independent security audit.

## Verified capabilities

- HTTP, TLS-encrypted HTTPS proxy, HTTP CONNECT, SOCKS4, SOCKS4a, and SOCKS5
  fixtures, including authentication and failure classification.
- Text, commercial colon format, reordered commercial CSV, JSON, JSONL, gzip, bzip2,
  UTF-8 BOM, multi-source, explicit stdin, deduplication, limits, and credential redaction.
- Bounded concurrency, target pressure, rate, retries, timeouts, cancellation,
  safe redirects, DNS policy, bounded multi-address fallback, response
  assertions, and transfer measurements.
- Optional bounded single-flight proxy DNS caching with multi-address rotation,
  one shared concurrency-safe dialer, and one connect deadline across DNS/TCP.
- Evidence-based anonymity levels and offline longest-prefix exit metadata.
- Target matrices, named declarative scenarios, quorum qualification, direct
  preflight, response hashes, custom CA bundles, and TLS evidence.
- Rotation/sticky classification, pool diversity, and cross-run stability analysis.
- Streaming output, secure atomic exports, resumable checkpoints, deterministic
  sharding, bounded merging, quality gates, JUnit reports, filtering, summaries,
  completion, interactive exploration, diagnostics, and controlled benchmarks.
- Streaming JSON arrays, aggregate Prometheus textfile reporting, and versioned
  machine-readable capability discovery.
- TCP prescreening, single-connection protocol fingerprinting, private gateway
  blocking, direct target canaries, per-protocol and templated working output,
  run comparison, UDP ASSOCIATE probing, expected-country checks, and JSON Schema
  generated from the model.
- Native Linux amd64/arm64, macOS arm64, and Windows amd64 CI, with static
  release builds for Linux amd64/386/ARMv7/ARM64/RISC-V 64 plus macOS,
  Windows, and FreeBSD amd64/arm64.
- Cross-build coverage for OpenBSD, NetBSD, DragonFly BSD, illumos, Solaris,
  and AIX; platform-specific signal and descriptor handling; Windows
  checkpoint locking, case-insensitive path collision checks, and atomic
  Windows replacement.

## Verification record

- `make verify`: passed (`go vet`, all tests, race detector, staticcheck,
  govulncheck, and the 70% coverage floor).
- Proxy parser fuzzing: 329,878 executions in 10 seconds with no failure.
- Structured CSV/JSON/JSONL/auto fuzzing: 178,374 executions in 10 seconds
  with no failure.
- HTTP response fuzzing: 222,363 executions in 10 seconds covering valid,
  truncated, malformed, and oversized inputs with no failure.
- Total coverage 73.5%, enforced in CI.
- Controlled 500,000-item scheduler: 910,336 items/s median at concurrency 128
  across three runs on the non-isolated delivery host.
- Offline IPv4 metadata lookup: 411 ns/op median, zero allocations across three
  benchmark samples.
- A 200,000-record import comparison measured 0.61 s and 15.8 MiB maximum RSS
  for the current parser versus 1.21 s and 18.6 MiB for commit `74427aa`.
- The bounded HTTP response reader measured 6.08 us/op and 5,123 B/op after
  removing duplicate buffering.
- Streaming 1 MiB response evidence with a 64 KiB intelligence capture measured
  4.76 ms/op and 66,140 B/op versus 6.39 ms/op and 2,228,054 B/op for the prior
  `ReadAll` path, using five samples on the same host.
- Streaming search for an absent ASCII assertion over 1 MiB measured 4.77 ms/op
  and 140,068 B/op median versus 4.21 ms/op and 3,276,633 B/op for full-body
  lowercase matching: about 95.7% fewer allocated bytes for a 13% CPU tradeoff
  limited to assertion-enabled checks.
- Cancellation registration and normal close measured 0.85-0.90 us/op and
  200 B/op while avoiding a permanently waiting goroutine per active socket.
- The revised evidence loop retained 1 MiB response throughput at 4.93 ms/op
  median while reducing ordinary allocations from 10 to 4; streaming assertion
  memory fell from about 140 KiB to 66 KiB and allocations from 16 to 8.
- Proxy DNS cache hits measured 524 ns/op median; buffered serializers measured
  238 ns/result for TXT, 3.11 us for JSON, 3.17 us for JSONL, and 1.82 us for CSV.
- Expanded destination range policy checks measured 146.5 ns/op median with
  zero allocations, versus 1,003 ns/op before static address-family tables.

The benchmark conditions and historical results are in
[BENCHMARKS.md](BENCHMARKS.md). Controlled local fixtures are used instead of
unauthorized external proxy infrastructure.

## Known limitations and outstanding work

- No independent third-party security audit has been completed.
- Real-proxy performance is environment and target dependent. `--prescreen` has
  been measured on simulated and kernel-level dead hosts, not on a real proxy pool,
  so its recall on intermittently reachable proxies is unmeasured.
- Native Windows behavior is verified only by CI; the local host compiles and vets
  Windows code but cannot run it.
- Anonymity labels require a compatible operator-approved echo target and an
  explicit baseline IP; ordinary websites cannot supply that evidence.
- Country, ASN, and network labels require an operator-supplied local CSV/gzip dataset;
  a native MMDB dependency could not be acquired in the restricted build environment.
- Validation requests use HTTP/1.1 after custom proxy negotiation. Direct
  preflight can negotiate HTTP/2, but end-to-end HTTP/2 proxy validation remains under evaluation.
- Windows files inherit directory ACLs; NetVex does not attempt to replace
  administrator-managed ACL policy with POSIX permission semantics.

## Resume commands

```sh
git status --short
make verify
make cross-check
make reproducibility-check
make fuzz FUZZTIME=10s
make build
./bin/netvex version
./bin/netvex doctor
```

Architectural decisions and threat boundaries are maintained in
[ARCHITECTURE.md](ARCHITECTURE.md) and [SECURITY.md](SECURITY.md).
