# Architecture

NetVex is a Go single-process, on-demand CLI. It has no daemon, browser UI,
HTTP service, plugin execution, or downloaded code path.

Data flow:

```text
text / CSV / JSON / gzip / bzip2 / scenario
        |
 streaming parser + hash deduplication
        |
 bounded job queue
        |
 optional wide TCP prescreen -- live socket ------> rejected results
        |                                                  |
 fixed worker pool                                         |
        |                                                  |
 preflight + cached destination policy                     |
        |                                                  |
 gateway TCP dial -> auto fingerprint -> per-target slot   |
        |                                                  |
 protocol adapter -> TLS/HTTP validation                   |
        |                                                  |
        +<-------------------------------------------------+
        |
 raw observations -> target quorum + rotation + score + bounded histogram
        |
 stdout / checkpoint / quality gate / Prometheus textfile / atomic optional JSONL history
```

Packages are divided by responsibility: `input`, `config`, `scenario`, `policy`,
`protocol`, `engine`, `intel`, `metadata`, `score`, `metrics`, `history`,
`quality`, `output`, `schema`, `store`, `fsx`, and `cli`.

An attempt follows one ordering rule: a gateway proves TCP reachability before it
occupies destination capacity. Most listed proxies are dead, and a slot held through
a connect timeout does no work. Slot wait is reported as `queue_ms` and charged to
neither latency nor the timeout. A connection that queued for more than a second is
redialed, because proxies drop idle clients and that drop would look like a proxy
failure.

In `cli`, `checkSession` owns a validation run and `check()` lists its steps.
Interactive and non-interactive commands use the same engine and models.

OS-specific code is restricted to small build-tagged boundaries: process
signals and descriptor limits, checkpoint locking and no-follow opening, path
identity, atomic replacement, and directory synchronization. Network protocol
logic and result semantics are shared across every supported platform.

The global worker count, configurable job/result queues, and per-target semaphores are all
bounded. Each worker checks repeats serially for one proxy, limiting connection
multiplication. An optional cancellation-aware rate gate reserves slots on a
virtual schedule and sleeps outside its lock, so timer overshoot cannot accumulate,
and returns an unused slot on cancellation. Context deadlines reach
dialing, negotiation, TLS, reads, and writes. SIGINT/SIGTERM close active
connections, cancel production and workers, and return exit 130.
Socket cancellation uses context callbacks instead of a dedicated waiting
goroutine and channel for every live connection.

Concurrent destination resolutions are collapsed and safe answers are cached
for a bounded TTL. A canceled initiating caller does not cancel a lookup still
needed by other waiters; the shared lookup remains bounded by the original
attempt deadline. Failed lookups are not cached. Permanent policy,
authentication, and invalid-protocol observations stop repeats unless the
operator explicitly requests them; successful runs can also stop at the first
success. This avoids predictable connection multiplication while preserving an
exhaustive mode.

When local DNS returns multiple safe addresses, destination-specific CONNECT,
SOCKS, or TLS failures may fall back across at most four unique answers within
the existing attempt deadline. Authentication, proxy-connect, policy, and
ordinary HTTP response failures never multiply connections. Proxy-side DNS
continues to use one hostname request because the remote resolver selects the
address.

Proxy gateway DNS caching is a separate optional path because proxy endpoints
are operator-supplied rather than validation destinations. It collapses
concurrent lookups per normalized hostname, retains at most 4,096 hostname
entries by default (configurable) and 16 unique addresses per hostname, rotates cache hits atomically,
does not cache failures, and shares the existing connect deadline. Literal IP
endpoints bypass it. A single concurrency-safe `net.Dialer` is reused by the
checker. A healthy prescreen socket has one owner and is transferred into its
first validation; it is never pooled or shared. Optional TLS resumption shares
only bounded cryptographic sessions, not open tunnels.

An optional gateway cache single-flights concurrent deterministic failures and
never shares a successful connection. The protocol cache retains only a
successful auto-detection result. The Digest cache retains the public challenge,
never credentials or an Authorization value. All are bounded and expiring.
Runtime AIMD and learned timeouts are separate opt-ins so fixed runs remain
reproducible.

Deduplication retains process-local seeded 96-bit identities so credential variants
remain distinct without exposing a credential-derived public ID or serializable
credential verifier. Persisted IDs
are 96-bit endpoint hashes over protocol, host, and port. Result encoders use a
bounded 64 KiB output buffer to batch small writes. These keep
allocation and resident-memory growth low on large datasets; exact
deduplication can be disabled for constant parser state.

Gzip and bzip2 are detected from stream magic bytes rather than trusted file extensions.
UTF-8 BOM prefixes are consumed incrementally for every structured and text
format.
The byte and record-count budgets are shared across every input source and
enforced on the decompressed stream, so additional files, tiny records, and
compression cannot multiply the configured parser limits. Filename suffixes
are used only to select the nested data format.

Destination hostnames are exact-allowlisted, every returned address is checked,
duplicates are removed, and at most 64 unique answers are retained. The
selected safe address is placed in CONNECT/SOCKS requests. HTTPS keeps
the original hostname only for SNI and certificate validation. Each redirect is
resolved and checked again. This design prevents the validation target from
becoming an implicit internal-network access primitive under default settings.
Only the bounded configured-target set is DNS-cached. Remote-controlled
redirects are deliberately re-resolved and never inserted into the cache.
SOCKS4 selects an approved IPv4 answer even if the resolver returned IPv6
first. Auto detection includes SOCKS4a only when remote DNS was deliberately
enabled.

HTTPS proxy transport wraps the proxy TCP connection in TLS 1.2 or newer with
normal hostname and certificate verification. CONNECT or absolute-form HTTP is
then performed inside that protected transport. Proxy TLS and destination TLS
have separate stages and timings.

Raw attempt observations are stored independently from the score. Score changes
therefore do not destroy evidence. Latency summary quantiles use a fixed-memory
1 ms histogram capped at the five-minute maximum attempt duration.

Credential-bearing working lists and standalone JSON summaries share the same
same-directory temporary-file, flush, synchronization, and atomic-commit path.
Canonical path comparison resolves symbolic-link aliases before an output can
replace an input.

Checkpoints append redacted results, periodically flush and synchronize, repair
an incomplete final line on resume, and bound the number of restored IDs.
Dataset sharding is streaming and deterministic by endpoint hash; merging is
bounded by an explicit record limit. Multi-file shard publication prepares all
temporary files first, although the final set cannot be transactionally renamed
as one filesystem operation.

Optional metadata is loaded before workers start into IPv4 and IPv6 prefix maps.
Lookup checks at most 33 IPv4 or 129 IPv6 prefix lengths and never performs a
network request. Responses are counted and SHA-256 hashed as a stream through a
reused fixed-size transfer buffer. Only a configurable bounded prefix is kept
for ordinary exit intelligence; content assertions retain the complete bounded
body only for JSON or Unicode-aware inspection. ASCII signatures use a streaming
multi-pattern matcher and do not create a full lowercase copy. Transfer rate
uses body bytes divided by body-read duration and is kept separate from TTFB
and total latency.

Protocol auto-detection orders candidates using conservative port hints and
assigns each candidate no more than the configured probe timeout or its fair
share of the remaining overall attempt deadline. One unresponsive protocol can
therefore no longer consume the complete detection window.

Qualification uses a configurable minimum success ratio. The checker computes
the required success count before starting, stops when that count is reached in
first-success mode, and also stops when it becomes impossible to reach. Partial
success below the requirement is retained as `unreliable` evidence rather than
being promoted to a working proxy.

Matrix scenarios repeat each named target and qualify target-local reliability
before applying a quorum. Rotation intervals apply between rounds, not between
destinations in one round. Direct preflight is independently bounded to four
concurrent destinations and never inherits environment proxy settings.
Attempt destinations are selected by index rather than materialized as a
per-proxy slice, so matrix planning remains constant-space up to its safety cap.

The local JSONL history remains optional. Cross-run analysis streams bounded
records into endpoint trends; pool analysis deliberately loads only up to its
operator-selected limit to calculate exit/subnet/ASN diversity. No background
service or network metadata lookup is introduced.
