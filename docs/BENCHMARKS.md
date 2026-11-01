# Benchmark method and results

`netvex bench` measures bounded scheduler, queue, result, and model overhead
without network access. `--delay` adds a controlled per-item wait. It does not
claim real proxy throughput, because that is dominated by remote latency and
timeouts.

Reproduce with:

```sh
for c in 1 16 64 128 256; do
  ./bin/netvex bench --count 100000 --concurrency "$c"
done
/usr/bin/time -v ./bin/netvex bench --count 1000000 --concurrency 128
go test -bench . -benchmem ./internal/engine
```

NetVex 0.2.0 delivery-host results (Ubuntu 26.04.1, Linux 7.0, 4 vCPU
Haswell-class KVM, Go 1.26.8, 2026-10-24) are the median of three runs with
500,000 zero-delay items. The host was not isolated, so normal VPS scheduling
noise remains:

| Concurrency | Items/s | Elapsed |
|---:|---:|---:|
| 1 | 260,892 | 1.916 s |
| 16 | 586,842 | 0.852 s |
| 64 | 539,200 | 0.927 s |
| 128 | 721,254 | 0.693 s |
| 256 | 684,640 | 0.730 s |

At one million items and concurrency 128, GNU `time` reported 13,020 KiB
maximum RSS; observed scheduler throughput ranged from 542k to 760k items/s
under changing host load. The Go microbenchmark (three runs) reported 1-worker
2.06–2.14 us/op, 16-worker 1.33–1.36 us/op, and 128-worker 1.01–1.03 us/op,
all at 32 B/op and 3 allocations/op. These are scheduler measurements, not
network claims. They also show why NetVex does not blindly recommend the
largest concurrency setting.

A separate streamed-input check normalized 200,000 distinct entries in 1.10 s
with 29,536 KiB maximum RSS. Deduplication intentionally retains one hash per
distinct input, so memory is bounded by the input byte limit rather than
strictly constant. Version 0.2.0 adds `--no-deduplicate` for constant parser
state on datasets where duplicate checks are acceptable.

Version 0.3.0 changed deduplication keys from allocated hexadecimal strings to
compact binary values and streams JSONL encoding directly. On a generated file
of 500,000 distinct proxies, measured twice on the same non-isolated host:

| Mode | Elapsed | Max RSS |
|---|---:|---:|
| v0.2.0 exact dedup | 2.87–2.98 s | 66–69 MiB |
| v0.3.0 exact dedup | 2.44–2.60 s | 33–34 MiB |
| v0.3.0 no dedup | 2.17 s | 13.3 MiB |

Output was redirected to `/dev/null`; the input and executable conditions were
otherwise identical. The exact-dedup memory reduction was approximately 50%.

After the v0.3.0 changes, three additional 500,000-item scheduler runs at
concurrency 128 measured 756,062–817,518 items/s, with a median of 813,349
items/s. Host scheduling remained uncontrolled, so this is recorded as a
regression baseline rather than a network-throughput promise.

The public-release verification of NetVex 0.4.0 on 2026-10-25 measured
816,643 items/s median under the same 500,000-item, 128-worker scheduler
benchmark (range 791,160–852,932 items/s). A one-million-item run measured
850,592 items/s, 1.17 seconds wall time, and 13,116 KiB maximum RSS. Reliability
threshold calculation and target aggregation remained low-overhead in this
controlled measurement.

Compare builds using the same executable, count, concurrency, delay, Go
version, and host load. Never benchmark against unauthorized proxies.

The 0.5.0 development parser benchmark uses 1,000 distinct text records per
operation on the same four-vCPU host. Three samples produced these medians:

| Input | Time/op | Decompressed throughput | Allocations/op |
|---|---:|---:|---:|
| Plain text | 2.39 ms | 7.91 MB/s | 7,006 |
| Gzip text | 2.48 ms | 7.62 MB/s | 7,027 |

Gzip detection and decompression added 21 allocations per 1,000-record batch
and approximately 3.7% median time in this small-input test. Reproduce with
`go test -run '^$' -bench '^BenchmarkParser' -benchmem -count=3 ./internal/input`.
The throughput column counts decompressed bytes and is not a network result.

The NetVex 0.6.0 development scheduler measured 786,085 items/s median
across three 500,000-item runs at concurrency 128 on the same non-isolated host
(range 779,540–855,874 items/s). This remains an engine-overhead baseline, not a
network proxy rate.

The offline IPv4 longest-prefix metadata lookup benchmark measured a median of
408 ns/op across three samples, with zero allocations per lookup. Reproduce with
`go test -run '^$' -bench '^BenchmarkLookupIPv4$' -benchmem -count=3 ./internal/metadata`.

The NetVex 0.7.0 development engine measured 812,682 items/s median across
three 500,000-item runs at concurrency 128 on 2026-10-26 (range
789,790–869,883 items/s). The corresponding scheduler microbenchmarks measured
1,962 ns/op with one worker, 1,245 ns/op with 16 workers, and 1,029 ns/op with
128 workers at the median; all retained 32 B/op and 3 allocations/op.

Ephemeral HMAC deduplication was implemented with a bounded stack fast path.
The 1,000-record parser benchmark then measured 3.81 ms/op median for plain text
(4.96 MB/s) and 3.81 ms/op median for gzip (4.96 MB/s), with 5,007 and 5,028
allocations respectively. The host was not isolated and the gzip samples had
visible scheduler variance, so these figures are regression evidence rather
than performance guarantees.

On 2026-10-28, the 0.7.0 development parser was profiled and changed to use
direct endpoint parsing, allocation-free hostname validation, `net/netip`, and
two process-local `hash/maphash` seeds compressed into a 96-bit fingerprint.
Five to seven samples on the same Go 1.26.8 four-vCPU host produced:

| Mode | Median time/1,000 | Throughput | Bytes/op | Allocations/op |
|---|---:|---:|---:|---:|
| Before, text | 3.03 ms | 6.24 MB/s | 345,190 | 5,007 |
| Current, exact dedup | 0.89 ms | 21.3 MB/s | 148,876 | 1,026 |
| Current, no dedup | 0.47 ms | 40.5 MB/s | 89,712 | 1,004 |
| Current, gzip dedup | 1.01 ms | 18.7 MB/s | 203,511 | 1,047 |

An executable-level import of the same 200,000-entry, 5,088,895-byte text file
was alternated five times between commit `74427aa` and the current tree. Output
was redirected to `/dev/null`; medians were 1.21 s and 19,032 KiB maximum RSS
before, versus 0.61 s and 16,200 KiB currently. This measures parsing,
deduplication, normalization, and output formatting together.

The HTTP response parser benchmark uses a fixed in-memory HTTP/1.1 response.
Replacing duplicated header buffers with one limit-enforcing reader reduced the
median from 10.03 us/op, 13,486 B/op, and 23 allocations to 6.08 us/op,
5,123 B/op, and 18 allocations. Reproduce the current measurements with:

```sh
go test -run '^$' -bench '^BenchmarkParser' -benchmem -count=5 ./internal/input
go test -run '^$' -bench '^BenchmarkReadResponseLimited$' -benchmem -count=5 ./internal/protocol
```

### Streaming response evidence

On 2026-10-30, a 1 MiB in-memory response was measured before and after moving
body hashing and byte accounting to a streaming reader. Five samples on the
same four-vCPU Go 1.26.8 host produced these medians:

| Mode | Time/op | Throughput | Bytes/op | Allocations/op |
|---|---:|---:|---:|---:|
| Previous `ReadAll` plus SHA-256 | 6.39 ms | 164 MB/s | 2,228,054 | 26 |
| Streaming, 64 KiB intelligence capture | 4.76 ms | 220 MB/s | 66,140 | 10 |
| Streaming, complete 1 MiB assertion capture | 5.24 ms | 200 MB/s | 1,056,284 | 11 |

The ordinary bounded-capture path used about 97% fewer allocated bytes and was
about 25% faster in this controlled benchmark. Network performance remains
dominated by the proxy and target.

An additional worst-case assertion benchmark searched for an absent ASCII
signature in a 1 MiB response. Five samples produced medians of 4.21 ms and
3,276,633 B/op for the former full-body lowercase path, versus 4.77 ms and
140,068 B/op for the streaming matcher. The matcher therefore used about 95.7%
fewer allocated bytes at a 13% median CPU-time cost confined to checks that
enable text assertions. Matching signatures may finish scanning earlier.

Reproduce both measurements with:

```sh
go test -run '^$' -bench '^BenchmarkReadBodyEvidence$' -benchmem -count=5 ./internal/engine
```

### Cancellation registration

Socket cancellation is registered without a permanently waiting goroutine per
connection. On the same four-vCPU host, five samples of the registration and
normal-close path measured 0.85-0.90 us/op, 200 B/op, and four allocations.
The benchmark is a local regression signal; the principal gain is eliminating
one live waiter and channel per active socket under high concurrency.

```sh
go test -run '^$' -bench '^BenchmarkWatchContextClose$' -benchmem -count=5 ./internal/protocol
```

### Gateway DNS, evidence, and output batching

On 2026-11-01, the response evidence loop was changed from a composed
`LimitReader`/`MultiWriter` pipeline to one bounded incremental loop. The ASCII
matcher now scans network blocks directly and allocates only a small boundary
window for cross-block matches. Five samples on the same host measured:

| Path | Median time/op | Bytes/op | Allocations/op |
|---|---:|---:|---:|
| 1 MiB, 64 KiB capture | 4.93 ms | 65,985 | 4 |
| 1 MiB, absent streaming assertion | 5.05 ms | 65,997 | 8 |

The preceding implementation used 10 allocations for ordinary capture and 16
allocations plus roughly 140 KiB for the assertion path. CPU time remained
within normal VPS variance while assertion memory fell by about 53%.

Cached proxy-gateway address selection measured 524 ns/op median, 64 B/op, and
two allocations across five sequential samples. The cache-hit benchmark does
not include DNS network latency; it establishes that cache coordination is
negligible relative to a proxy connection. Reproduce with:

```sh
go test -run '^$' -bench '^BenchmarkProxyDNSCacheHit' -benchmem -count=5 ./internal/protocol
go test -run '^$' -bench '^BenchmarkWriter$' -benchmem -count=5 ./internal/output
```

Result writers batch output in 64 KiB chunks. The 2026-11-01 serializer rerun
measured medians of 238 ns/result for TXT, 3.11 us for streaming JSON arrays,
3.17 us for JSONL, and 1.82 us for CSV. These are encoding costs against
`io.Discard`, not disk-throughput claims.

The controlled 500,000-item scheduler was also rerun three times at concurrency
128 against this tree. It measured 910,336 items/s median (range
888,071-972,978 items/s). This is an engine-overhead regression signal from a
non-isolated host, not a claim about real proxy throughput.

### Destination policy

Special-purpose destination prefixes were previously parsed inside every
`IsUnsafe` call. Moving the expanded current IANA set into immutable,
address-family-specific tables reduced five-sample median policy time from
1,003 ns/op to 146.5 ns/op with zero allocations in both versions. Reproduce
with:

```sh
go test -run '^$' -bench '^BenchmarkIsUnsafe$' -benchmem -count=5 ./internal/policy
```

The benchmark alternates public and blocked IPv4/IPv6 addresses. It measures
local classification only, not DNS or network latency.

### Dead gateways

Measured on 2026-11-01 on the same four-vCPU host. A real list is mostly dead
gateways, so this is the scenario that decides run time.

Real sockets on loopback, using a listener with a saturated backlog so the kernel
drops SYN packets and every connect blocks until its timeout. Connect timeout 1 s,
request timeout 2 s, one measurement. All entries are dead:

| Build and mode | Workers | Proxies/s | Max RSS |
|---|---:|---:|---:|
| Before these changes | 128 (64 usable) | 62 | 16 MiB |
| Current | 128 | 125 | 17 MiB |
| Current, `--prescreen --prescreen-retries 0` | 4096 | 3,795 | 103 MiB |

The first two lines ran 1,000 entries and the third 12,000. At the standard 5 s
timeout these rates divide by five.

Simulation at 1/50 time scale, where every dial blocks until its timeout, using the
default 5 s connect and 12 s request timeouts. "Before" figures come from the same
harness against commit `427e7fe`:

| Mode | Dials per proxy | Proxies/s | Hours per million |
|---|---:|---:|---:|
| Before, defaults, `http` | 2.0 | 6.3 | 44.4 |
| Before, defaults, `auto` | 6.3 | 5.0 | 56.0 |
| Current, defaults, `http` | 2.0 | 11.7 | 23.7 |
| Current, defaults, `auto` | 2.0 | 11.8 | 23.6 |
| Current, `--no-connect-retry`, `auto` | 1.0 | 23.8 | 11.7 |
| Current, `--prescreen` | 2.0 | 364 | 0.76 |
| Current, `--prescreen`, no retry, 3 s timeout | 1.0 | 1,134 | 0.24 |
| Current, as above with 16,384 workers | 1.0 | 1,977 | 0.14 |

The last row is below linear scaling because compressing time makes scheduler
overhead proportionally larger. A host that refuses connections fails immediately
and costs far less than these figures. Neither table is a real proxy result:
real pools mix live, refusing, and silent hosts, and that measurement remains open.

```sh
NETVEX_SIMULATE=1 go test ./internal/engine -run TestDeadGatewaySimulation -v -count=1
```

### Live proxies and TLS

An HTTPS destination behind a CONNECT proxy, both separate local processes sharing
the four vCPUs, 20,000 proxies at concurrency 128. Three alternating samples:

| Build | Median proxies/s | Median p50 |
|---|---:|---:|
| Before these changes (Go 1.26.8) | 1,167 | 103 ms |
| Current (Go 1.27.3) | 1,145 | 105 ms |

The difference is within the sample spread, so live-proxy throughput is unchanged.
TLS handshakes took 69% of client CPU in this path. Two samples of each variant
measured 1,205 proxies/s at baseline, 1,581 with `--tls-classical-kex` (31% more),
and 1,283 with shared TLS session resumption (6% more), which was rejected as not
worth linking every exit to one client.

`--rate 5000` previously delivered 905 attempts/s because timer overshoot
accumulated. The limiter unit test now holds 3,500-5,500/s for that setting, and a
real local run reached 4,051/s.

The controlled 500,000-item scheduler measured 909,052 items/s median (range
894,294-983,639 items/s), level with the previous baseline.

### Saved runs

Measured on 2026-11-01 on the same host with 100,000 distinct refused endpoints at
concurrency 512, so compression sees realistic variety rather than repeated lines:

| Mode | Bytes per result | Wall time | Max RSS |
|---|---:|---:|---:|
| `--save` | 1,003 | 3.29 s | 40 MiB |
| `--save --save-gzip` | 57 | 3.26 s | 41 MiB |

Failed results are the most repetitive, so successful results with full evidence
will compress less. Reusing one buffer moved `BenchmarkRunWriter` from 1,600 B/op and
3 allocations to 832 B/op and 2 allocations, across three samples each.

```sh
go test -run '^$' -bench '^BenchmarkRunWriter$' -benchmem -count=3 ./internal/store
```
