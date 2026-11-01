# Data schemas

Machine formats are UTF-8. JSON output is one streamed array, JSONL contains
one complete result object per line, and CSV has a stable header row. Times use RFC 3339 UTC and durations use
milliseconds as floating-point values.

The current `schema_version` is 7. `netvex schema result` and
`netvex schema summary` print JSON Schema derived from the model, and
[docs/schemas](schemas) holds the published copies; a test fails if they drift.
Readers should tolerate unknown fields and missing fields from older runs.

Version 7 adds the summary field `interrupted`, set when `--keep-partial` publishes
an unfinished run. Its counts cover only completed proxies, and `input` may be empty
if reading had not finished.

Version 6 scopes `id` to the account for credentialed proxies, so several accounts
on one gateway are separate results; such IDs differ from those written by earlier
versions and are not comparable with them. It also adds `queue_ms`, `capabilities`,
the `canary` summary block, and a `median_ms` for single-measurement runs. `total_ms`
no longer includes destination queueing.

Version 5 adds credential-free endpoint IDs,
target matrices, rotation profiles, TLS evidence, body hashes, labels, target
health, quality reports, and attempt totals. Version 4 added proxy-TLS and body timings,
response size and throughput, offline exit metadata, and the revised anonymity
vocabulary. Version 3 added reliability requirements, the `unreliable`
status/count, and per-target health summaries. Validation targets in results and
summaries are reduced to scheme/authority origins so path, fragment, or query
tokens are never persisted. Scenario target names may replace origins in raw
observations and target summaries.

Result fields:

| Field | Meaning |
|---|---|
| `id` | Truncated SHA-256 protocol/host/port identifier, or an HMAC with a local key that also covers credentials |
| `proxy` | Protocol URI with username and password replaced by `***` |
| `endpoint` | Credential-free host and port |
| `protocol` | Requested or successful detected protocol |
| `status` | Overall classified status |
| `attempts`, `successes`, `required_successes` | Completed and required measurement counts |
| `observations` | Raw per-attempt evidence and stage timings |
| `target_results`, `target_quorum` | Per-target qualification and required matrix quorum |
| `rotation` | Observed exit stability, changes, dominant share, countries, and ASNs |
| `label` | Optional safe pool or scenario label |
| `score` | Derived value, confidence, inputs, and explanation |
| `capabilities` | Demonstrated exit address families and, with `--probe-udp`, the SOCKS5 UDP ASSOCIATE answer |
| `checked_at` | Start time of proxy validation |

Observation timings are `dns_ms`, `queue_ms`, `connect_ms`, `proxy_tls_ms`, `tunnel_ms`,
`tls_ms`, `ttfb_ms`, `body_ms`, and `total_ms`. `body_bytes` and
`throughput_kbps` describe the bounded response transfer. A failure exposes
`stage`, stable `code`, and a sanitized `message`. `exit_ip`, `anonymity`,
`forwarding_evidence`, and `metadata` are present only when the target and local
database supply the required evidence. Forwarding evidence contains header names
without header values. `proxy_authentication` records the successfully negotiated
method. `proxy_tls` and `destination_tls` separately record TLS version, cipher,
ALPN, certificate SHA-256, and certificate expiry. `body_sha256` covers the
bounded final response body.
When a large body was streamed without retaining it completely,
`body_captured_bytes` records the smaller prefix available for intelligence
inspection. Its absence means the full bounded body was available. Hash and
throughput evidence always cover every transferred byte, not just that prefix.
`destination_address_attempts` appears when a policy-approved secondary DNS
answer was tried; `resolved_ip` is the address that produced the stored final
observation.

The CSV export is intentionally flat and contains the last observation's
stage/code plus the most recent successful observation's exit, anonymity,
transfer, and metadata evidence. It also contains the aggregate score and
median. JSON and JSONL are lossless exports. TXT emits only safe proxy URIs and should
be filtered by status when used as a working-proxy list.

Run summaries contain cumulative proxy `processed` count, checkpoint `restored`
count, raw observation `attempts`,
`status_count`, `failure_codes`, and `failure_stages`.
These maps count raw observations, so a finally successful proxy can still
contribute an earlier failure. This preserves transient-error evidence.

The same summary object is written by `--summary-output` and by optional run
history. A standalone summary may have an empty `run_id` because no historical
JSONL run was created. Consumers should use `schema_version`, not the presence
of a run identifier, to select a decoder.
The embedded run configuration records `max_response_bytes`,
`intelligence_body_bytes`, `min_response_bytes`, and `auto_probe_timeout`,
making response-memory, throughput, and protocol-detection conditions
reproducible without consulting the original command line.
`proxy_dns_cache_ttl` records whether gateway resolution reuse affected the
run; `0s` means every hostname dial used the system resolver normally.
`keep_partial` records the explicit interruption-output policy when enabled.
`prescreen`, `skip_connect_retry`, `tls_classical_kex`, `probe_udp`,
`expect_countries`, `canary_interval`, and `save_status` record the corresponding
options. With `save_status`, the summary counts every proxy while the saved run
holds only the selected statuses.

When a quality policy is active, `quality` contains a boolean result and the
actual/operator/expected tuple for every evaluated check. The same evidence is
available as JUnit XML with `--junit-output`.

`--metrics-output` and `stats --prometheus` expose an aggregate-only Prometheus
text snapshot. Metric labels are a fixed vocabulary; proxy endpoints, targets,
pool labels, failure messages, and credentials are deliberately excluded.

`capabilities --json` uses its own `schema_version: 1` document containing the
implemented protocols, authentication methods, input/output formats,
compression methods, reports, safeguards, and cross-build platforms. Consumers
should ignore unknown future fields.
