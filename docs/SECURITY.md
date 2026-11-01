# Security model

NetVex assumes proxy endpoints and validation target names are explicitly
authorized by the operator. It does not discover proxies, scan address ranges,
evade controls, bypass rate limits, or execute imported content.

Default safeguards:

- exact hostname allowlist derived from configured targets;
- scheme limited to HTTP/HTTPS, with no target URL credentials;
- all DNS answers checked before use;
- loopback, private, link-local, carrier-grade NAT, cloud metadata, reserved,
  documentation, multicast, and unspecified address ranges denied;
- NAT64, 6to4, Teredo, discard-only, benchmarking, deprecated transition, and
  other non-global ranges from the current IANA [IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/)
  and [IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/)
  special-purpose registries denied;
- destination answers deduplicated and capped at 64 retained addresses;
- numeric IP pinned in HTTP CONNECT, SOCKS4, and SOCKS5 destination requests;
- concurrent DNS lookup collapse and bounded caching of fully checked answers;
- optional proxy-gateway DNS coalescing with bounded host/address cardinality,
  round-robin selection, no negative caching, and the original TLS hostname;
- redirect destinations are revalidated without entering the DNS cache;
- redirects independently allowlisted and resolved;
- TLS 1.2 minimum and normal system certificate validation, never an insecure
  skip mode;
- independent certificate validation for HTTPS proxies and HTTPS destinations;
- overall, connect, input, line, response, concurrency, repeat, redirect, and
  target-count, URL-size, sorting and queue limits, plus a 64 KiB status/header limit;
- complete-write loops for HTTP CONNECT and SOCKS negotiation messages, with
  short-write and zero-progress detection;
- streaming response hashing, streaming ASCII content matching, and a separately
  bounded intelligence-body capture, with full bounded capture only for JSON or
  Unicode content assertions;
- a 512 MiB worst-case concurrent response-capture budget enforced before any
  network operation;
- one aggregate decompressed-byte budget across all plain, gzip, and bzip2 input sources;
- at most four locally resolved, fully policy-approved target addresses are
  considered for destination-specific fallback within one attempt deadline;
- CI and release actions are pinned to audited immutable revisions, and source
  checkout does not persist repository credentials;
- proxy usernames and passwords redacted from ordinary output and omitted from history;
- credential-bearing result strings are not constructed or retained unless the
  operator explicitly requests `--working-output`;
- redacted `***` passwords rejected when diagnostic output is re-imported;
- target paths, fragments, and queries removed from persisted observations unless
  replaced by an explicit control-character-free scenario target name;
- forwarding evidence stores names but not potentially identifying header values;
- history, checkpoints, sharded credential lists, reports, and generated configuration use owner-only POSIX permissions;
- standalone summaries and credential-bearing exports use atomic owner-only POSIX files;
- Prometheus textfile reports contain aggregate metrics with fixed labels and
  exclude proxy, target, credential, and operator-supplied label values;
- generated configuration is synchronized and atomically replaced;
- input/output path aliases are compared after symbolic-link resolution;
- no shell evaluation, dynamic code loading, privileged operation, or service
  modification.

Proxy gateways are checked as well. The dialer inspects the address actually
being connected, so a hostname cannot resolve around the check, and private,
loopback, link-local, carrier-grade NAT, cloud metadata, and reserved gateways are
refused with `proxy_gateway_blocked`. Without this, an untrusted list could make
NetVex connect to internal services and metadata endpoints.

Text chosen by a remote proxy is bounded and stripped of control characters before
it reaches a result, so a hostile proxy cannot fail a run's persistence or write
escape sequences to a terminal.

Chain validation accepts any CA this host trusts, so it cannot see interception by
a corporate or malicious trusted root. `--pin-sha256` closes that gap for known
destinations. Redirects from HTTPS to HTTP are refused because they would continue
validation over plaintext the proxy can rewrite.

Explicit exceptions `--allow-private-targets`, `--allow-private-proxies`,
`--allow-redirect-downgrade`, and `--allow-remote-dns` reduce protection and exist for controlled labs. Private-target mode can reach internal
services through supplied proxies, but invalid, unspecified, and multicast
service addresses remain rejected. Remote-DNS mode lets a proxy independently
resolve HTTP CONNECT, forward HTTP, SOCKS4a, and SOCKS5 destinations, so split DNS or
DNS rebinding can defeat IP pinning. These options should not be used with
untrusted datasets or targets.

The proxy DNS cache does not apply destination SSRF rules to proxy endpoints:
those endpoints are the explicitly authorized input being tested and may
legitimately be private in controlled deployments. Enabling the cache can keep
using an address until its configured TTL expires; disable it for providers
whose gateway DNS changes are intentionally faster than that interval.

Credentials present in process arguments may be visible in shell history and the
process list. Prefer a mode-0600 input file or protected standard input. Both
username and password are replaced by `***` in ordinary results. Public endpoint
IDs do not depend on credentials. Exact in-process deduplication uses a randomly
seeded 96-bit `hash/maphash` fingerprint so alternate credentials remain distinct
without persisting a useful credential verifier. Seeds are process-local and
cannot be serialized. The fingerprint is for an in-memory hash table, not for
authentication or cryptographic integrity.

Normal results and history always redact usernames and passwords. `--working-output` is an
explicit credential-bearing export for operational use; it creates mode-0600
files, refuses replacement unless `--force` is present, refuses to target an
input path, and commits by same-directory atomic replacement only after a
complete run. Its contents must be handled as secrets.

`inspect` passes the proxy through memory and never writes it to a file. A proxy
on the command line is still visible in the process list, so use `netvex inspect -`
to read it from standard input on shared hosts.

Shard outputs also contain full credentials and use mode 0600. Resume
checkpoints are redacted. Credentialed result IDs are HMACs keyed by a private
`identity.key` in the data directory, which keeps low-entropy credentials from
being recovered offline from saved IDs. Treat that key like a credential file;
deleting it makes existing IDs incomparable but exposes nothing. If it cannot be
stored, IDs are valid for one process and resume revalidates instead of skipping.

On Windows, generated files inherit the ACL of their containing directory.
NetVex uses native exclusive checkpoint locks, rejects reparse-point-like
symbolic links exposed by Go, verifies file identity after opening, and uses
atomic replace semantics, but it deliberately does not rewrite organization- or
administrator-managed ACLs. Store credential inputs and outputs in a directory
whose ACL grants access only to the intended account.

Custom CA bundles extend, rather than replace, the system trust store. NetVex
does not expose an insecure TLS mode. Certificate files are bounded before
parsing, and `doctor` validates configured bundles without making a network
request.

When a credential-bearing input file is readable by group or other users,
NetVex emits a security warning with the observed mode. It does not change
operator-owned file permissions automatically.
User-controlled filenames and rejected records are quoted in verbose terminal
diagnostics so control characters cannot alter terminal or log presentation.

Anonymity observations are limited. Forwarded-header evidence proves that a
chosen echo target observed a header; its absence cannot prove anonymity. Exit
IP, geolocation, ASN, and operator labels can be wrong or unavailable. Treat
third-party target response data as untrusted evidence.

Elite, anonymous, and transparent labels require an operator-supplied baseline
IP and an echo target that returns both exit-IP and header evidence. They describe
one observed request, not a permanent property or guarantee. Supplying a
baseline IP through a process argument may expose it in process listings; use a
mode-0600 configuration file when that IP is sensitive.

Metadata files are local untrusted input with decompressed-byte, record, prefix,
and field limits. Their classifications are not independently verified. Content
assertions identify response properties but do not solve, bypass, or interact
with anti-bot challenges.

Report vulnerabilities according to the repository's private disclosure
procedure in [SECURITY.md](../SECURITY.md). Include the NetVex version,
affected command, sanitized input, and a minimal reproduction without live
third-party credentials.
