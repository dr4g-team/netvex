# Versioning and releases

NetVex uses Semantic Versioning. Published versions have the form `vX.Y.Z`;
development versions use `X.Y.Z-dev` on the default branch.

## Sources of version information

| Location | Purpose |
|---|---|
| [`VERSION`](../VERSION) | Version used by local Makefile builds |
| [`CHANGELOG.md`](../CHANGELOG.md) | Human-readable changes in each version |
| Git tag `vX.Y.Z` | Immutable source revision for a published version |
| [GitHub Releases](https://github.com/drag-team/netvex/releases) | Platform archives, checksums, and release notes |
| `netvex version` | Version, commit, build time, Go version, OS, and architecture of an executable |

The repository does not commit generated binaries. Development work stays in
the `Unreleased` changelog section until a release is prepared. Development
versions may be skipped and do not receive tags.

## Compatibility policy

NetVex remains on major version 1 unless a deliberately incompatible product
contract requires a new major release. Backward-compatible features increment
the minor digit (`1.Y.0`); compatible fixes increment the patch digit
(`1.Y.Z`). Schema changes increment `schema_version`, and readers should
tolerate unknown fields. Published tags are never moved or silently replaced.

Release archives are produced for static Linux amd64, 386, ARMv7, ARM64, and
RISC-V 64 executables, plus macOS, Windows, and FreeBSD amd64/arm64. Windows
uses ZIP; the other platforms use tar.gz. Each archive has an adjacent SHA-256
file, and every release includes an SPDX bill of materials and signed provenance. Source archives are provided automatically by GitHub. Native CI executes
Linux amd64/arm64, macOS arm64, and Windows amd64; FreeBSD and the remaining
release architectures are verified by cross-compiling the application and its
test packages.

The complete maintainer procedure is documented in
[RELEASING.md](RELEASING.md).
