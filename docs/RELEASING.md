# Release process

NetVex releases are created from annotated Semantic Versioning tags on a
clean `main` branch. The release workflow builds static Linux
amd64/386/ARMv7/ARM64/RISC-V 64 plus macOS, Windows, and FreeBSD amd64/arm64
archives, generates SHA-256 checksum files and an SPDX bill of materials, attests
build provenance, and publishes them to GitHub. Releases use the exact Go version
in `GO_RELEASE_VERSION`, which must be raised with every security release of Go.
`VERSION`, the changelog section, and the tag must agree exactly.

## Prepare

Update the version history, verify schemas and user documentation, then run the
full local gate:

```sh
make clean
make verify
make cross-check
make reproducibility-check
make build
./bin/netvex version
git status --short
```

Choose the stable version, remove its `-dev` suffix from `VERSION`, and move the
relevant entries from `Unreleased` to a dated version section in `CHANGELOG.md`.
Confirm that release notes do not contain proxy credentials, private targets,
local paths, or unpublished vulnerability details. Commit and push that release
preparation before tagging it.

## Tag

Create an annotated tag only after the release commit has passed CI. The
canonical version comes from `VERSION`:

```sh
version="$(cat VERSION)"
git tag -a "v${version}" -m "NetVex v${version}"
make release-check
git push origin main
git push origin "v${version}"
```

The pushed tag triggers the release jobs in `.github/workflows/netvex.yml`. A
failed workflow must be fixed and rerun; release artifacts must not be assembled
manually from an unverified working tree.

## Verify

Download each archive and its checksum onto a matching clean host. For example,
on Linux:

```sh
version="1.0.0"
sha256sum --check "netvex-v${version}-linux-amd64.tar.gz.sha256"
tar -xzf "netvex-v${version}-linux-amd64.tar.gz"
./"netvex-v${version}-linux-amd64"/netvex version
./"netvex-v${version}-linux-amd64"/netvex doctor
```

Verify build provenance with `gh attestation verify netvex-v${version}-linux-amd64.tar.gz --repo drag-team/netvex-go`.

Confirm the embedded version, commit, target OS and architecture, license,
README, and changelog. Verify every native architecture available to the
maintainer; CI provides native Linux ARM64, macOS ARM64, and Windows x64 coverage
and compile coverage for the remaining release targets.

## Recovery

Do not move or silently replace a published tag. If a release is defective,
document the problem, publish a corrective patch version, and mark the affected
release clearly. If an unpublished local tag is wrong, delete it locally and
recreate it before any push.
