#!/usr/bin/env python3
"""Write an SPDX 2.3 JSON document describing NetVex release archives.

NetVex has no third-party Go modules, so the bill of materials is the release
archives plus the Go toolchain whose standard library they embed. Generating it
here avoids granting a third-party action access to the release job.
"""
import argparse
import datetime
import hashlib
import json
import pathlib
import re
import sys


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--go-version", required=True)
    parser.add_argument("--created", help="RFC 3339 timestamp, normally the commit date")
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("archives", nargs="+", type=pathlib.Path)
    args = parser.parse_args()
    if not re.fullmatch(r"\d+\.\d+\.\d+(-dev)?", args.version):
        parser.error("version must be X.Y.Z or X.Y.Z-dev")
    created = args.created or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    packages = [
        {
            "SPDXID": "SPDXRef-Package-netvex",
            "name": "netvex",
            "versionInfo": args.version,
            "downloadLocation": f"git+https://github.com/drag-team/netvex@{args.commit}",
            "licenseConcluded": "Apache-2.0",
            "licenseDeclared": "Apache-2.0",
            "copyrightText": "NOASSERTION",
            "filesAnalyzed": False,
        },
        {
            "SPDXID": "SPDXRef-Package-go-stdlib",
            "name": "go-stdlib",
            "versionInfo": args.go_version,
            "downloadLocation": "https://go.dev/dl/",
            "licenseConcluded": "BSD-3-Clause",
            "licenseDeclared": "BSD-3-Clause",
            "copyrightText": "NOASSERTION",
            "filesAnalyzed": False,
        },
    ]
    files = []
    relationships = [
        {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Package-netvex"},
        {"spdxElementId": "SPDXRef-Package-netvex", "relationshipType": "STATIC_LINK", "relatedSpdxElement": "SPDXRef-Package-go-stdlib"},
    ]
    for index, archive in enumerate(sorted(args.archives)):
        identifier = f"SPDXRef-File-{index}"
        files.append({
            "SPDXID": identifier,
            "fileName": f"./{archive.name}",
            "checksums": [{"algorithm": "SHA256", "checksumValue": sha256(archive)}],
            "licenseConcluded": "Apache-2.0",
            "copyrightText": "NOASSERTION",
        })
        relationships.append({"spdxElementId": "SPDXRef-Package-netvex", "relationshipType": "GENERATES", "relatedSpdxElement": identifier})
    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"netvex-{args.version}",
        "documentNamespace": f"https://github.com/drag-team/netvex/releases/tag/v{args.version}/spdx/{args.commit}",
        "creationInfo": {"created": created, "creators": ["Tool: netvex-scripts-sbom"]},
        "packages": packages,
        "files": files,
        "relationships": relationships,
    }
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
