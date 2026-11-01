#!/usr/bin/env bash
# Runs go test and republishes each failure as a workflow annotation, because
# annotations are readable without the authentication that job logs require.
set -uo pipefail
log="$(mktemp)"
trap 'rm -f "$log"' EXIT
go test "$@" ./... 2>&1 | tee "$log"
status="${PIPESTATUS[0]}"
if test "$status" -ne 0; then
  grep -E -A12 -e '^\s*--- FAIL' -e '^FAIL\s' -e '^panic:' "$log" | head -c 3500 |
    sed -e 's/%/%25/g' -e 's/\r//g' | awk 'BEGIN{printf "::error title=go test failure::"} {printf "%s%%0A", $0} END{print ""}'
fi
exit "$status"
