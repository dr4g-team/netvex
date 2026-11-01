#!/usr/bin/env bash
# Runs go test and republishes each failure as a workflow annotation, because
# annotations are readable without the authentication that job logs require.
set -uo pipefail
log="$(mktemp)"
trap 'rm -f "$log"' EXIT
go test "$@" ./... 2>&1 | tee "$log"
status="${PIPESTATUS[0]}"
if test "$status" -ne 0; then
  # Every failing package must fit: annotations are capped, so lines are shortened
  # rather than letting one verbose failure hide the others.
  grep -E -A2 -e '^\s*--- FAIL' -e '^FAIL\s' -e '^panic:' "$log" | grep -v '^ok' | cut -c1-300 | head -c 3500 |
    sed -e 's/%/%25/g' -e 's/\r//g' | awk 'BEGIN{printf "::error title=go test failure::"} {printf "%s%%0A", $0} END{print ""}'
fi
exit "$status"
