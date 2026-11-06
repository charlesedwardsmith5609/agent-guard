#!/usr/bin/env bash
# Go checks: gofmt, go vet, govulncheck, go test with the race detector.
# Runs in the Go module's directory.
set -u
fail=0
stage() { printf '\n== go: %s\n' "$1"; }

if [ -z "$(go list ./... 2>/dev/null)" ]; then
  echo "go: no packages yet. Toolchain OK: $(go version)"
  exit 0
fi

stage "gofmt"
unformatted=$(gofmt -l . 2>&1)
if [ -n "$unformatted" ]; then
  echo "FAIL: files need gofmt:"; echo "$unformatted"
  echo "Fix: gofmt -w ."
  fail=1
else
  echo "PASS"
fi

stage "go vet"
if go vet ./...; then echo "PASS"; else echo "FAIL"; fail=1; fi

stage "govulncheck"
# Deterministic layer: known vulnerabilities in the code paths you actually call, from the
# Go vulnerability database. Exit codes: 0 clean, 3 vulnerabilities found, anything else
# means it could not finish (usually no network); that is reported but does not fail the gate.
vc=$(command -v govulncheck 2>/dev/null || true)
if [ -z "$vc" ] && [ -x "$(go env GOPATH)/bin/govulncheck" ]; then vc="$(go env GOPATH)/bin/govulncheck"; fi
if [ -z "$vc" ]; then
  echo "SKIPPED: govulncheck not installed. Install once: go install golang.org/x/vuln/cmd/govulncheck@latest"
else
  vout=$("$vc" ./... 2>&1)
  vrc=$?
  case "$vrc" in
    0) echo "PASS" ;;
    3) echo "$vout"; echo "FAIL: known vulnerabilities reachable from this code"; fail=1 ;;
    *) echo "$vout" | tail -n 5; echo "WARNING: govulncheck could not finish (network?). Not counted as pass or fail." ;;
  esac
fi

stage "go test"
race_flag="-race"
if [ "$(go env CGO_ENABLED)" != "1" ] || ! command -v "$(go env CC)" >/dev/null 2>&1; then
  echo "WARNING: race detector unavailable (needs CGO_ENABLED=1 and a C compiler)."
  echo "WARNING: running tests WITHOUT -race."
  race_flag=""
fi
# shellcheck disable=SC2086
if go test $race_flag -count=1 -timeout 60s ./...; then echo "PASS${race_flag:+ (with -race)}"; else echo "FAIL"; fail=1; fi

exit "$fail"
