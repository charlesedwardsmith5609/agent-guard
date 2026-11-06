#!/usr/bin/env bash
# Validation gate: runs the checks for every language in this project.
# The project's languages and directories are listed in .pairing-profiles.
# Usage: bash scripts/check.sh
set -u
root="$(cd "$(dirname "$0")/.." && pwd)"
list="$root/.pairing-profiles"
[ -f "$list" ] || { echo "check: $list not found"; exit 2; }

fail=0 results=""
while read -r profile dir <&3; do
  [ -n "${profile:-}" ] || continue
  printf '\n######## %s (%s)\n' "$profile" "$dir"
  if (cd "$root/$dir" && bash "$root/scripts/checks/$profile.sh"); then
    results="$results\n  $profile ($dir): PASS"
  else
    results="$results\n  $profile ($dir): FAIL"
    fail=1
  fi
done 3< "$list"

printf '\nSummary:%b\n' "$results"
if [ "$fail" -eq 0 ]; then echo "CHECK PASSED"; else echo "CHECK FAILED"; fi
exit "$fail"
