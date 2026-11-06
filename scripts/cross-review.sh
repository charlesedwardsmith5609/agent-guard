#!/usr/bin/env bash
# Cross-model review: send the current diff to a different AI provider for an independent review.
# Usage: bash scripts/cross-review.sh [--provider cursor|openai|anthropic|auto] [--model NAME] [--base REF]
# Env:   REVIEW_PROVIDER, CURSOR_REVIEW_MODEL, OPENAI_API_KEY / ANTHROPIC_API_KEY, REVIEW_MODEL,
#        OPENAI_BASE_URL, ANTHROPIC_BASE_URL. See scripts/review-call.sh for how a provider is chosen.
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/review-call.sh

provider="${REVIEW_PROVIDER:-auto}"
model=""
explicit=0
base="HEAD"
base_given=0
while [ $# -gt 0 ]; do
  case "$1" in
    --provider) provider="$2"; explicit=1; shift 2 ;;
    --model) model="$2"; shift 2 ;;
    --base) base="$2"; base_given=1; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
review_resolve "$provider" "$model" || exit 2

# Include new, untracked files in the diff without staging their content.
git add --intent-to-add --all >/dev/null 2>&1 || true
get_diff() { git diff --no-color "$1" -- . ':(exclude)go.sum' ':(exclude)**/go.sum' ':(exclude)package-lock.json' ':(exclude)**/package-lock.json'; }
diff=$(get_diff "$base")
# Nothing uncommitted and no --base given: review the last commit instead.
if [ -z "$diff" ] && [ "$base_given" = 0 ] && git rev-parse -q --verify HEAD~1 >/dev/null; then
  base="HEAD~1"
  echo "No uncommitted changes; reviewing the last commit: $(git log -1 --format='%h %s')" >&2
  echo "(If the milestone spans several commits, rerun with --base REF.)" >&2
  diff=$(get_diff "$base")
fi
if [ -z "$diff" ]; then echo "No changes against $base. Nothing to review."; exit 0; fi
max=60000
if [ "${#diff}" -gt "$max" ]; then
  echo "WARNING: diff is ${#diff} chars; truncating to $max." >&2
  diff="${diff:0:$max}"
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# shellcheck disable=SC2016  # the backticks are literal markdown fences, not a command
printf 'Review this diff:\n\n```diff\n%s\n```\n' "$diff" > "$work/user.md"

export REVIEW_META_FILE="$work/meta"
review=$(review_call skills/review-checklist.md "$work/user.md" "$explicit")
read -r used_provider used_model < "$work/meta"

mkdir -p .reviews
out=".reviews/review-$(date +%Y%m%d-%H%M%S)-$used_provider.md"
printf '# Cross-model review (%s, %s, base %s)\n\n%s\n' "$used_provider" "$used_model" "$base" "$review" > "$out"
printf '%s\n\nSaved to %s\n' "$review" "$out"
