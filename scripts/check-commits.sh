#!/usr/bin/env bash
# Verifies that every commit subject in the given range follows
# Conventional Commits (https://www.conventionalcommits.org/en/v1.0.0/).
set -euo pipefail

range="${1:?usage: check-commits.sh <git-range>}"
pattern='^(feat|fix|docs|refactor|test|chore|ci|perf|build|revert)(\([a-z0-9/,._-]+\))?!?: .+'
fail=0

while IFS= read -r line; do
  [ -z "$line" ] && continue
  hash="${line%% *}"
  subject="${line#* }"
  if [[ "$subject" =~ $pattern ]]; then
    echo "ok   $hash $subject"
  else
    echo "FAIL $hash $subject"
    fail=1
  fi
done < <(git log --no-merges --format='%h %s' "$range")

if [ "$fail" -ne 0 ]; then
  echo
  echo "Commit subjects must follow Conventional Commits, e.g. 'feat(detect): add port scan windows'."
  exit 1
fi
