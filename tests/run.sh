#!/usr/bin/env bash
# Test runner: executes every tests/*/test_*.sh in its own process and
# aggregates results. Exit 0 only if every test file passes.
# Usage: tests/run.sh [unit|integration|regression|all]
unset BASH_ENV ENV CDPATH
set -u
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
suite=${1:-all}
files=()
case $suite in
  all) files=("$ROOT"/unit/test_*.sh "$ROOT"/integration/test_*.sh "$ROOT"/regression/test_*.sh) ;;
  unit | integration | regression) files=("$ROOT/$suite"/test_*.sh) ;;
  *) echo "unknown suite: $suite" >&2; exit 2 ;;
esac
tp=0 tf=0 ts=0 bad=0
for f in "${files[@]}"; do
  out=$(bash "$f" 2>&1); rc=$?
  printf '%s\n' "$out"
  line=$(printf '%s\n' "$out" | grep '^# summary' | tail -1)
  if [[ $line =~ pass=([0-9]+)\ fail=([0-9]+)\ skip=([0-9]+) ]]; then
    tp=$((tp + BASH_REMATCH[1])) tf=$((tf + BASH_REMATCH[2])) ts=$((ts + BASH_REMATCH[3]))
  else
    echo "!! $f produced no summary (crashed?)"; bad=$((bad + 1))
  fi
  if ((rc != 0)); then bad=$((bad + 1)); fi
done
printf '\n==== TOTAL: %d passed, %d failed, %d skipped, %d file(s) failing or crashed ====\n' "$tp" "$tf" "$ts" "$bad"
((tf == 0 && bad == 0))
