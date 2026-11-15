#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034
# Minimal dependency-free test harness (TAP-like output).
unset BASH_ENV ENV CDPATH
TEST_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
AN_BIN="$TEST_ROOT/authforge.sh"
T_PASS=0 T_FAIL=0 T_SKIP=0
export LANG=C.UTF-8

t_ok() { T_PASS=$((T_PASS + 1)); printf 'ok - %s\n' "$1"; }
t_fail() { T_FAIL=$((T_FAIL + 1)); printf 'not ok - %s\n' "$1"; if [[ -n ${2:-} ]]; then printf '    %s\n' "$2"; fi; }
t_skip() { T_SKIP=$((T_SKIP + 1)); printf 'skip - %s (%s)\n' "$1" "$2"; }

assert_eq() { # expected actual desc
  if [[ $1 == "$2" ]]; then t_ok "$3"; else t_fail "$3" "expected [$1] got [$2]"; fi
}
assert_contains() { # haystack needle desc
  if [[ $1 == *"$2"* ]]; then t_ok "$3"; else t_fail "$3" "missing [$2]"; fi
}
assert_not_contains() {
  if [[ $1 != *"$2"* ]]; then t_ok "$3"; else t_fail "$3" "unexpectedly contains [$2]"; fi
}
assert_file_not_contains() { # file needle desc
  if ! grep -rqF -- "$2" "$1" 2>/dev/null; then t_ok "$3"; else t_fail "$3" "found [$2] in $1"; fi
}

t_summary() {
  printf '# summary pass=%d fail=%d skip=%d\n' "$T_PASS" "$T_FAIL" "$T_SKIP"
  ((T_FAIL == 0))
}

# Per-file sandbox: private data dir + TMPDIR, removed on exit.
# Automatically falls back to $TEST_ROOT/.tmp-test if $TMPDIR (or /tmp) is mounted noexec.
SB=""
sandbox() {
  local base=${TMPDIR:-/tmp} probe
  mkdir -p "$base" 2>/dev/null || base="$TEST_ROOT/.tmp-test"
  mkdir -p "$base"
  probe=$(mktemp "$base/an-exec-probe.XXXXXX")
  printf '#!/bin/sh\nexit 0\n' >"$probe"
  chmod +x "$probe"
  if ! "$probe" >/dev/null 2>&1; then
    rm -f "$probe"
    base="$TEST_ROOT/.tmp-test"
    mkdir -p "$base"
  else
    rm -f "$probe"
  fi
  SB=$(mktemp -d "$base/an-test.XXXXXX")
  mkdir -p "$SB/data" "$SB/tmp"
  export AN_DATA_DIR="$SB/data" TMPDIR="$SB/tmp"
  trap 'rm -rf "$SB"' EXIT
}

# Isolated copy of the whole repo (for tests that mutate config/modules).
clone_repo() { # -> sets CLONE and CLONE_BIN
  CLONE="$SB/clone"
  mkdir -p "$CLONE"
  (cd "$TEST_ROOT" && tar --exclude=./reports --exclude=./logs --exclude=./evidence --exclude=./.tmp-test --exclude=./.git -cf - .) | tar -xf - -C "$CLONE"
  mkdir -p "$CLONE/reports" "$CLONE/logs" "$CLONE/evidence"
  CLONE_BIN="$CLONE/authforge.sh"
}

# load_core: source framework internals for unit tests.
load_core() {
  AN_ROOT=$TEST_ROOT AN_PROFILE="" AN_MODULE=core
  : "${AN_DATA_DIR:=$TEST_ROOT}"
  shopt -s extglob
  local f
  for f in core/constants lib/strutil core/log core/ui core/errors core/tmp core/validate \
    core/config core/deps core/session core/findings core/authz core/plugin core/menu \
    lib/pwdcheck lib/hashid lib/wordlist lib/risk lib/mfa lib/session_audit lib/pwreset \
    lib/proto_audit lib/auth_intel lib/web_auth; do
    if [[ -f "$TEST_ROOT/$f.sh" ]]; then
      # shellcheck source=/dev/null
      source "$TEST_ROOT/$f.sh"
    fi
  done
  config_defaults
}

# Run the CLI capturing stdout, stderr and rc.
an() { # an <args...> ; results in OUT ERR RC
  local o e
  o=$(mktemp "$SB/o.XXXX") e=$(mktemp "$SB/e.XXXX")
  "$AN_BIN" --no-color "$@" >"$o" 2>"$e" </dev/null
  RC=$?
  OUT=$(<"$o") ERR=$(<"$e")
  rm -f "$o" "$e"
  return 0
}
an_stdin() { # an_stdin <stdin-text> <args...>
  local in=$1 o e
  shift
  o=$(mktemp "$SB/o.XXXX") e=$(mktemp "$SB/e.XXXX")
  printf '%s\n' "$in" | "$AN_BIN" --no-color "$@" >"$o" 2>"$e"
  RC=$?
  OUT=$(<"$o") ERR=$(<"$e")
  rm -f "$o" "$e"
  return 0
}
