#!/usr/bin/env bash
# shellcheck shell=bash
# AUTHFORGE core: error handling, cleanup registry, signal handling.
[[ -n "${_AN_ERRORS:-}" ]] && return 0
_AN_ERRORS=1

declare -a AN_CLEANUP_FNS=()

an_on_cleanup() { AN_CLEANUP_FNS+=("$1"); }

an_die() { # an_die <exit-code> <message...>
  local code=$1
  shift
  log_error "$*"
  exit "$code"
}

an_usage_error() {
  printf '%s: %s\nTry: %s --help\n' "${AN_NAME,,}" "$*" "${AN_NAME,,}" >&2
  exit "$EX_USAGE"
}

_an_run_cleanup() {
  local fn
  for fn in "${AN_CLEANUP_FNS[@]}"; do
    "$fn" || true
  done
  AN_CLEANUP_FNS=()
}

an_on_exit() {
  local rc=$?
  _an_run_cleanup
  if [[ -t 1 ]]; then printf '\e[?25h' 2>/dev/null || true; fi
  exit "$rc"
}

an_on_signal() { # graceful interruption
  local sig=$1
  log_warn "interrupted by SIG${sig}; cleaning up"
  exit "$EX_INTERRUPT"
}

an_on_err() { # only informative; BASH_COMMAND is redacted before logging
  local rc=$1 line=$2 cmd=$3
  log_debug "command failed rc=${rc} line=${line} cmd=${cmd}"
}

an_install_traps() {
  trap an_on_exit EXIT
  trap 'an_on_signal INT' INT
  trap 'an_on_signal TERM' TERM
  trap 'an_on_signal HUP' HUP
  trap 'an_on_err $? $LINENO "$BASH_COMMAND"' ERR
}
