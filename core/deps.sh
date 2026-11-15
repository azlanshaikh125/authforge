#!/usr/bin/env bash
# shellcheck shell=bash
# AUTHFORGE core: dependency management and system diagnostics ("doctor").
[[ -n "${_AN_DEPS:-}" ]] && return 0
_AN_DEPS=1

readonly -a AN_REQUIRED_CMDS=(awk sed grep sort uniq tr head wc mktemp date od stat readlink realpath cat mkdir chmod cp rm mv ln flock id sha256sum)
readonly -a AN_OPTIONAL_CMDS=(shellcheck tput openssl curl timeout getent iconv tar)

deps_check_required() { # prints missing commands; returns number missing
  local c missing=0
  for c in "${AN_REQUIRED_CMDS[@]}"; do
    if ! command -v "$c" >/dev/null 2>&1 && [[ ! -x "/usr/bin/$c" && ! -x "/bin/$c" ]]; then
      printf '%s\n' "$c"
      missing=$((missing + 1))
    fi
  done
  return "$missing"
}

# doctor: returns 0 if no hard failures, EX_DEPENDENCY otherwise
deps_doctor() {
  local fails=0 warns=0 total=0 n=0 c
  total=$((${#AN_REQUIRED_CMDS[@]} + ${#AN_OPTIONAL_CMDS[@]} + 5))
  _res() { printf '%s %s\n' "$(ui_status_badge "$1")" "$2"; }

  if ((BASH_VERSINFO[0] >= 5)); then _res PASS "bash ${BASH_VERSION}"; else _res FAIL "bash >= 5 required (found ${BASH_VERSION})"; fails=$((fails + 1)); fi
  n=$((n + 1)); ui_progress "$n" "$total" "bash"

  for c in "${AN_REQUIRED_CMDS[@]}"; do
    if command -v "$c" >/dev/null 2>&1; then _res PASS "required: $c"; else _res FAIL "required command missing: $c"; fails=$((fails + 1)); fi
    n=$((n + 1)); ui_progress "$n" "$total" "$c"
  done
  for c in "${AN_OPTIONAL_CMDS[@]}"; do
    if command -v "$c" >/dev/null 2>&1; then _res PASS "optional: $c"; else _res WARN "optional command missing: $c"; warns=$((warns + 1)); fi
    n=$((n + 1)); ui_progress "$n" "$total" "$c"
  done

  if [[ -r /dev/urandom ]]; then _res PASS "/dev/urandom readable"; else _res FAIL "/dev/urandom not readable"; fails=$((fails + 1)); fi
  n=$((n + 1)); ui_progress "$n" "$total" "entropy source"

  local d ok=1
  for d in logs reports evidence; do
    if [[ -d $AN_DATA_DIR/$d && -w $AN_DATA_DIR/$d ]]; then :; else ok=0; fi
  done
  if ((ok)); then _res PASS "data directories writable ($AN_DATA_DIR)"; else _res FAIL "data directories not writable ($AN_DATA_DIR)"; fails=$((fails + 1)); fi
  n=$((n + 1)); ui_progress "$n" "$total" "data dirs"

  local os="unknown"
  if [[ -r /etc/os-release ]]; then
    # shellcheck source=/dev/null
    os=$(. /etc/os-release && printf '%s' "${ID:-unknown}")
  fi
  case $os in
    kali | ubuntu | debian) _res PASS "platform: $os (supported)" ;;
    *) _res WARN "platform: $os (not in supported set: kali/ubuntu/debian)"; warns=$((warns + 1)) ;;
  esac
  n=$((n + 1)); ui_progress "$n" "$total" "platform"

  local awkv
  awkv=$(awk --version 2>&1 | head -1 || true)
  [[ -n $awkv ]] || awkv=$(awk -W version 2>&1 | head -1 || true)
  _res PASS "awk: ${awkv:-unknown}"
  n=$((n + 1)); ui_progress "$n" "$total" "awk"

  if ui_is_utf8; then _res PASS "UTF-8 locale"; else _res WARN "non-UTF-8 locale: banner falls back to ASCII"; warns=$((warns + 1)); fi
  n=$((n + 1)); ui_progress "$n" "$total" "locale"

  printf '\nSummary: %d failure(s), %d warning(s)\n' "$fails" "$warns"
  unset -f _res
  if ((fails > 0)); then return "$EX_DEPENDENCY"; fi
  return 0
}
