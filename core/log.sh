#!/usr/bin/env bash
# shellcheck shell=bash
# AUTHFORGE core: structured logging with mandatory secret redaction.
[[ -n "${_AN_LOG:-}" ]] && return 0
_AN_LOG=1

AN_VERBOSE=${AN_VERBOSE:-0}
AN_QUIET=${AN_QUIET:-0}
AN_DEBUG=${AN_DEBUG:-0}
AN_LOG_FILE=${AN_LOG_FILE:-}
AN_LOG_LEVEL=${AN_LOG_LEVEL:-info}

declare -A _AN_LEVEL_NUM=([debug]=0 [info]=1 [warn]=2 [error]=3)

# Redact secrets/hashes from stdin -> stdout. Defence in depth: callers must
# still avoid passing secrets to the logger in the first place.
log_redact() {
  sed -E \
    -e 's/(Set-Cookie|Cookie)[[:space:]]*:[[:space:]]*.*/\1: [REDACTED]/I' \
    -e 's/Bearer[[:space:]]+[A-Za-z0-9._~+\/=-]+/Bearer [REDACTED]/Ig' \
    -e 's/(otpauth:\/\/[^[:space:]"'"'"']*[?&]secret=)[^&[:space:]"'"'"']+/\1[REDACTED]/Ig' \
    -e 's/(password|passwd|pwd|passphrase|secret|token|api[_-]?key|authorization|session(id)?|recovery[_-]?code|reset[_-]?token|hash|ntlm|lmhash)([[:space:]]*[=:][[:space:]]*)[^[:space:]&;,"]+/\1\3[REDACTED]/Ig' \
    -e 's/\$[A-Za-z0-9_.-]{1,24}\$[^[:space:]"'"'"']{4,}/[HASH-REDACTED]/g' \
    -e 's/\b(pbkdf2_(sha1|sha256|sha512)|bcrypt(_sha256)?|scrypt|argon2(id|i|d)?)\$[A-Za-z0-9$.\/_=+-]{6,}/[HASH-REDACTED]/Ig' \
    -e 's/\bscrypt:[0-9]+:[0-9]+:[0-9]+:[-A-Za-z0-9+\/=_$]{6,}/[HASH-REDACTED]/Ig' \
    -e 's/\{(SHA|SSHA|SHA256|SSHA256|SHA512|SSHA512|MD5|SMD5|CRYPT|CLEARTEXT)\}[A-Za-z0-9+\/=._$-]{4,}/[HASH-REDACTED]/Ig' \
    -e 's/\*[a-fA-F0-9]{40}\b/[HASH-REDACTED]/g' \
    -e 's/\b[a-fA-F0-9]{32,}\b/[HEX-REDACTED]/g'
}

log_ts() { printf '%(%Y-%m-%dT%H:%M:%S%z)T' -1; }

_log() { # _log <level> <module> <message...>
  local lvl=$1 mod=$2
  shift 2
  local msg="$*"
  msg=${msg//$'\n'/ }
  msg=$(printf '%s' "$msg" | log_redact)

  local want=${_AN_LEVEL_NUM[$AN_LOG_LEVEL]:-1}
  if ((AN_DEBUG)); then want=0; fi
  local have=${_AN_LEVEL_NUM[$lvl]}

  if [[ -n $AN_LOG_FILE && $have -ge $want ]]; then
    printf 'ts=%s level=%s module=%s msg="%s"\n' \
      "$(log_ts)" "${lvl^^}" "$mod" "${msg//\"/\\\"}" >>"$AN_LOG_FILE" 2>/dev/null || true
  fi

  # Console routing: errors/warnings always (unless quiet hides warn), info only with -v
  local show=0
  case $lvl in
    error) show=1 ;;
    warn) if ((!AN_QUIET)); then show=1; fi ;;
    info) if ((AN_VERBOSE && !AN_QUIET)); then show=1; fi ;;
    debug) if ((AN_DEBUG)); then show=1; fi ;;
  esac
  if ((show)); then
    local color=""
    case $lvl in
      error) color=${C_RED:-} ;;
      warn) color=${C_YELLOW:-} ;;
      debug) color=${C_DIM:-} ;;
    esac
    printf '%s[%-5s]%s %s: %s\n' "$color" "${lvl^^}" "${C_RESET:-}" "$mod" "$msg" >&2
  fi
  return 0
}

log_debug() { _log debug "${AN_MODULE:-core}" "$@"; }
log_info() { _log info "${AN_MODULE:-core}" "$@"; }
log_warn() { _log warn "${AN_MODULE:-core}" "$@"; }
log_error() { _log error "${AN_MODULE:-core}" "$@"; }
