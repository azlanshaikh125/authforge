#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034  # globals are shared across sourced files by design
# AUTHFORGE lib: Authorized Lab-Only Web Authentication Assessment helpers.
#
# SECURITY: Never logs or prints Set-Cookie values, Authorization headers, or tokens.
[[ -n "${_AN_WEB_AUTH:-}" ]] && return 0
_AN_WEB_AUTH=1

WA_HAS_CSP=0
WA_HAS_XFO=0
WA_HAS_CACHE_NOSTORE=0
WA_HAS_REFERRER=0
WA_HAS_RATELIMIT_HDR=0
WA_COOKIE_COUNT=0
declare -ga WA_COOKIE_LINES=()

_wa_reset_headers() {
  WA_HAS_CSP=0
  WA_HAS_XFO=0
  WA_HAS_CACHE_NOSTORE=0
  WA_HAS_REFERRER=0
  WA_HAS_RATELIMIT_HDR=0
  WA_COOKIE_COUNT=0
  WA_COOKIE_LINES=()
}

# Pure parser for HTTP security & cookie headers.
# Resets state whenever a new HTTP status block begins (M4-AUD-04).
web_auth_parse_headers() { # <hdr_file>
  _wa_reset_headers
  local f=$1 line low
  [[ -s $f ]] || return 1

  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%$'\r'}
    if [[ $line =~ ^HTTP/[0-9.]+\ [0-9]{3} ]]; then
      _wa_reset_headers
      continue
    fi
    low=${line,,}
    case $low in
      content-security-policy:*) WA_HAS_CSP=1 ;;
      x-frame-options:*) WA_HAS_XFO=1 ;;
      referrer-policy:*) WA_HAS_REFERRER=1 ;;
      cache-control:*no-store*) WA_HAS_CACHE_NOSTORE=1 ;;
      x-ratelimit-*:* | retry-after:* | ratelimit-*:) WA_HAS_RATELIMIT_HDR=1 ;;
      set-cookie:*)
        WA_COOKIE_COUNT=$((WA_COOKIE_COUNT + 1))
        WA_COOKIE_LINES+=("$line") ;;
    esac
  done <"$f"
  return 0
}
