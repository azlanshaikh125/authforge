#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034  # globals are shared across sourced files by design
# AUTHFORGE lib: Offline Session Security & Cookie Flag Analyzer.
#
# SECURITY: Descriptor files are parsed via strict whitelist + regex (never sourced).
# Set-Cookie headers are read from stdin/hidden prompt or file, never argv, and
# cookie values are NEVER printed, logged, or stored in findings.
[[ -n "${_AN_SESS_AUDIT:-}" ]] && return 0
_AN_SESS_AUDIT=1

declare -gA SESS_DESC=()
SESS_PARSE_ERRORS=0

CK_NAME=""
CK_SECURE=0
CK_HTTPONLY=0
CK_SAMESITE="none-specified"
CK_DOMAIN=""
CK_PATH=""
CK_PREFIX="none"

declare -gA _SESS_RULES=(
  [session_id_entropy_bits]='^[0-9]{1,4}$'
  [session_id_in_url]='^[01]$'
  [session_cookie_secure]='^[01]$'
  [session_cookie_httponly]='^[01]$'
  [session_cookie_samesite]='^(Strict|Lax|None|strict|lax|none|unset)$'
  [session_cookie_host_prefix]='^[01]$'
  [session_rotate_on_login]='^[01]$'
  [session_rotate_on_privilege_change]='^[01]$'
  [session_idle_timeout_min]='^[0-9]{1,5}$'
  [session_absolute_timeout_min]='^[0-9]{1,6}$'
  [session_server_side_revoke_on_logout]='^[01]$'
  [session_revoke_on_password_change]='^[01]$'
  [session_max_concurrent]='^[0-9]{1,4}$'
)

sess_parse_descriptor() { # <file>
  local file=$1 line key val
  SESS_DESC=()
  SESS_PARSE_ERRORS=0
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%$'\r'}
    line=$(str_trim "$line")
    if [[ -z $line || $line == \#* ]]; then continue; fi
    if [[ ! $line =~ ^([a-z0-9_]+)=(.*)$ ]]; then
      SESS_PARSE_ERRORS=$((SESS_PARSE_ERRORS + 1))
      continue
    fi
    key=${BASH_REMATCH[1]}
    val=$(str_trim "${BASH_REMATCH[2]}")
    if [[ -z ${_SESS_RULES[$key]+x} ]]; then
      SESS_PARSE_ERRORS=$((SESS_PARSE_ERRORS + 1))
      continue
    fi
    if [[ ! $val =~ ${_SESS_RULES[$key]} ]]; then
      SESS_PARSE_ERRORS=$((SESS_PARSE_ERRORS + 1))
      continue
    fi
    SESS_DESC[$key]=$val
  done <"$file"
  ((SESS_PARSE_ERRORS == 0))
}

# Parse a single Set-Cookie header line (without ever printing or storing its value).
sess_parse_cookie_header() { # <raw-header-line>
  local raw=${1%$'\r'}
  CK_NAME="" CK_SECURE=0 CK_HTTPONLY=0 CK_SAMESITE="unset" CK_DOMAIN="" CK_PATH="" CK_PREFIX="none"

  raw=${raw#Set-Cookie:}
  raw=${raw#set-cookie:}
  raw=$(str_trim "$raw")
  [[ -n $raw ]] || return 1

  local IFS=';' part idx=0
  for part in $raw; do
    part=$(str_trim "$part")
    if ((idx == 0)); then
      if [[ $part != *=* ]]; then return 1; fi
      CK_NAME=${part%%=*}
      CK_NAME=$(str_trim "$CK_NAME")
      if [[ $CK_NAME == __Host-* ]]; then CK_PREFIX="__Host-"
      elif [[ $CK_NAME == __Secure-* ]]; then CK_PREFIX="__Secure-"
      fi
    else
      local low=${part,,}
      case $low in
        secure) CK_SECURE=1 ;;
        httponly) CK_HTTPONLY=1 ;;
        samesite=strict) CK_SAMESITE="Strict" ;;
        samesite=lax) CK_SAMESITE="Lax" ;;
        samesite=none) CK_SAMESITE="None" ;;
        domain=*) CK_DOMAIN=${part#*=}; CK_DOMAIN=$(str_trim "$CK_DOMAIN") ;;
        path=*) CK_PATH=${part#*=}; CK_PATH=$(str_trim "$CK_PATH") ;;
      esac
    fi
    idx=$((idx + 1))
  done
  [[ -n $CK_NAME ]]
}
