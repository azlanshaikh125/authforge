#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034  # globals are shared across sourced files by design
# AUTHFORGE lib: Offline Password-Reset Workflow Security Analyzer.
#
# SECURITY: Descriptor files are parsed via strict whitelist + regex (never sourced).
[[ -n "${_AN_PWRESET:-}" ]] && return 0
_AN_PWRESET=1

declare -gA PWR_DESC=()
PWR_PARSE_ERRORS=0

declare -gA _PWR_RULES=(
  [reset_token_entropy_bits]='^[0-9]{1,4}$'
  [reset_token_hashed_at_rest]='^[01]$'
  [reset_token_single_use]='^[01]$'
  [reset_token_ttl_min]='^[0-9]{1,5}$'
  [reset_uniform_response]='^[01]$'
  [reset_rate_limit_enabled]='^[01]$'
  [reset_max_requests_per_hour]='^[0-9]{1,4}$'
  [reset_security_questions_enabled]='^[01]$'
  [reset_send_password_in_email]='^[01]$'
  [reset_revoke_active_sessions]='^[01]$'
  [reset_allow_host_header_link]='^[01]$'
  [reset_notify_user_on_change]='^[01]$'
  [reset_require_mfa_if_enrolled]='^[01]$'
)

pwr_parse_descriptor() { # <file>
  local file=$1 line key val
  PWR_DESC=()
  PWR_PARSE_ERRORS=0
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%$'\r'}
    line=$(str_trim "$line")
    if [[ -z $line || $line == \#* ]]; then continue; fi
    if [[ ! $line =~ ^([a-z0-9_]+)=(.*)$ ]]; then
      PWR_PARSE_ERRORS=$((PWR_PARSE_ERRORS + 1))
      continue
    fi
    key=${BASH_REMATCH[1]}
    val=$(str_trim "${BASH_REMATCH[2]}")
    if [[ -z ${_PWR_RULES[$key]+x} ]]; then
      PWR_PARSE_ERRORS=$((PWR_PARSE_ERRORS + 1))
      continue
    fi
    if [[ ! $val =~ ${_PWR_RULES[$key]} ]]; then
      PWR_PARSE_ERRORS=$((PWR_PARSE_ERRORS + 1))
      continue
    fi
    PWR_DESC[$key]=$val
  done <"$file"
  ((PWR_PARSE_ERRORS == 0))
}
