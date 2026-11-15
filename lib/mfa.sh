#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034  # globals are shared across sourced files by design
# AUTHFORGE lib: Offline MFA Configuration & Recovery-Code Hygiene Engine.
#
# SECURITY: Descriptor files are parsed via strict whitelist + regex (never sourced).
# Recovery-code files are streamed via LC_ALL=C awk and sort -T "$AN_TMPDIR";
# candidate codes and TOTP secrets are NEVER printed, logged, or placed on argv.
[[ -n "${_AN_MFA:-}" ]] && return 0
_AN_MFA=1

declare -gA MFA_DESC=()
declare -ga MFA_ISSUES=()
MFA_PARSE_ERRORS=0

MFA_RC_TOTAL=0
MFA_RC_NONEMPTY=0
MFA_RC_UNIQUE=0
MFA_RC_DUPS=0
MFA_RC_MIN_LEN=0
MFA_RC_MIN_BITS="0.0"
MFA_RC_WEAK_COUNT=0

declare -gA _MFA_RULES=(
  [mfa_enabled]='^[01]$'
  [mfa_required_for_all]='^[01]$'
  [mfa_webauthn_enabled]='^[01]$'
  [mfa_allow_totp]='^[01]$'
  [mfa_allow_sms]='^[01]$'
  [mfa_allow_email]='^[01]$'
  [totp_algorithm]='^(SHA1|SHA256|SHA512|MD5|sha1|sha256|sha512|md5)$'
  [totp_digits]='^[0-9]{1,2}$'
  [totp_period_sec]='^[0-9]{1,4}$'
  [totp_window_steps]='^[0-9]{1,2}$'
  [totp_replay_protection]='^[01]$'
  [totp_max_attempts]='^[0-9]{1,4}$'
  [totp_lockout_sec]='^[0-9]{1,6}$'
  [mfa_secret_encrypted_at_rest]='^[01]$'
  [mfa_require_reauth_to_enroll]='^[01]$'
  [mfa_require_reauth_to_disable]='^[01]$'
  [recovery_code_count]='^[0-9]{1,3}$'
  [recovery_code_single_use]='^[01]$'
  [recovery_code_hashed_at_rest]='^[01]$'
  [recovery_code_min_entropy_bits]='^[0-9]{1,3}$'
  [recovery_regenerate_invalidates_old]='^[01]$'
)

mfa_parse_descriptor() { # <file>
  local file=$1 line key val n=0
  MFA_DESC=()
  MFA_ISSUES=()
  MFA_PARSE_ERRORS=0

  while IFS= read -r line || [[ -n $line ]]; do
    n=$((n + 1))
    line=${line%$'\r'}
    line=$(str_trim "$line")
    if [[ -z $line || $line == \#* ]]; then continue; fi
    if [[ ! $line =~ ^([a-z0-9_]+)=(.*)$ ]]; then
      MFA_PARSE_ERRORS=$((MFA_PARSE_ERRORS + 1))
      continue
    fi
    key=${BASH_REMATCH[1]}
    val=$(str_trim "${BASH_REMATCH[2]}")
    if [[ -z ${_MFA_RULES[$key]+x} ]]; then
      MFA_PARSE_ERRORS=$((MFA_PARSE_ERRORS + 1))
      continue
    fi
    if [[ ! $val =~ ${_MFA_RULES[$key]} ]]; then
      MFA_PARSE_ERRORS=$((MFA_PARSE_ERRORS + 1))
      continue
    fi
    MFA_DESC[$key]=$val
  done <"$file"
  ((MFA_PARSE_ERRORS == 0))
}

# Streaming analysis of an authorized recovery-code fixture/dataset.
# Never prints or logs individual recovery codes.
mfa_check_codes_file() { # <file> [min_entropy_bits]
  local file=$1
  local min_bits=${2:-${AN_CFG[mfa_min_recovery_entropy_bits]:-64}}
  MFA_RC_TOTAL=0 MFA_RC_NONEMPTY=0 MFA_RC_UNIQUE=0 MFA_RC_DUPS=0
  MFA_RC_MIN_LEN=0 MFA_RC_MIN_BITS="0.0" MFA_RC_WEAK_COUNT=0

  local norm_file awk_out
  norm_file=$(tmp_file)

  awk_out=$(LC_ALL=C awk -v min_b="$min_bits" -v norm_out="$norm_file" '
    {
      total++
      sub(/\r$/, "")
      if (length($0) == 0 || substr($0, 1, 1) == "#") next
      nonempty++
      print $0 > norm_out

      # Strip common grouping hyphens/spaces to estimate true secret character count
      clean = $0
      gsub(/[- ]/, "", clean)
      clen = length(clean)
      if (nonempty == 1 || clen < min_len) min_len = clen

      pool = 0
      if (clean ~ /[a-z]/) pool += 26
      if (clean ~ /[A-Z]/) pool += 26
      if (clean ~ /[0-9]/) pool += 10
      if (clean ~ /[^A-Za-z0-9]/) pool += 33
      if (pool <= 1) pool = 10
      bits = clen * (log(pool) / log(2))

      if (nonempty == 1 || bits < min_est) min_est = bits
      if (bits < min_b || clen < 8) weak++
    }
    END {
      if (nonempty == 0) { min_len = 0; min_est = 0.0 }
      printf "%d|%d|%d|%.1f|%d\n", total+0, nonempty+0, min_len+0, min_est, weak+0
    }' "$file")

  IFS='|' read -r MFA_RC_TOTAL MFA_RC_NONEMPTY MFA_RC_MIN_LEN MFA_RC_MIN_BITS MFA_RC_WEAK_COUNT <<<"$awk_out"

  if ((MFA_RC_NONEMPTY > 0)) && [[ -s $norm_file ]]; then
    read -r MFA_RC_UNIQUE MFA_RC_DUPS < <(
      LC_ALL=C sort -T "$AN_TMPDIR" -- "$norm_file" | uniq -c |
        awk '{u++; if ($1>1) d++} END{printf "%d %d\n", u+0, d+0}'
    )
  fi
  rm -f -- "$norm_file"
  return 0
}
