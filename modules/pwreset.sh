#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034  # globals are shared across sourced files by design
# AUTHFORGE module: Password Reset Security Audit (menu 08) -- Milestone 3.
# Implemented: analyze.
# Offline and defensive only. Never triggers password resets or probes endpoints.

mod_pwreset_info() { printf '08|Password Reset Security Audit|Offline reset-token strength, enumeration and workflow audit|ready'; }

_pwr_usage() {
  cat <<'USAGE'
Usage: authforge [global opts] pwreset <subcommand> [args]

  analyze FILE      Audit a password-reset workflow descriptor (key=value)

Descriptor files are parsed strictly by whitelist and never sourced or executed.
USAGE
}

_pwr_rule() {
  printf '  %s %s\n' "$(ui_status_badge "$1")" "$2"
}

_pwr_cmd_analyze() {
  local file=${1:-}
  [[ -n $file ]] || an_die "$EX_USAGE" "analyze requires a FILE argument"
  validate_regular_file "$file" || an_die "$EX_VALIDATION" "not a readable regular file: $file"
  local mode
  mode=$(stat -c '%a' -- "$file")
  if [[ ${mode: -1} != 0 ]]; then log_warn "input file is world-accessible (mode $mode); restrict it"; fi
  if ! pwr_parse_descriptor "$file"; then
    an_die "$EX_CONFIG" "invalid password-reset descriptor ($PWR_PARSE_ERRORS parse error(s)): $file"
  fi

  local min_eb=${AN_CFG[reset_min_entropy_bits]:-128}
  local max_ttl=${AN_CFG[reset_max_token_ttl_min]:-30}
  local max_req=${AN_CFG[reset_max_requests_per_hour]:-5}

  local ebits=${PWR_DESC[reset_token_entropy_bits]:-}
  local hashed=${PWR_DESC[reset_token_hashed_at_rest]:-}
  local single=${PWR_DESC[reset_token_single_use]:-}
  local ttl=${PWR_DESC[reset_token_ttl_min]:-}
  local unif=${PWR_DESC[reset_uniform_response]:-}
  local rl=${PWR_DESC[reset_rate_limit_enabled]:-}
  local rph=${PWR_DESC[reset_max_requests_per_hour]:-}
  local secq=${PWR_DESC[reset_security_questions_enabled]:-}
  local plain_mail=${PWR_DESC[reset_send_password_in_email]:-}
  local rev_sess=${PWR_DESC[reset_revoke_active_sessions]:-}
  local host_hdr=${PWR_DESC[reset_allow_host_header_link]:-}
  local notify=${PWR_DESC[reset_notify_user_on_change]:-}
  local mfa_req=${PWR_DESC[reset_require_mfa_if_enrolled]:-}

  printf 'Password-reset workflow audit: %s  (profile: %s)\n' "${file##*/}" "${AN_PROFILE:-default}"
  ui_rule

  # 1. Plaintext password email (CRITICAL)
  if [[ $plain_mail == 1 ]]; then
    _pwr_rule FAIL "[REQUIREMENT] Plaintext or temporary password sent via email (reset_send_password_in_email=1)"
    findings_add CRITICAL HIGH verified "Password-reset workflow transmits secrets in email" \
      "reset_send_password_in_email=1 sends plaintext or temporary passwords over unencrypted email." \
      "Send only time-limited, single-use, high-entropy reset tokens over HTTPS." \
      "file=${file##*/}; setting=reset_send_password_in_email=1" || true
  elif [[ $plain_mail == 0 ]]; then
    _pwr_rule PASS "[REQUIREMENT] Passwords are never emailed"
  fi

  # 2. Token strength, hashing, single-use, TTL
  if [[ -n $ebits ]]; then
    if ((10#$ebits < 64)); then
      _pwr_rule FAIL "[REQUIREMENT] Reset token entropy ${ebits} bits is critically low (< 64 bits)"
      findings_add CRITICAL HIGH verified "Password-reset token entropy is critically weak" \
        "reset_token_entropy_bits=$ebits permits practical token guessing." \
        "Generate reset tokens with >= 128 bits from a CSPRNG." \
        "file=${file##*/}; reset_token_entropy_bits=$ebits" || true
    elif ((10#$ebits < 10#$min_eb)); then
      _pwr_rule FAIL "[REQUIREMENT] Reset token entropy ${ebits} bits < policy minimum ${min_eb} bits"
      findings_add HIGH HIGH verified "Password-reset token entropy below policy minimum" \
        "reset_token_entropy_bits=$ebits is below reset_min_entropy_bits=$min_eb." \
        "Increase reset token entropy to >= $min_eb bits." \
        "file=${file##*/}; reset_token_entropy_bits=$ebits; required=$min_eb" || true
    else
      _pwr_rule PASS "[REQUIREMENT] Reset token entropy ${ebits} bits (>= $min_eb)"
    fi
  fi

  if [[ $hashed == 0 ]]; then
    _pwr_rule FAIL "[REQUIREMENT] Reset tokens stored unhashed at rest (reset_token_hashed_at_rest=0)"
    findings_add HIGH HIGH verified "Password-reset tokens stored in plaintext" \
      "reset_token_hashed_at_rest=0 allows database read access to hijack active reset links." \
      "Store only a cryptographic hash (e.g. SHA-256) of the reset token." \
      "file=${file##*/}; setting=reset_token_hashed_at_rest=0" || true
  elif [[ $hashed == 1 ]]; then
    _pwr_rule PASS "[REQUIREMENT] Reset tokens hashed at rest"
  fi

  if [[ $single == 0 ]]; then
    _pwr_rule FAIL "[REQUIREMENT] Reset tokens are reusable (reset_token_single_use=0)"
    findings_add HIGH HIGH verified "Password-reset tokens are not single-use" \
      "reset_token_single_use=0 permits replay of a previously used reset token." \
      "Invalidate reset tokens immediately upon consumption." \
      "file=${file##*/}; setting=reset_token_single_use=0" || true
  elif [[ $single == 1 ]]; then
    _pwr_rule PASS "[REQUIREMENT] Reset tokens are single-use"
  fi

  if [[ -n $ttl ]]; then
    if ((10#$ttl == 0 || 10#$ttl > 10#$max_ttl)); then
      _pwr_rule FAIL "[REQUIREMENT] Reset token TTL ${ttl}m exceeds policy max ${max_ttl}m (0 = unlimited)"
      findings_add MEDIUM HIGH verified "Password-reset token lifetime exceeds policy threshold" \
        "reset_token_ttl_min=$ttl exceeds reset_max_token_ttl_min=$max_ttl." \
        "Shorten reset token TTL to <= $max_ttl minutes." \
        "file=${file##*/}; reset_token_ttl_min=$ttl; max_ttl=$max_ttl" || true
    else
      _pwr_rule PASS "[REQUIREMENT] Reset token TTL ${ttl}m (<= ${max_ttl}m)"
    fi
  fi

  # 3. Enumeration, rate limiting, security questions, Host header poisoning
  if [[ $unif == 0 ]]; then
    _pwr_rule FAIL "[REQUIREMENT] Non-uniform reset response enables account enumeration"
    findings_add MEDIUM HIGH verified "Password-reset endpoint leaks account existence" \
      "reset_uniform_response=0 distinguishes valid vs. invalid accounts in responses." \
      "Return a generic response and normalize timing regardless of account existence." \
      "file=${file##*/}; setting=reset_uniform_response=0" || true
  elif [[ $unif == 1 ]]; then
    _pwr_rule PASS "[REQUIREMENT] Uniform response prevents enumeration"
  fi

  if [[ $rl == 0 ]] || { [[ -n $rph ]] && ((10#$rph == 0 || 10#$rph > 10#$max_req)); }; then
    _pwr_rule FAIL "[REQUIREMENT] Weak or disabled reset rate limiting (enabled=$rl, max_per_hr=${rph:-unset}, limit=$max_req)"
    findings_add MEDIUM HIGH verified "Weak or missing password-reset rate limiting" \
      "rate_limit=$rl, max_per_hour=${rph:-unset} exceeds policy limit $max_req." \
      "Enforce rate limiting of <= $max_req reset requests per hour per account/IP." \
      "file=${file##*/}; rate_limit=$rl; max_per_hr=${rph:-unset}" || true
  elif [[ $rl == 1 ]]; then
    _pwr_rule PASS "[REQUIREMENT] Reset rate limiting enabled (${rph:-n/a}/hr <= $max_req)"
  fi

  if [[ $secq == 1 ]]; then
    _pwr_rule FAIL "[REQUIREMENT] Knowledge-based security questions enabled (reset_security_questions_enabled=1)"
    findings_add HIGH HIGH verified "Weak knowledge-based security questions used for account recovery" \
      "reset_security_questions_enabled=1 relies on guessable or OSINT-recoverable answers." \
      "Remove security questions and rely on verified out-of-band tokens or MFA recovery." \
      "file=${file##*/}; setting=reset_security_questions_enabled=1" || true
  elif [[ $secq == 0 ]]; then
    _pwr_rule PASS "[REQUIREMENT] Security questions disabled"
  fi

  if [[ $host_hdr == 1 ]]; then
    _pwr_rule FAIL "[REQUIREMENT] Reset links trust HTTP Host header (reset_allow_host_header_link=1)"
    findings_add HIGH HIGH verified "Password-reset link generation vulnerable to Host header poisoning" \
      "reset_allow_host_header_link=1 allows attackers to redirect reset links to an external domain." \
      "Construct reset links strictly from an allowlisted server-configured canonical origin." \
      "file=${file##*/}; setting=reset_allow_host_header_link=1" || true
  elif [[ $host_hdr == 0 ]]; then
    _pwr_rule PASS "[REQUIREMENT] Reset links use canonical origin (Host header ignored)"
  fi

  # 4. Post-reset session revocation & notifications
  if [[ $rev_sess == 0 ]]; then
    _pwr_rule FAIL "[REQUIREMENT] Active sessions not revoked on password reset (reset_revoke_active_sessions=0)"
    findings_add HIGH HIGH verified "Active sessions survive password reset" \
      "reset_revoke_active_sessions=0 leaves existing potentially compromised sessions active." \
      "Invalidate all active sessions when a password reset completes." \
      "file=${file##*/}; setting=reset_revoke_active_sessions=0" || true
  elif [[ $rev_sess == 1 ]]; then
    _pwr_rule PASS "[REQUIREMENT] Active sessions revoked upon password reset"
  fi

  if [[ $notify == 0 ]]; then
    _pwr_rule REVIEW "[RECOMMENDATION] User notification on password reset disabled"
  elif [[ $notify == 1 ]]; then
    _pwr_rule PASS "[RECOMMENDATION] User notified upon password reset"
  fi

  if [[ $mfa_req == 0 ]]; then
    _pwr_rule REVIEW "[RECOMMENDATION] Enrolled MFA not checked during password reset"
  elif [[ $mfa_req == 1 ]]; then
    _pwr_rule PASS "[RECOMMENDATION] Enrolled MFA verified during password reset"
  fi

  ui_rule
  return 0
}

mod_pwreset_main() {
  local sub=${1:-}
  shift || true
  AN_MODULE=pwreset
  case $sub in
    analyze) session_run_check "pwreset:analyze" "descriptor:${1:+${1##*/}}" "file=${1:+${1##*/}};profile=${AN_PROFILE:-default}" _pwr_cmd_analyze "$@" ;;
    "" | help | -h | --help) _pwr_usage ;;
    *) an_die "$EX_USAGE" "pwreset: unknown subcommand '$sub'" ;;
  esac
}

mod_pwreset_menu() {
  AN_MODULE=pwreset
  local c f
  while :; do
    ui_banner
    printf '\n  PASSWORD RESET SECURITY AUDIT\n'
    ui_rule
    printf '  [1] Audit password-reset workflow descriptor\n'
    printf '  [b] Back\n\n'
    read -r -p "Select: " c || return 0
    case $c in
      1) read -r -p "Path to password-reset descriptor: " f || return 0; (session_run_check "pwreset:analyze" "descriptor:${f##*/}" "file=${f##*/}" _pwr_cmd_analyze "$f") || true; ui_pause ;;
      b | B | q | Q) return 0 ;;
      *) printf 'Invalid selection.\n' ;;
    esac
  done
}
