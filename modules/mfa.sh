#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034  # globals are shared across sourced files by design
# AUTHFORGE module: MFA Security Assessment (menu 05) -- Milestone 3.
# Implemented: audit-config, audit-recovery, check-codes.
# Offline and defensive only. Never performs MFA bypass or online probing.

mod_mfa_info() { printf '05|MFA Security Assessment|Offline TOTP configuration, factor strength and recovery-code hygiene|ready'; }

_mfa_usage() {
  cat <<'USAGE'
Usage: authforge [global opts] mfa <subcommand> [args]

  audit-config FILE      Audit an MFA/TOTP configuration descriptor (key=value)
  audit-recovery FILE    Audit recovery-code policy settings in a descriptor (key=value)
  check-codes FILE       Stream-analyze a recovery-code dataset for entropy and duplicates

Descriptor files are parsed strictly by whitelist and never sourced or executed.
Recovery codes are never displayed, logged, or passed on command-line arguments.
USAGE
}

_mfa_rule() { # <PASS|FAIL|WARN|RECOMMEND|NOT TESTED> <text>
  printf '  %s %s\n' "$(ui_status_badge "$1")" "$2"
}

_mfa_load_file() { # <file>
  local f=$1
  validate_regular_file "$f" || an_die "$EX_VALIDATION" "not a readable regular file: $f"
  local mode
  mode=$(stat -c '%a' -- "$f")
  if [[ ${mode: -1} != 0 ]]; then log_warn "input file is world-accessible (mode $mode); restrict it"; fi
  if ! mfa_parse_descriptor "$f"; then
    an_die "$EX_CONFIG" "invalid MFA descriptor ($MFA_PARSE_ERRORS parse error(s)): $f"
  fi
  return 0
}

_mfa_cmd_audit_config() {
  local file=${1:-}
  [[ -n $file ]] || an_die "$EX_USAGE" "audit-config requires a FILE argument"
  _mfa_load_file "$file"

  local min_digits=${AN_CFG[mfa_min_totp_digits]:-6}
  local max_win=${AN_CFG[mfa_max_totp_window]:-1}
  local max_att=${AN_CFG[mfa_max_attempts]:-5}
  local req_pr=${AN_CFG[mfa_require_phishing_resistant]:-0}

  local mfa_en=${MFA_DESC[mfa_enabled]:-}
  local mfa_all=${MFA_DESC[mfa_required_for_all]:-}
  local webauthn=${MFA_DESC[mfa_webauthn_enabled]:-0}
  local totp_on=${MFA_DESC[mfa_allow_totp]:-0}
  local sms_on=${MFA_DESC[mfa_allow_sms]:-0}
  local email_on=${MFA_DESC[mfa_allow_email]:-0}
  local alg=${MFA_DESC[totp_algorithm]:-}
  local digits=${MFA_DESC[totp_digits]:-}
  local period=${MFA_DESC[totp_period_sec]:-}
  local win=${MFA_DESC[totp_window_steps]:-}
  local replay=${MFA_DESC[totp_replay_protection]:-}
  local attempts=${MFA_DESC[totp_max_attempts]:-}
  local lockout=${MFA_DESC[totp_lockout_sec]:-}
  local enc_rest=${MFA_DESC[mfa_secret_encrypted_at_rest]:-}
  local reauth_en=${MFA_DESC[mfa_require_reauth_to_enroll]:-}
  local reauth_dis=${MFA_DESC[mfa_require_reauth_to_disable]:-}

  printf 'MFA configuration audit: %s  (profile: %s)\n' "${file##*/}" "${AN_PROFILE:-default}"
  ui_rule

  # 1. Mandatory MFA enforcement
  if [[ $mfa_en == 0 ]]; then
    _mfa_rule FAIL "[REQUIREMENT] MFA is disabled (mfa_enabled=0)"
    findings_add CRITICAL HIGH verified "Multi-factor authentication is disabled" \
      "mfa_enabled=0 in ${file##*/}; accounts rely solely on single-factor credentials." \
      "Enable MFA across all accounts and prefer phishing-resistant WebAuthn/FIDO2." \
      "file=${file##*/}; setting=mfa_enabled=0" || true
    ui_rule
    return 0
  elif [[ $mfa_en == 1 ]]; then
    _mfa_rule PASS "[REQUIREMENT] MFA enabled"
  fi

  if [[ $mfa_all == 0 ]]; then
    _mfa_rule FAIL "[REQUIREMENT] MFA not enforced for all users (mfa_required_for_all=0)"
    findings_add HIGH HIGH verified "MFA is optional rather than universally enforced" \
      "mfa_required_for_all=0 allows accounts to operate without second-factor protection." \
      "Enforce MFA for all interactive and privileged accounts." \
      "file=${file##*/}; setting=mfa_required_for_all=0" || true
  elif [[ $mfa_all == 1 ]]; then
    _mfa_rule PASS "[REQUIREMENT] MFA enforced for all users"
  fi

  # 2. Factor strength & phishing resistance
  if [[ $sms_on == 1 || $email_on == 1 ]]; then
    if ((req_pr == 1)) && [[ $webauthn != 1 ]]; then
      _mfa_rule FAIL "[REQUIREMENT] Weak out-of-band MFA (SMS/email) enabled without WebAuthn under ${AN_PROFILE:-default}"
      findings_add HIGH HIGH verified "Weak out-of-band MFA permitted without phishing-resistant factor" \
        "mfa_allow_sms=$sms_on, mfa_allow_email=$email_on without mfa_webauthn_enabled=1 under profile ${AN_PROFILE:-default}." \
        "Enable FIDO2/WebAuthn and phase out SMS/email OTP factors." \
        "file=${file##*/}; mfa_allow_sms=$sms_on; mfa_allow_email=$email_on; webauthn=$webauthn" || true
    else
      _mfa_rule REVIEW "[RECOMMENDATION] SMS/email OTP enabled (susceptible to SIM-swap/phishing)"
      findings_add MEDIUM HIGH verified "SMS or email OTP fallback enabled" \
        "Out-of-band SMS/email factors (sms=$sms_on, email=$email_on) are vulnerable to SIM swapping and interception." \
        "Migrate users to FIDO2/WebAuthn or TOTP authenticator apps." \
        "file=${file##*/}; mfa_allow_sms=$sms_on; mfa_allow_email=$email_on" || true
    fi
  else
    _mfa_rule PASS "[RECOMMENDATION] No SMS/email OTP fallback enabled"
  fi

  if ((req_pr == 1)) && [[ $webauthn != 1 ]]; then
    _mfa_rule FAIL "[REQUIREMENT] Phishing-resistant WebAuthn/FIDO2 required by profile (${AN_PROFILE:-default})"
    findings_add MEDIUM HIGH verified "Phishing-resistant MFA (WebAuthn) not enabled" \
      "Profile ${AN_PROFILE:-default} requires phishing-resistant MFA, but mfa_webauthn_enabled=0." \
      "Enable FIDO2/WebAuthn security keys or passkeys." \
      "file=${file##*/}; setting=mfa_webauthn_enabled=0" || true
  elif [[ $webauthn == 1 ]]; then
    _mfa_rule PASS "[RECOMMENDATION] WebAuthn/FIDO2 enabled"
  fi

  # 3. TOTP parameters
  if [[ $totp_on == 1 ]]; then
    case ${alg^^} in
      MD5)
        _mfa_rule FAIL "[REQUIREMENT] TOTP algorithm MD5 is cryptographically broken"
        findings_add HIGH HIGH verified "TOTP configured with broken MD5 hash algorithm" \
          "totp_algorithm=MD5 is weak and non-standard for RFC 6238 TOTP." \
          "Use HMAC-SHA256 or HMAC-SHA1 (for authenticator app compatibility)." \
          "file=${file##*/}; setting=totp_algorithm=$alg" || true ;;
      SHA1)
        _mfa_rule WARN "[COMPATIBILITY] TOTP uses HMAC-SHA1 (RFC 6238 baseline; widely compatible, SHA256 preferred where supported)" ;;
      SHA256 | SHA512)
        _mfa_rule PASS "[RECOMMENDATION] TOTP uses $alg" ;;
    esac

    if [[ -n $digits ]]; then
      if ((10#$digits < 10#$min_digits)); then
        _mfa_rule FAIL "[REQUIREMENT] TOTP digits $digits < policy minimum $min_digits"
        findings_add MEDIUM HIGH verified "TOTP code length below policy minimum" \
          "totp_digits=$digits is below mfa_min_totp_digits=$min_digits." \
          "Configure at least $min_digits TOTP digits." \
          "file=${file##*/}; totp_digits=$digits; required=$min_digits" || true
      else
        _mfa_rule PASS "[REQUIREMENT] TOTP digits $digits (>= $min_digits)"
      fi
    fi

    if [[ -n $period ]]; then
      if ((10#$period == 0 || 10#$period > 60)); then
        _mfa_rule FAIL "[REQUIREMENT] TOTP period ${period}s outside safe 1..60s range"
        findings_add MEDIUM HIGH verified "Excessive TOTP validity period (${period}s)" \
          "totp_period_sec=$period extends code lifetime beyond 60 seconds." \
          "Use standard 30-second TOTP time steps." \
          "file=${file##*/}; totp_period_sec=$period" || true
      else
        _mfa_rule PASS "[REQUIREMENT] TOTP period ${period}s"
      fi
    fi

    if [[ -n $win ]]; then
      if ((10#$win > 10#$max_win)); then
        _mfa_rule FAIL "[REQUIREMENT] TOTP clock-skew window $win steps > policy max $max_win"
        findings_add MEDIUM HIGH verified "Excessive TOTP clock-skew acceptance window" \
          "totp_window_steps=$win exceeds mfa_max_totp_window=$max_win, widening the guessing/replay window." \
          "Reduce totp_window_steps to <= $max_win and enforce server NTP sync." \
          "file=${file##*/}; totp_window_steps=$win; max=$max_win" || true
      else
        _mfa_rule PASS "[REQUIREMENT] TOTP clock-skew window $win step(s) (<= $max_win)"
      fi
    fi

    if [[ $replay == 0 ]]; then
      _mfa_rule FAIL "[REQUIREMENT] TOTP replay protection disabled (totp_replay_protection=0)"
      findings_add HIGH HIGH verified "TOTP code replay protection disabled" \
        "totp_replay_protection=0 permits the same OTP code to be reused within the validity window." \
        "Record last accepted TOTP time-step per user and reject same/older steps." \
        "file=${file##*/}; setting=totp_replay_protection=0" || true
    elif [[ $replay == 1 ]]; then
      _mfa_rule PASS "[REQUIREMENT] TOTP replay protection enabled"
    fi

    if [[ -n $attempts ]]; then
      if ((10#$attempts == 0 || 10#$attempts > 10#$max_att)); then
        _mfa_rule FAIL "[REQUIREMENT] TOTP max attempts ($attempts) exceeds policy max ($max_att) or unlimited"
        findings_add HIGH HIGH verified "Weak or missing TOTP brute-force rate limiting" \
          "totp_max_attempts=$attempts exceeds mfa_max_attempts=$max_att (0 = unlimited)." \
          "Limit TOTP verification to <= $max_att failed attempts with lockout/backoff." \
          "file=${file##*/}; totp_max_attempts=$attempts; max=$max_att" || true
      else
        _mfa_rule PASS "[REQUIREMENT] TOTP attempt limit $attempts (<= $max_att)"
      fi
    fi

    if [[ -n $lockout ]] && ((10#$lockout < 60)); then
      _mfa_rule REVIEW "[RECOMMENDATION] TOTP lockout duration (${lockout}s) is short (< 60s)"
    fi
  fi

  # 4. Secret storage & enrollment lifecycle
  if [[ $enc_rest == 0 ]]; then
    _mfa_rule FAIL "[REQUIREMENT] TOTP secrets stored unencrypted at rest (mfa_secret_encrypted_at_rest=0)"
    findings_add HIGH HIGH verified "MFA shared secrets stored without encryption at rest" \
      "mfa_secret_encrypted_at_rest=0 exposes TOTP seeds if the database or backup is compromised." \
      "Encrypt TOTP secrets at rest using authenticated encryption (KMS/envelope key)." \
      "file=${file##*/}; setting=mfa_secret_encrypted_at_rest=0" || true
  elif [[ $enc_rest == 1 ]]; then
    _mfa_rule PASS "[REQUIREMENT] TOTP secrets encrypted at rest"
  fi

  if [[ $reauth_en == 0 || $reauth_dis == 0 ]]; then
    _mfa_rule FAIL "[REQUIREMENT] Re-authentication not required for MFA enrollment/disable"
    findings_add HIGH HIGH verified "Missing re-authentication gate for MFA lifecycle changes" \
      "mfa_require_reauth_to_enroll=$reauth_en, mfa_require_reauth_to_disable=$reauth_dis allows session-hijack MFA takeover." \
      "Require fresh authentication before enrolling, modifying, or disabling MFA factors." \
      "file=${file##*/}; reauth_enroll=$reauth_en; reauth_disable=$reauth_dis" || true
  elif [[ $reauth_en == 1 && $reauth_dis == 1 ]]; then
    _mfa_rule PASS "[REQUIREMENT] Re-authentication required for MFA enroll/disable"
  fi

  ui_rule
  return 0
}

_mfa_cmd_audit_recovery() {
  local file=${1:-}
  [[ -n $file ]] || an_die "$EX_USAGE" "audit-recovery requires a FILE argument"
  _mfa_load_file "$file"

  local min_ebits=${AN_CFG[mfa_min_recovery_entropy_bits]:-64}
  local cnt=${MFA_DESC[recovery_code_count]:-}
  local single=${MFA_DESC[recovery_code_single_use]:-}
  local hashed=${MFA_DESC[recovery_code_hashed_at_rest]:-}
  local ebits=${MFA_DESC[recovery_code_min_entropy_bits]:-}
  local regen=${MFA_DESC[recovery_regenerate_invalidates_old]:-}

  printf 'MFA recovery-code policy audit: %s  (profile: %s)\n' "${file##*/}" "${AN_PROFILE:-default}"
  ui_rule

  if [[ $hashed == 0 ]]; then
    _mfa_rule FAIL "[REQUIREMENT] Recovery codes stored in plaintext (recovery_code_hashed_at_rest=0)"
    findings_add CRITICAL HIGH verified "MFA recovery codes stored without cryptographic hashing" \
      "recovery_code_hashed_at_rest=0 exposes backup authentication codes upon database read access." \
      "Store recovery codes hashed (Argon2id/bcrypt or salted SHA-256 for high-entropy codes)." \
      "file=${file##*/}; setting=recovery_code_hashed_at_rest=0" || true
  elif [[ $hashed == 1 ]]; then
    _mfa_rule PASS "[REQUIREMENT] Recovery codes hashed at rest"
  fi

  if [[ $single == 0 ]]; then
    _mfa_rule FAIL "[REQUIREMENT] Recovery codes are reusable (recovery_code_single_use=0)"
    findings_add HIGH HIGH verified "MFA recovery codes are not single-use" \
      "recovery_code_single_use=0 allows a leaked backup code to be used repeatedly." \
      "Mark each recovery code as consumed immediately upon first successful use." \
      "file=${file##*/}; setting=recovery_code_single_use=0" || true
  elif [[ $single == 1 ]]; then
    _mfa_rule PASS "[REQUIREMENT] Recovery codes are single-use"
  fi

  if [[ $regen == 0 ]]; then
    _mfa_rule FAIL "[REQUIREMENT] Regenerating recovery codes does not invalidate old codes"
    findings_add MEDIUM HIGH verified "Old MFA recovery codes remain valid after regeneration" \
      "recovery_regenerate_invalidates_old=0 leaves stale backup codes active." \
      "Invalidate all previous recovery codes whenever a new set is generated." \
      "file=${file##*/}; setting=recovery_regenerate_invalidates_old=0" || true
  elif [[ $regen == 1 ]]; then
    _mfa_rule PASS "[REQUIREMENT] Regeneration invalidates prior recovery codes"
  fi

  if [[ -n $ebits ]]; then
    if ((10#$ebits < 10#$min_ebits)); then
      _mfa_rule FAIL "[REQUIREMENT] Recovery code entropy ${ebits} bits < policy minimum ${min_ebits} bits"
      findings_add HIGH HIGH verified "MFA recovery code entropy below policy minimum" \
        "recovery_code_min_entropy_bits=$ebits is below mfa_min_recovery_entropy_bits=$min_ebits." \
        "Generate recovery codes with at least $min_ebits bits from a CSPRNG." \
        "file=${file##*/}; recovery_entropy=$ebits; required=$min_ebits" || true
    else
      _mfa_rule PASS "[REQUIREMENT] Recovery code entropy ${ebits} bits (>= $min_ebits)"
    fi
  fi

  if [[ -n $cnt ]]; then
    if ((10#$cnt < 6 || 10#$cnt > 24)); then
      _mfa_rule REVIEW "[RECOMMENDATION] Recovery code count ($cnt) outside typical 6..24 range"
    else
      _mfa_rule PASS "[RECOMMENDATION] Recovery code count ($cnt)"
    fi
  fi

  ui_rule
  return 0
}

_mfa_cmd_check_codes() {
  local file=${1:-}
  [[ -n $file ]] || an_die "$EX_USAGE" "check-codes requires a FILE argument"
  validate_regular_file "$file" || an_die "$EX_VALIDATION" "not a readable regular file: $file"
  local mode
  mode=$(stat -c '%a' -- "$file")
  if [[ ${mode: -1} != 0 ]]; then log_warn "input file is world-accessible (mode $mode); restrict it"; fi

  local min_ebits=${AN_CFG[mfa_min_recovery_entropy_bits]:-64}
  mfa_check_codes_file "$file" "$min_ebits"

  printf 'Recovery-code dataset hygiene: %s  (codes are never printed)\n' "${file##*/}"
  ui_rule
  printf '  %-28s total=%s non-empty=%s unique=%s duplicates=%s\n' \
    "Code counts" "$MFA_RC_TOTAL" "$MFA_RC_NONEMPTY" "$MFA_RC_UNIQUE" "$MFA_RC_DUPS"
  printf '  %-28s min_len=%s chars  min_est_entropy=%s bits\n' \
    "Entropy floor" "$MFA_RC_MIN_LEN" "$MFA_RC_MIN_BITS"
  printf '  %-28s %s entries below %s-bit threshold\n' \
    "Weak codes" "$MFA_RC_WEAK_COUNT" "$min_ebits"
  ui_rule

  if ((MFA_RC_DUPS > 0)); then
    findings_add HIGH HIGH verified "Duplicate MFA recovery codes detected in dataset" \
      "$MFA_RC_DUPS duplicate recovery code group(s) found across $MFA_RC_NONEMPTY entries." \
      "Ensure recovery codes are generated independently from a CSPRNG." \
      "file=${file##*/}; duplicate_groups=$MFA_RC_DUPS; total=$MFA_RC_NONEMPTY" || true
  fi
  if ((MFA_RC_WEAK_COUNT > 0)); then
    findings_add HIGH MEDIUM heuristic "Low-entropy MFA recovery codes detected" \
      "$MFA_RC_WEAK_COUNT of $MFA_RC_NONEMPTY recovery code(s) estimate below ${min_ebits} bits (min=${MFA_RC_MIN_BITS} bits)." \
      "Increase recovery-code length and character-space entropy (>= ${min_ebits} bits)." \
      "file=${file##*/}; weak_codes=$MFA_RC_WEAK_COUNT; min_bits=$MFA_RC_MIN_BITS" || true
  fi
  return 0
}

mod_mfa_main() {
  local sub=${1:-}
  shift || true
  AN_MODULE=mfa
  case $sub in
    audit-config) session_run_check "mfa:audit-config" "descriptor:${1:+${1##*/}}" "file=${1:+${1##*/}};profile=${AN_PROFILE:-default}" _mfa_cmd_audit_config "$@" ;;
    audit-recovery) session_run_check "mfa:audit-recovery" "descriptor:${1:+${1##*/}}" "file=${1:+${1##*/}};profile=${AN_PROFILE:-default}" _mfa_cmd_audit_recovery "$@" ;;
    check-codes) session_run_check "mfa:check-codes" "dataset:${1:+${1##*/}}" "file=${1:+${1##*/}}" _mfa_cmd_check_codes "$@" ;;
    "" | help | -h | --help) _mfa_usage ;;
    *) an_die "$EX_USAGE" "mfa: unknown subcommand '$sub'" ;;
  esac
}

mod_mfa_menu() {
  AN_MODULE=mfa
  local c f
  while :; do
    ui_banner
    printf '\n  MFA SECURITY ASSESSMENT\n'
    ui_rule
    printf '  [1] Audit MFA/TOTP configuration descriptor\n'
    printf '  [2] Audit recovery-code policy descriptor\n'
    printf '  [3] Analyze a recovery-code dataset file\n'
    printf '  [b] Back\n\n'
    read -r -p "Select: " c || return 0
    case $c in
      1) read -r -p "Path to MFA descriptor: " f || return 0; (session_run_check "mfa:audit-config" "descriptor:${f##*/}" "file=${f##*/}" _mfa_cmd_audit_config "$f") || true; ui_pause ;;
      2) read -r -p "Path to MFA descriptor: " f || return 0; (session_run_check "mfa:audit-recovery" "descriptor:${f##*/}" "file=${f##*/}" _mfa_cmd_audit_recovery "$f") || true; ui_pause ;;
      3) read -r -p "Path to recovery-code file: " f || return 0; (session_run_check "mfa:check-codes" "dataset:${f##*/}" "file=${f##*/}" _mfa_cmd_check_codes "$f") || true; ui_pause ;;
      b | B | q | Q) return 0 ;;
      *) printf 'Invalid selection.\n' ;;
    esac
  done
}
