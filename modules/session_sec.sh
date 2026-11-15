#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034  # globals are shared across sourced files by design
# AUTHFORGE module: Session Security Analysis (menu 07) -- Milestone 3.
# Implemented: analyze, check-cookie.
# Offline and defensive only. Never probes live sessions or captures live tokens.

mod_session_sec_info() { printf '07|Session Security Analysis|Offline session lifecycle, fixation, timeout and cookie-flag audit|ready'; }

_sa_usage() {
  cat <<'USAGE'
Usage: authforge [global opts] session-audit <subcommand> [args]

  analyze FILE      Audit a session-management configuration descriptor (key=value)
  check-cookie      Audit a Set-Cookie header line (read from stdin or prompt, never argv)

Descriptor files are parsed strictly by whitelist and never sourced or executed.
Session tokens and cookie values are never printed, logged, or stored in findings.
USAGE
}

_sa_rule() {
  printf '  %s %s\n' "$(ui_status_badge "$1")" "$2"
}

_sa_cmd_analyze() {
  local file=${1:-}
  [[ -n $file ]] || an_die "$EX_USAGE" "analyze requires a FILE argument"
  validate_regular_file "$file" || an_die "$EX_VALIDATION" "not a readable regular file: $file"
  local mode
  mode=$(stat -c '%a' -- "$file")
  if [[ ${mode: -1} != 0 ]]; then log_warn "input file is world-accessible (mode $mode); restrict it"; fi
  if ! sess_parse_descriptor "$file"; then
    an_die "$EX_CONFIG" "invalid session descriptor ($SESS_PARSE_ERRORS parse error(s)): $file"
  fi

  local min_eb=${AN_CFG[session_min_entropy_bits]:-128}
  local max_idle=${AN_CFG[session_max_idle_min]:-30}
  local max_abs=${AN_CFG[session_max_absolute_min]:-480}

  local ebits=${SESS_DESC[session_id_entropy_bits]:-}
  local in_url=${SESS_DESC[session_id_in_url]:-}
  local sec=${SESS_DESC[session_cookie_secure]:-}
  local http=${SESS_DESC[session_cookie_httponly]:-}
  local ss=${SESS_DESC[session_cookie_samesite]:-}
  local host_pfx=${SESS_DESC[session_cookie_host_prefix]:-}
  local rot_login=${SESS_DESC[session_rotate_on_login]:-}
  local rot_priv=${SESS_DESC[session_rotate_on_privilege_change]:-}
  local idle=${SESS_DESC[session_idle_timeout_min]:-}
  local abs=${SESS_DESC[session_absolute_timeout_min]:-}
  local rev_out=${SESS_DESC[session_server_side_revoke_on_logout]:-}
  local rev_pw=${SESS_DESC[session_revoke_on_password_change]:-}

  printf 'Session security audit: %s  (profile: %s)\n' "${file##*/}" "${AN_PROFILE:-default}"
  ui_rule

  # 1. Token entropy & URL leakage
  if [[ -n $ebits ]]; then
    if ((10#$ebits <= 64)); then
      _sa_rule FAIL "[REQUIREMENT] Session ID entropy ${ebits} bits is critically low (<= 64 bits)"
      findings_add CRITICAL HIGH verified "Session identifier entropy is critically weak" \
        "session_id_entropy_bits=$ebits permits practical session prediction." \
        "Generate session identifiers with >= 128 bits from a CSPRNG." \
        "file=${file##*/}; session_id_entropy_bits=$ebits" || true
    elif ((10#$ebits < 10#$min_eb)); then
      _sa_rule FAIL "[REQUIREMENT] Session ID entropy ${ebits} bits < policy minimum ${min_eb} bits"
      findings_add HIGH HIGH verified "Session identifier entropy below policy minimum" \
        "session_id_entropy_bits=$ebits is below session_min_entropy_bits=$min_eb." \
        "Increase session ID entropy to at least $min_eb bits." \
        "file=${file##*/}; session_id_entropy_bits=$ebits; required=$min_eb" || true
    else
      _sa_rule PASS "[REQUIREMENT] Session ID entropy ${ebits} bits (>= $min_eb)"
    fi
  fi

  if [[ $in_url == 1 ]]; then
    _sa_rule FAIL "[REQUIREMENT] Session IDs exposed in URL parameters (session_id_in_url=1)"
    findings_add HIGH HIGH verified "Session identifiers transmitted in URLs" \
      "session_id_in_url=1 exposes tokens via browser history, server logs, and Referer headers." \
      "Store session identifiers exclusively in hardened HTTP cookies." \
      "file=${file##*/}; setting=session_id_in_url=1" || true
  elif [[ $in_url == 0 ]]; then
    _sa_rule PASS "[REQUIREMENT] Session IDs not placed in URLs"
  fi

  # 2. Cookie flags
  if [[ $sec == 0 ]]; then
    _sa_rule FAIL "[REQUIREMENT] Cookie Secure flag disabled (session_cookie_secure=0)"
    findings_add HIGH HIGH verified "Session cookie missing Secure attribute" \
      "session_cookie_secure=0 allows transmission over unencrypted HTTP." \
      "Set Secure on all session cookies and enforce HTTPS." \
      "file=${file##*/}; setting=session_cookie_secure=0" || true
  elif [[ $sec == 1 ]]; then
    _sa_rule PASS "[REQUIREMENT] Cookie Secure flag enabled"
  fi

  if [[ $http == 0 ]]; then
    _sa_rule FAIL "[REQUIREMENT] Cookie HttpOnly flag disabled (session_cookie_httponly=0)"
    findings_add HIGH HIGH verified "Session cookie missing HttpOnly attribute" \
      "session_cookie_httponly=0 exposes the session token to JavaScript/XSS." \
      "Set HttpOnly on all session cookies." \
      "file=${file##*/}; setting=session_cookie_httponly=0" || true
  elif [[ $http == 1 ]]; then
    _sa_rule PASS "[REQUIREMENT] Cookie HttpOnly flag enabled"
  fi

  case ${ss,,} in
    strict | lax) _sa_rule PASS "[REQUIREMENT] SameSite=$ss" ;;
    none)
      _sa_rule REVIEW "[RECOMMENDATION] SameSite=None increases CSRF surface (requires Secure)"
      findings_add MEDIUM HIGH verified "Session cookie uses SameSite=None" \
        "SameSite=None permits cross-site cookie transmission; ensure explicit CSRF tokens." \
        "Prefer SameSite=Lax or Strict unless cross-origin embedding is required." \
        "file=${file##*/}; setting=session_cookie_samesite=None" || true ;;
    unset)
      _sa_rule FAIL "[REQUIREMENT] SameSite attribute unset"
      findings_add MEDIUM HIGH verified "Session cookie missing SameSite attribute" \
        "session_cookie_samesite=unset relies on browser defaults for CSRF mitigation." \
        "Explicitly configure SameSite=Lax or SameSite=Strict." \
        "file=${file##*/}; setting=session_cookie_samesite=unset" || true ;;
  esac

  if [[ $host_pfx == 0 ]]; then
    _sa_rule REVIEW "[RECOMMENDATION] __Host- cookie prefix not enforced"
  elif [[ $host_pfx == 1 ]]; then
    _sa_rule PASS "[RECOMMENDATION] __Host- cookie prefix enabled"
  fi

  # 3. Fixation & lifecycle
  if [[ $rot_login == 0 || $rot_priv == 0 ]]; then
    _sa_rule FAIL "[REQUIREMENT] Session rotation missing (login=$rot_login, priv_change=$rot_priv)"
    findings_add HIGH HIGH verified "Session identifier not rotated on authentication or privilege change" \
      "Missing rotation (login=$rot_login, privilege_change=$rot_priv) enables session fixation." \
      "Regenerate and invalidate the prior session ID on login and privilege escalation." \
      "file=${file##*/}; rotate_login=$rot_login; rotate_priv=$rot_priv" || true
  elif [[ $rot_login == 1 && $rot_priv == 1 ]]; then
    _sa_rule PASS "[REQUIREMENT] Session ID rotated on login and privilege change"
  fi

  if [[ -n $idle ]]; then
    if ((10#$idle == 0 || 10#$idle > 10#$max_idle)); then
      _sa_rule FAIL "[REQUIREMENT] Idle timeout ${idle}m exceeds policy max ${max_idle}m (0 = unlimited)"
      findings_add MEDIUM HIGH verified "Session idle timeout exceeds policy threshold" \
        "session_idle_timeout_min=$idle exceeds session_max_idle_min=$max_idle." \
        "Configure an idle timeout <= $max_idle minutes." \
        "file=${file##*/}; idle_min=$idle; max_idle=$max_idle" || true
    else
      _sa_rule PASS "[REQUIREMENT] Idle timeout ${idle}m (<= ${max_idle}m)"
    fi
  fi

  if [[ -n $abs ]]; then
    if ((10#$abs == 0 || 10#$abs > 10#$max_abs)); then
      _sa_rule FAIL "[REQUIREMENT] Absolute timeout ${abs}m exceeds policy max ${max_abs}m (0 = unlimited)"
      findings_add MEDIUM HIGH verified "Session absolute lifetime exceeds policy threshold" \
        "session_absolute_timeout_min=$abs exceeds session_max_absolute_min=$max_abs." \
        "Enforce a bounded absolute session lifetime <= $max_abs minutes." \
        "file=${file##*/}; abs_min=$abs; max_abs=$max_abs" || true
    else
      _sa_rule PASS "[REQUIREMENT] Absolute timeout ${abs}m (<= ${max_abs}m)"
    fi
  fi

  if [[ $rev_out == 0 || $rev_pw == 0 ]]; then
    _sa_rule FAIL "[REQUIREMENT] Server-side session revocation incomplete (logout=$rev_out, pw_change=$rev_pw)"
    findings_add HIGH HIGH verified "Server-side session invalidation missing on logout or password change" \
      "rev_logout=$rev_out, rev_pw_change=$rev_pw leaves stale sessions valid after logout or credential reset." \
      "Invalidate session state server-side on logout and revoke all other sessions on password change." \
      "file=${file##*/}; rev_logout=$rev_out; rev_pw_change=$rev_pw" || true
  elif [[ $rev_out == 1 && $rev_pw == 1 ]]; then
    _sa_rule PASS "[REQUIREMENT] Server-side revocation enforced on logout and password change"
  fi

  ui_rule
  return 0
}

_sa_cmd_check_cookie() {
  local hdr=""
  ui_read_secret hdr "Set-Cookie header (input hidden): " || an_die "$EX_VALIDATION" "no input"
  sess_parse_cookie_header "$hdr" || an_die "$EX_VALIDATION" "invalid Set-Cookie header format"
  unset hdr

  printf 'Set-Cookie attribute audit  (cookie value is never displayed or logged)\n'
  ui_rule
  printf '  %-22s %s\n' "Cookie name" "$CK_NAME"
  printf '  %-22s %s\n' "Cookie prefix" "$CK_PREFIX"
  printf '  %-22s %s\n' "SameSite" "$CK_SAMESITE"
  printf '  %-22s %s\n' "Secure / HttpOnly" "Secure=$CK_SECURE HttpOnly=$CK_HTTPONLY"
  ui_rule

  if ((CK_SECURE == 0)); then
    _sa_rule FAIL "[REQUIREMENT] Missing Secure flag on cookie $CK_NAME"
    findings_add HIGH HIGH verified "Session cookie header missing Secure flag" \
      "Cookie '$CK_NAME' lacks the Secure attribute." "Add the Secure attribute to '$CK_NAME'." \
      "cookie=$CK_NAME; missing=Secure" || true
  else
    _sa_rule PASS "[REQUIREMENT] Secure flag present"
  fi

  if ((CK_HTTPONLY == 0)); then
    _sa_rule FAIL "[REQUIREMENT] Missing HttpOnly flag on cookie $CK_NAME"
    findings_add HIGH HIGH verified "Session cookie header missing HttpOnly flag" \
      "Cookie '$CK_NAME' lacks the HttpOnly attribute." "Add the HttpOnly attribute to '$CK_NAME'." \
      "cookie=$CK_NAME; missing=HttpOnly" || true
  else
    _sa_rule PASS "[REQUIREMENT] HttpOnly flag present"
  fi

  if [[ $CK_SAMESITE == "None" && $CK_SECURE == 0 ]]; then
    _sa_rule FAIL "[REQUIREMENT] SameSite=None without Secure is rejected by modern browsers and insecure"
    findings_add HIGH HIGH verified "Cookie uses SameSite=None without Secure" \
      "Cookie '$CK_NAME' specifies SameSite=None without Secure." "Set Secure or switch to SameSite=Lax/Strict." \
      "cookie=$CK_NAME; samesite=None; secure=0" || true
  elif [[ $CK_SAMESITE == "unset" ]]; then
    _sa_rule FAIL "[REQUIREMENT] Missing SameSite attribute on cookie $CK_NAME"
    findings_add MEDIUM HIGH verified "Session cookie header missing SameSite attribute" \
      "Cookie '$CK_NAME' does not specify SameSite." "Add SameSite=Lax or SameSite=Strict." \
      "cookie=$CK_NAME; missing=SameSite" || true
  else
    _sa_rule PASS "[REQUIREMENT] SameSite=$CK_SAMESITE"
  fi

  if [[ $CK_PREFIX == "__Host-" ]]; then
    if ((CK_SECURE == 0)) || [[ -n $CK_DOMAIN || $CK_PATH != "/" ]]; then
      _sa_rule FAIL "[REQUIREMENT] __Host- prefix requires Secure, Path=/, and no Domain attribute"
      findings_add MEDIUM HIGH verified "Malformed __Host- cookie prefix attributes" \
        "Cookie '$CK_NAME' uses __Host- without satisfying Secure/Path=/no-Domain." \
        "Set Secure, Path=/, and omit Domain for __Host- cookies." "cookie=$CK_NAME; prefix=__Host-" || true
    else
      _sa_rule PASS "[RECOMMENDATION] __Host- prefix attributes valid"
    fi
  fi
  ui_rule
  return 0
}

mod_session_sec_main() {
  local sub=${1:-}
  shift || true
  AN_MODULE=session_sec
  case $sub in
    analyze) session_run_check "session-audit:analyze" "descriptor:${1:+${1##*/}}" "file=${1:+${1##*/}};profile=${AN_PROFILE:-default}" _sa_cmd_analyze "$@" ;;
    check-cookie) session_run_check "session-audit:check-cookie" "stdin_cookie" "mode=set_cookie_header" _sa_cmd_check_cookie ;;
    "" | help | -h | --help) _sa_usage ;;
    *) an_die "$EX_USAGE" "session-audit: unknown subcommand '$sub'" ;;
  esac
}

mod_session_sec_menu() {
  AN_MODULE=session_sec
  local c f
  while :; do
    ui_banner
    printf '\n  SESSION SECURITY ANALYSIS\n'
    ui_rule
    printf '  [1] Audit session-management descriptor file\n'
    printf '  [2] Audit a Set-Cookie header (hidden input)\n'
    printf '  [b] Back\n\n'
    read -r -p "Select: " c || return 0
    case $c in
      1) read -r -p "Path to session descriptor: " f || return 0; (session_run_check "session-audit:analyze" "descriptor:${f##*/}" "file=${f##*/}" _sa_cmd_analyze "$f") || true; ui_pause ;;
      2) (session_run_check "session-audit:check-cookie" "stdin_cookie" "mode=set_cookie_header" _sa_cmd_check_cookie) || true; ui_pause ;;
      b | B | q | Q) return 0 ;;
      *) printf 'Invalid selection.\n' ;;
    esac
  done
}
