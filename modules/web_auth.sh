#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034  # globals are shared across sourced files by design
# AUTHFORGE module: Web Authentication Assessment (menu 09) -- Milestone 4.
# Implemented: headers, cookies, rate-limit-check (bounded, authorized lab only).

mod_web_auth_info() { printf '09|Web Authentication Assessment|Authorized lab-only security headers, live cookie flags and rate-limit checks|ready'; }

_wa_usage() {
  cat <<'USAGE'
Usage: authforge --allow-online --scope FILE [global opts] web-auth <subcommand> <url>

  headers URL           Audit auth-page security headers (CSP, X-Frame-Options, Cache-Control, Referrer-Policy)
  cookies URL           Audit Set-Cookie security flags returned by URL (values are never logged or printed)
  rate-limit-check URL  Send up to 3 bounded safe GET/HEAD probes to check rate-limit headers (429 / Retry-After)

All online checks refuse to run without --allow-online and a valid --scope FILE.
USAGE
}

_wa_rule() {
  printf '  %s %s\n' "$(ui_status_badge "$1")" "$2"
}

_wa_fetch() { # <method> <url> <out_hdr> <out_body> <insecure>
  local method=$1 url=$2 hdr=$3 body=$4 insecure=${5:-0}
  local scheme host port path
  authz_parse_url "$url" scheme host port path || {
    log_error "invalid URL: $url"
    return "$EX_VALIDATION"
  }
  local rc=0
  authz_require_online "$host" || rc=$?
  if ((rc != 0)); then return "$rc"; fi
  authz_safe_http "$method" "$url" "$hdr" "$body" "$insecure"
}

_wa_cmd_headers() {
  local url=${1:-} insecure=0
  [[ -n $url ]] || an_die "$EX_USAGE" "web-auth headers requires URL"
  shift || true
  if [[ ${1:-} == "--insecure-lab" ]]; then insecure=1; fi

  local hdr body
  hdr=$(tmp_file) body=$(tmp_file)
  local rc=0
  _wa_fetch GET "$url" "$hdr" "$body" "$insecure" || rc=$?
  if ((rc == EX_AUTHZ || rc == EX_VALIDATION)); then
    rm -f -- "$hdr" "$body"
    return "$rc"
  elif ((rc == EX_DEPENDENCY)); then
    rm -f -- "$hdr" "$body"
    if ! command -v curl >/dev/null 2>&1; then
      _wa_rule 'NOT TESTED' "curl not installed; web-auth headers skipped"
    else
      _wa_rule 'NOT TESTED' "required HTTP probe dependency (getent/curl) not installed; web-auth headers skipped"
    fi
    return "$EX_DEPENDENCY"
  elif ((rc != 0)) || [[ ! -s $hdr ]]; then
    rm -f -- "$hdr" "$body"
    _AN_ACTIVE_CHECK_DETAIL="http_probe_ok=0"
    _wa_rule 'NOT TESTED' "HTTP request failed or returned empty headers"
    return 0
  fi
  web_auth_parse_headers "$hdr" || true
  rm -f -- "$hdr" "$body"
  _AN_ACTIVE_CHECK_DETAIL="http_probe_ok=1;csp=$WA_HAS_CSP;xfo=$WA_HAS_XFO;nostore=$WA_HAS_CACHE_NOSTORE"

  printf 'Web authentication headers audit: %s\n' "$url"
  ui_rule
  if ((WA_HAS_CSP)); then _wa_rule PASS "Content-Security-Policy present"; else
    _wa_rule FAIL "Missing Content-Security-Policy header"
    findings_add MEDIUM HIGH verified "Authentication page missing Content-Security-Policy" \
      "Response from $url lacked Content-Security-Policy, increasing XSS credential/token exposure." \
      "Configure a strict Content-Security-Policy with frame-ancestors 'none'." \
      "url=$url; missing=Content-Security-Policy" || true
  fi
  if ((WA_HAS_XFO)); then _wa_rule PASS "X-Frame-Options present"; else
    _wa_rule FAIL "Missing X-Frame-Options header"
    findings_add LOW HIGH verified "Authentication page missing X-Frame-Options header" \
      "Response from $url lacked X-Frame-Options (clickjacking risk on login UI)." \
      "Set X-Frame-Options: DENY and CSP frame-ancestors 'none'." \
      "url=$url; missing=X-Frame-Options" || true
  fi
  if ((WA_HAS_CACHE_NOSTORE)); then _wa_rule PASS "Cache-Control: no-store present"; else
    _wa_rule FAIL "Missing Cache-Control: no-store on authentication endpoint"
    findings_add MEDIUM HIGH verified "Authentication response may be cached" \
      "Response from $url lacked Cache-Control: no-store." \
      "Set Cache-Control: no-store, max-age=0 on authentication responses." \
      "url=$url; missing=Cache-Control:no-store" || true
  fi
  if ((WA_HAS_REFERRER)); then _wa_rule PASS "Referrer-Policy present"; else
    _wa_rule REVIEW "Referrer-Policy header not set"
  fi
  ui_rule
  return 0
}

_wa_cmd_cookies() {
  local url=${1:-} insecure=0
  [[ -n $url ]] || an_die "$EX_USAGE" "web-auth cookies requires URL"
  shift || true
  if [[ ${1:-} == "--insecure-lab" ]]; then insecure=1; fi

  local hdr body
  hdr=$(tmp_file) body=$(tmp_file)
  local rc=0
  _wa_fetch GET "$url" "$hdr" "$body" "$insecure" || rc=$?
  if ((rc == EX_AUTHZ || rc == EX_VALIDATION)); then
    rm -f -- "$hdr" "$body"
    return "$rc"
  elif ((rc == EX_DEPENDENCY)); then
    rm -f -- "$hdr" "$body"
    if ! command -v curl >/dev/null 2>&1; then
      _wa_rule 'NOT TESTED' "curl not installed; web-auth cookies skipped"
    else
      _wa_rule 'NOT TESTED' "required HTTP probe dependency (getent/curl) not installed; web-auth cookies skipped"
    fi
    return "$EX_DEPENDENCY"
  elif ((rc != 0)) || [[ ! -s $hdr ]]; then
    rm -f -- "$hdr" "$body"
    _AN_ACTIVE_CHECK_DETAIL="http_probe_ok=0;cookies_seen=0"
    _wa_rule 'NOT TESTED' "HTTP request failed or returned empty headers"
    return 0
  fi
  web_auth_parse_headers "$hdr" || true
  rm -f -- "$hdr" "$body"
  _AN_ACTIVE_CHECK_DETAIL="http_probe_ok=1;cookies_seen=$WA_COOKIE_COUNT"

  printf 'Live Set-Cookie flag audit: %s  (cookie values are never displayed or logged)\n' "$url"
  ui_rule
  if ((WA_COOKIE_COUNT == 0)); then
    printf '  No Set-Cookie headers returned.\n'
    ui_rule
    return 0
  fi

  local cline
  for cline in "${WA_COOKIE_LINES[@]}"; do
    sess_parse_cookie_header "$cline" || continue
    printf '  Cookie %-18s Secure=%s HttpOnly=%s SameSite=%s Prefix=%s\n' \
      "$CK_NAME" "$CK_SECURE" "$CK_HTTPONLY" "$CK_SAMESITE" "$CK_PREFIX"
    if ((CK_SECURE == 0)); then
      findings_add HIGH HIGH verified "Live Set-Cookie missing Secure flag ($CK_NAME)" \
        "Endpoint $url issued cookie '$CK_NAME' without Secure." \
        "Set Secure on '$CK_NAME'." "url=$url; cookie=$CK_NAME; missing=Secure" || true
    fi
    if ((CK_HTTPONLY == 0)); then
      findings_add HIGH HIGH verified "Live Set-Cookie missing HttpOnly flag ($CK_NAME)" \
        "Endpoint $url issued cookie '$CK_NAME' without HttpOnly." \
        "Set HttpOnly on '$CK_NAME'." "url=$url; cookie=$CK_NAME; missing=HttpOnly" || true
    fi
    if [[ $CK_SAMESITE == "unset" ]]; then
      findings_add MEDIUM HIGH verified "Live Set-Cookie missing SameSite attribute ($CK_NAME)" \
        "Endpoint $url issued cookie '$CK_NAME' without SameSite." \
        "Set SameSite=Lax or Strict on '$CK_NAME'." "url=$url; cookie=$CK_NAME; missing=SameSite" || true
    fi
  done
  ui_rule
  return 0
}

_wa_cmd_rate_limit_check() {
  local url=${1:-} insecure=0
  [[ -n $url ]] || an_die "$EX_USAGE" "web-auth rate-limit-check requires URL"
  shift || true
  if [[ ${1:-} == "--insecure-lab" ]]; then insecure=1; fi

  local hdr body i saw_rl=0 ok_probes=0 rc=0
  for ((i = 1; i <= 3; i++)); do
    hdr=$(tmp_file) body=$(tmp_file)
    rc=0
    _wa_fetch HEAD "$url" "$hdr" "$body" "$insecure" || rc=$?
    if ((rc == EX_AUTHZ || rc == EX_VALIDATION)); then
      rm -f -- "$hdr" "$body"
      return "$rc"
    elif ((rc == EX_DEPENDENCY)); then
      rm -f -- "$hdr" "$body"
      if ! command -v curl >/dev/null 2>&1; then
        _wa_rule 'NOT TESTED' "curl not installed; rate-limit check skipped"
      else
        _wa_rule 'NOT TESTED' "required HTTP probe dependency (getent/curl) not installed; rate-limit check skipped"
      fi
      return "$EX_DEPENDENCY"
    elif ((rc == 0)); then
      ok_probes=$((ok_probes + 1))
      web_auth_parse_headers "$hdr" || true
      proto_parse_http_headers "$hdr" "http" || true
      if ((WA_HAS_RATELIMIT_HDR)) || [[ $PA_HTTP_STATUS == "429" ]]; then
        saw_rl=1
      fi
    fi
    rm -f -- "$hdr" "$body"
  done

  if ((ok_probes == 0)); then
    _AN_ACTIVE_CHECK_DETAIL="http_probe_ok=0;ratelimit_probes=0"
    _wa_rule 'NOT TESTED' "HTTP request failed or timed out for $url"
    return 0
  fi
  _AN_ACTIVE_CHECK_DETAIL="http_probe_ok=1;ratelimit_probes=$ok_probes;ratelimit_seen=$saw_rl"

  printf 'Bounded rate-limit header check (3 probes): %s\n' "$url"
  ui_rule
  if ((saw_rl)); then
    _wa_rule PASS "Rate-limit headers or HTTP 429 observed"
  else
    _wa_rule REVIEW "No rate-limit headers (X-RateLimit-*/Retry-After/429) observed in 3 probes"
    findings_add LOW MEDIUM heuristic "No rate-limiting headers observed on authentication endpoint" \
      "3 bounded probes to $url did not return X-RateLimit-*, Retry-After, or HTTP 429." \
      "Verify server-side rate limiting and account lockout controls are enforced." \
      "url=$url; probes=3; ratelimit_headers=0" || true
  fi
  ui_rule
  return 0
}

mod_web_auth_main() {
  local sub=${1:-}
  shift || true
  AN_MODULE=web_auth
  case $sub in
    headers) session_run_check "web-auth:headers" "endpoint:${1:-}" "target=${1:-}" _wa_cmd_headers "$@" ;;
    cookies) session_run_check "web-auth:cookies" "endpoint:${1:-}" "target=${1:-}" _wa_cmd_cookies "$@" ;;
    rate-limit-check) session_run_check "web-auth:rate-limit-check" "endpoint:${1:-}" "target=${1:-}" _wa_cmd_rate_limit_check "$@" ;;
    "" | help | -h | --help) _wa_usage ;;
    *) an_die "$EX_USAGE" "web-auth: unknown subcommand '$sub'" ;;
  esac
}

mod_web_auth_menu() {
  AN_MODULE=web_auth
  local c target rc
  while :; do
    ui_banner
    printf '\n  WEB AUTHENTICATION ASSESSMENT (authorized lab only)\n'
    ui_rule
    printf '  [1] Audit security headers (URL)\n'
    printf '  [2] Audit live Set-Cookie flags (URL)\n'
    printf '  [3] Bounded rate-limit header check (URL)\n'
    printf '  [b] Back\n\n'
    read -r -p "Select: " c || return 0
    case $c in
      1)
        read -r -p "Target URL: " target || return 0
        rc=0
        session_run_check "web-auth:headers" "endpoint:$target" "target=$target" _wa_cmd_headers "$target" || rc=$?
        if ((rc == EX_AUTHZ || rc == EX_VALIDATION || rc == EX_DEPENDENCY)); then return "$rc"; fi
        ui_pause ;;
      2)
        read -r -p "Target URL: " target || return 0
        rc=0
        session_run_check "web-auth:cookies" "endpoint:$target" "target=$target" _wa_cmd_cookies "$target" || rc=$?
        if ((rc == EX_AUTHZ || rc == EX_VALIDATION || rc == EX_DEPENDENCY)); then return "$rc"; fi
        ui_pause ;;
      3)
        read -r -p "Target URL: " target || return 0
        rc=0
        session_run_check "web-auth:rate-limit-check" "endpoint:$target" "target=$target" _wa_cmd_rate_limit_check "$target" || rc=$?
        if ((rc == EX_AUTHZ || rc == EX_VALIDATION || rc == EX_DEPENDENCY)); then return "$rc"; fi
        ui_pause ;;
      b | B | q | Q) return 0 ;;
      *) printf 'Invalid selection.\n' ;;
    esac
  done
}
