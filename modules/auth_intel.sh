#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034  # globals are shared across sourced files by design
# AUTHFORGE module: Authentication Intelligence (menu 01) -- Milestone 4.
# Implemented: scan, oidc-check.
# Strictly gated by --allow-online + --scope FILE + lab-target rules.

mod_auth_intel_info() { printf '01|Authentication Intelligence|Authorized lab-only auth surface and OIDC discovery checks|ready'; }

_ai_usage() {
  cat <<'USAGE'
Usage: authforge --allow-online --scope FILE [global opts] auth-intel <subcommand> <url>

  scan URL          Inspect auth headers, server banner, and redirect posture (no redirects followed)
  oidc-check URL    Inspect /.well-known/openid-configuration posture on an authorized lab target

All online checks refuse to run without --allow-online and a valid --scope FILE.
USAGE
}

_ai_rule() {
  printf '  %s %s\n' "$(ui_status_badge "$1")" "$2"
}

_ai_cmd_scan() {
  local url=${1:-} insecure=0
  [[ -n $url ]] || an_die "$EX_USAGE" "auth-intel scan requires URL"
  shift || true
  if [[ ${1:-} == "--insecure-lab" ]]; then insecure=1; fi

  local scheme host port path
  authz_parse_url "$url" scheme host port path || {
    log_error "invalid URL: $url"
    return "$EX_VALIDATION"
  }
  local rc=0
  authz_require_online "$host" || rc=$?
  if ((rc != 0)); then return "$rc"; fi

  local hdr body
  hdr=$(tmp_file) body=$(tmp_file)
  rc=0
  authz_safe_http HEAD "$url" "$hdr" "$body" "$insecure" || rc=$?
  if ((rc == EX_AUTHZ || rc == EX_VALIDATION)); then
    rm -f -- "$hdr" "$body"
    return "$rc"
  elif ((rc == EX_DEPENDENCY)); then
    rm -f -- "$hdr" "$body"
    if ! command -v curl >/dev/null 2>&1; then
      _ai_rule 'NOT TESTED' "curl not installed; auth-intel scan skipped"
    else
      _ai_rule 'NOT TESTED' "required HTTP probe dependency (getent/curl) not installed; auth-intel scan skipped"
    fi
    return "$EX_DEPENDENCY"
  fi
  if ((rc != 0)); then
    rm -f -- "$hdr" "$body"
    _AN_ACTIVE_CHECK_DETAIL="http_probe_ok=0"
    _ai_rule 'NOT TESTED' "HTTP request failed or timed out for $host:$port"
    return 0
  fi
  proto_parse_http_headers "$hdr" "$scheme" || true
  auth_intel_parse_server_header "$hdr" || true
  rm -f -- "$hdr" "$body"
  _AN_ACTIVE_CHECK_DETAIL="http_probe_ok=1;scheme=$scheme;status=$PA_HTTP_STATUS"

  printf 'Authentication surface intelligence: %s://%s:%s%s\n' "$scheme" "$host" "$port" "$path"
  ui_rule
  printf '  %-22s %s\n' "HTTP status" "$PA_HTTP_STATUS"
  printf '  %-22s %s\n' "Server header" "${AI_SERVER_BANNER:-not disclosed}"
  printf '  %-22s %s\n' "Auth schemes" "${PA_HTTP_AUTH_SCHEMES:-none}"
  ui_rule

  if [[ $scheme == "http" ]]; then
    _ai_rule FAIL "Unencrypted HTTP transport on authentication endpoint"
    findings_add HIGH HIGH verified "Authentication surface served over unencrypted HTTP" \
      "Endpoint ${host}:${port}${path} uses HTTP rather than HTTPS." \
      "Enforce HTTPS with TLS 1.2+ and HSTS." \
      "target=${host}:${port}; scheme=http" || true
  else
    _ai_rule PASS "HTTPS transport configured"
  fi
  if ((PA_HTTP_BASIC_PLAINTEXT)); then
    findings_add CRITICAL HIGH verified "Cleartext HTTP Basic authentication advertised" \
      "Endpoint ${host}:${port}${path} advertises WWW-Authenticate: Basic over HTTP." \
      "Disable HTTP Basic over cleartext HTTP." \
      "target=${host}:${port}; auth=Basic; scheme=http" || true
  fi
  return 0
}

_ai_cmd_oidc_check() {
  local base_url=${1:-} insecure=0
  [[ -n $base_url ]] || an_die "$EX_USAGE" "auth-intel oidc-check requires URL"
  shift || true
  if [[ ${1:-} == "--insecure-lab" ]]; then insecure=1; fi

  local url="${base_url%/}/.well-known/openid-configuration"
  local scheme host port path
  authz_parse_url "$url" scheme host port path || {
    log_error "invalid URL: $base_url"
    return "$EX_VALIDATION"
  }
  local rc=0
  authz_require_online "$host" || rc=$?
  if ((rc != 0)); then return "$rc"; fi

  local hdr body
  hdr=$(tmp_file) body=$(tmp_file)
  rc=0
  authz_safe_http GET "$url" "$hdr" "$body" "$insecure" || rc=$?
  if ((rc == EX_AUTHZ || rc == EX_VALIDATION)); then
    rm -f -- "$hdr" "$body"
    return "$rc"
  elif ((rc == EX_DEPENDENCY)); then
    rm -f -- "$hdr" "$body"
    if ! command -v curl >/dev/null 2>&1; then
      _ai_rule 'NOT TESTED' "curl not installed; OIDC check skipped"
    else
      _ai_rule 'NOT TESTED' "required HTTP probe dependency (getent/curl) not installed; OIDC check skipped"
    fi
    return "$EX_DEPENDENCY"
  fi
  if ((rc != 0)); then
    rm -f -- "$hdr" "$body"
    _AN_ACTIVE_CHECK_DETAIL="http_probe_ok=0;oidc_found=0"
    _ai_rule 'NOT TESTED' "OIDC discovery request failed for $host:$port"
    return 0
  fi
  auth_intel_parse_oidc "$body" || true
  rm -f -- "$hdr" "$body"
  _AN_ACTIVE_CHECK_DETAIL="http_probe_ok=1;oidc_found=$AI_OIDC_FOUND;issuer_https=$AI_OIDC_ISSUER_HTTPS;pkce_s256=$AI_OIDC_PKCE_S256"

  printf 'OIDC discovery posture: %s\n' "$url"
  ui_rule
  if ((!AI_OIDC_FOUND)); then
    _ai_rule 'NOT TESTED' "No OpenID Connect discovery metadata found at $path"
    ui_rule
    return 0
  fi
  if ((!AI_OIDC_ISSUER_HTTPS)); then
    _ai_rule FAIL "OIDC issuer URL is not HTTPS"
    findings_add HIGH HIGH verified "OIDC discovery issuer does not use HTTPS" \
      "OIDC metadata at ${host}:${port}${path} advertises a non-HTTPS issuer." \
      "Configure HTTPS for the OIDC issuer and all token/authorization endpoints." \
      "target=${host}:${port}; oidc_issuer_https=0" || true
  else
    _ai_rule PASS "OIDC issuer uses HTTPS"
  fi
  if ((!AI_OIDC_PKCE_S256)); then
    _ai_rule FAIL "OIDC discovery does not advertise PKCE S256"
    findings_add MEDIUM HIGH verified "OIDC metadata missing PKCE S256 support" \
      "code_challenge_methods_supported at ${host}:${port} does not include S256." \
      "Enable and require PKCE with S256 for public and confidential OAuth2 clients." \
      "target=${host}:${port}; pkce_s256=0" || true
  else
    _ai_rule PASS "OIDC PKCE S256 advertised"
  fi
  if ((AI_OIDC_IMPLICIT_FLOW)); then
    _ai_rule REVIEW "Legacy OAuth2 implicit flow (token) advertised in response_types_supported"
    findings_add MEDIUM HIGH verified "OIDC discovery advertises legacy implicit flow" \
      "response_types_supported at ${host}:${port} includes implicit token grant." \
      "Disable implicit flow in favor of Authorization Code + PKCE." \
      "target=${host}:${port}; implicit_flow=1" || true
  else
    _ai_rule PASS "Implicit grant not advertised"
  fi
  ui_rule
  return 0
}

mod_auth_intel_main() {
  local sub=${1:-}
  shift || true
  AN_MODULE=auth_intel
  case $sub in
    scan) session_run_check "auth-intel:scan" "endpoint:${1:-}" "target=${1:-}" _ai_cmd_scan "$@" ;;
    oidc-check) session_run_check "auth-intel:oidc-check" "endpoint:${1:-}" "target=${1:-}" _ai_cmd_oidc_check "$@" ;;
    "" | help | -h | --help) _ai_usage ;;
    *) an_die "$EX_USAGE" "auth-intel: unknown subcommand '$sub'" ;;
  esac
}

mod_auth_intel_menu() {
  AN_MODULE=auth_intel
  local c target rc
  while :; do
    ui_banner
    printf '\n  AUTHENTICATION INTELLIGENCE (authorized lab only)\n'
    ui_rule
    printf '  [1] Scan authentication surface headers (URL)\n'
    printf '  [2] Inspect OIDC discovery metadata (URL)\n'
    printf '  [b] Back\n\n'
    read -r -p "Select: " c || return 0
    case $c in
      1)
        read -r -p "Target URL: " target || return 0
        rc=0
        session_run_check "auth-intel:scan" "endpoint:$target" "target=$target" _ai_cmd_scan "$target" || rc=$?
        if ((rc == EX_AUTHZ || rc == EX_VALIDATION || rc == EX_DEPENDENCY)); then return "$rc"; fi
        ui_pause ;;
      2)
        read -r -p "Base URL: " target || return 0
        rc=0
        session_run_check "auth-intel:oidc-check" "endpoint:$target" "target=$target" _ai_cmd_oidc_check "$target" || rc=$?
        if ((rc == EX_AUTHZ || rc == EX_VALIDATION || rc == EX_DEPENDENCY)); then return "$rc"; fi
        ui_pause ;;
      b | B | q | Q) return 0 ;;
      *) printf 'Invalid selection.\n' ;;
    esac
  done
}
