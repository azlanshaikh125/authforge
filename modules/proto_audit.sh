#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034  # globals are shared across sourced files by design
# AUTHFORGE module: Authentication Protocol Audit (menu 06) -- Milestone 4.
# Implemented: tls, http-auth.
# Online checks are strictly gated by --allow-online + --scope FILE + lab target rules.

mod_proto_audit_info() { printf '06|Authentication Protocol Audit|Authorized lab-only TLS and HTTP authentication posture checks|ready'; }

_pa_usage() {
  cat <<'USAGE'
Usage: authforge --allow-online --scope FILE [global opts] proto-audit <subcommand> <target>

  tls HOST[:PORT]       Inspect TLS protocol version, cipher suite, and certificate flags
  http-auth URL         Inspect HTTP auth schemes (WWW-Authenticate), HSTS, and redirect safety

All online checks refuse to run without --allow-online and a valid --scope FILE.
By default (allow_nonlocal_targets=0), only local/lab IPv4 and hostname targets are permitted.
Ambiguous numeric IPv4 representations and IPv6 literals are unsupported and rejected.
USAGE
}

_pa_rule() {
  printf '  %s %s\n' "$(ui_status_badge "$1")" "$2"
}

_pa_cmd_tls() {
  local spec=${1:-}
  [[ -n $spec ]] || an_die "$EX_USAGE" "proto-audit tls requires HOST[:PORT]"
  if [[ $spec == *\[* || $spec == *\]* ]]; then
    log_error "IPv6 literals are unsupported: $spec"
    return "$EX_VALIDATION"
  fi
  local host=$spec port=443
  if [[ $spec == *:* ]]; then
    host=${spec%:*}
    port=${spec##*:}
  fi
  validate_uint "$port" 1 65535 || {
    log_error "invalid port: $port"
    return "$EX_VALIDATION"
  }

  local rc=0
  authz_require_online "$host" || rc=$?
  if ((rc != 0)); then return "$rc"; fi

  local out_file
  out_file=$(tmp_file)
  rc=0
  proto_probe_tls "$host" "$port" "$out_file" || rc=$?
  if ((rc == EX_AUTHZ || rc == EX_VALIDATION)); then
    rm -f -- "$out_file"
    return "$rc"
  elif ((rc == EX_DEPENDENCY)); then
    rm -f -- "$out_file"
    if ! command -v openssl >/dev/null 2>&1; then
      _pa_rule 'NOT TESTED' "openssl not installed; TLS check skipped"
    elif ! command -v timeout >/dev/null 2>&1; then
      _pa_rule 'NOT TESTED' "timeout not installed; TLS check skipped"
    else
      _pa_rule 'NOT TESTED' "required TLS probe dependency (getent/openssl/timeout) not installed; TLS check skipped"
    fi
    return "$EX_DEPENDENCY"
  fi
  if ((rc != 0)) || ! proto_parse_tls_output "$out_file"; then
    rm -f -- "$out_file"
    _AN_ACTIVE_CHECK_DETAIL="tls_handshake_ok=0;reason=${PA_TLS_PROBE_REASON:-unknown}"
    case ${PA_TLS_PROBE_REASON:-unknown} in
      timeout)
        _pa_rule 'NOT TESTED' "TLS handshake timed out for ${host}:${port}" ;;
      missing_negotiation)
        _pa_rule 'NOT TESTED' "incomplete TLS negotiation (missing protocol or cipher) with ${host}:${port}" ;;
      *)
        _pa_rule 'NOT TESTED' "unable to establish TLS handshake with ${host}:${port}" ;;
    esac
    return 0
  fi
  rm -f -- "$out_file"
  _AN_ACTIVE_CHECK_DETAIL="tls_handshake_ok=1;protocol=$PA_TLS_PROTOCOL;cipher=$PA_TLS_CIPHER;self_signed=$PA_TLS_SELF_SIGNED"

  printf 'TLS protocol audit: %s:%s\n' "$host" "$port"
  ui_rule
  printf '  %-22s %s\n' "Negotiated protocol" "$PA_TLS_PROTOCOL"
  printf '  %-22s %s\n' "Negotiated cipher" "$PA_TLS_CIPHER"
  printf '  %-22s %s\n' "Self-signed" "$( ((PA_TLS_SELF_SIGNED)) && printf 'yes' || printf 'no' )"
  ui_rule

  if ((PA_TLS_DEPRECATED)); then
    _pa_rule FAIL "Deprecated TLS/SSL protocol negotiated ($PA_TLS_PROTOCOL)"
    findings_add HIGH HIGH verified "Deprecated TLS protocol negotiated ($PA_TLS_PROTOCOL)" \
      "Target ${host}:${port} negotiated $PA_TLS_PROTOCOL, which has known cryptographic weaknesses." \
      "Disable SSLv2/SSLv3/TLS 1.0/TLS 1.1 and enforce TLS 1.2 or TLS 1.3." \
      "target=${host}:${port}; protocol=$PA_TLS_PROTOCOL" || true
  else
    _pa_rule PASS "TLS protocol acceptable ($PA_TLS_PROTOCOL)"
  fi

  if ((PA_TLS_WEAK_CIPHER)); then
    _pa_rule FAIL "Weak TLS cipher negotiated ($PA_TLS_CIPHER)"
    findings_add HIGH HIGH verified "Weak TLS cipher suite negotiated ($PA_TLS_CIPHER)" \
      "Target ${host}:${port} selected weak cipher $PA_TLS_CIPHER." \
      "Restrict server cipher suites to AEAD ciphers (AES-GCM / ChaCha20-Poly1305) with PFS." \
      "target=${host}:${port}; cipher=$PA_TLS_CIPHER" || true
  else
    _pa_rule PASS "Cipher suite acceptable ($PA_TLS_CIPHER)"
  fi

  if ((PA_TLS_SELF_SIGNED)); then
    _pa_rule REVIEW "Self-signed certificate detected (expected in isolated lab; verify trust chain in prod)"
    findings_add LOW HIGH verified "Self-signed TLS certificate observed" \
      "Target ${host}:${port} presented a self-signed certificate." \
      "Use a trusted CA-signed certificate outside isolated test labs." \
      "target=${host}:${port}; self_signed=1" || true
  fi
  ui_rule
  return 0
}

_pa_cmd_http_auth() {
  local url=${1:-} insecure=0
  [[ -n $url ]] || an_die "$EX_USAGE" "proto-audit http-auth requires URL"
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
  hdr=$(tmp_file)
  body=$(tmp_file)
  rc=0
  authz_safe_http HEAD "$url" "$hdr" "$body" "$insecure" || rc=$?
  if ((rc == EX_AUTHZ || rc == EX_VALIDATION)); then
    rm -f -- "$hdr" "$body"
    return "$rc"
  elif ((rc == EX_DEPENDENCY)); then
    rm -f -- "$hdr" "$body"
    if ! command -v curl >/dev/null 2>&1; then
      _pa_rule 'NOT TESTED' "curl not installed; HTTP auth check skipped"
    else
      _pa_rule 'NOT TESTED' "required HTTP probe dependency (getent/curl) not installed; HTTP auth check skipped"
    fi
    return "$EX_DEPENDENCY"
  fi
  if ((rc != 0)) || ! proto_parse_http_headers "$hdr" "$scheme"; then
    rm -f -- "$hdr" "$body"
    _AN_ACTIVE_CHECK_DETAIL="http_probe_ok=0"
    _pa_rule 'NOT TESTED' "HTTP request failed or timed out for $host:$port"
    return 0
  fi
  rm -f -- "$hdr" "$body"
  _AN_ACTIVE_CHECK_DETAIL="http_probe_ok=1;scheme=$scheme;status=$PA_HTTP_STATUS;hsts=$PA_HTTP_HSTS"

  printf 'HTTP authentication protocol audit: %s://%s:%s%s\n' "$scheme" "$host" "$port" "$path"
  ui_rule
  printf '  %-22s %s\n' "HTTP status" "$PA_HTTP_STATUS"
  printf '  %-22s %s\n' "Auth schemes" "${PA_HTTP_AUTH_SCHEMES:-none}"
  printf '  %-22s %s\n' "HSTS present" "$( ((PA_HTTP_HSTS)) && printf 'yes' || printf 'no' )"
  if [[ -n $PA_HTTP_REDIRECT_TARGET ]]; then
    printf '  %-22s %s (automatic redirect disabled)\n' "Redirect Location" "$PA_HTTP_REDIRECT_TARGET"
  fi
  ui_rule

  if ((PA_HTTP_BASIC_PLAINTEXT)); then
    _pa_rule FAIL "HTTP Basic authentication advertised over cleartext HTTP"
    findings_add CRITICAL HIGH verified "Cleartext HTTP Basic authentication enabled" \
      "Target ${host}:${port} advertises WWW-Authenticate: Basic over unencrypted HTTP." \
      "Enforce HTTPS with HSTS before accepting Basic or credentialed authentication." \
      "target=${host}:${port}; scheme=$scheme; auth=Basic" || true
  else
    _pa_rule PASS "No cleartext HTTP Basic auth advertised"
  fi

  if [[ $scheme == "https" && $PA_HTTP_HSTS == 0 ]]; then
    _pa_rule FAIL "HTTPS endpoint missing Strict-Transport-Security (HSTS) header"
    findings_add MEDIUM HIGH verified "Missing HSTS header on HTTPS authentication endpoint" \
      "HTTPS endpoint ${host}:${port} did not return a Strict-Transport-Security header." \
      "Configure Strict-Transport-Security: max-age=31536000; includeSubDomains." \
      "target=${host}:${port}; missing=HSTS" || true
  elif [[ $scheme == "https" ]]; then
    _pa_rule PASS "HSTS header present"
  fi

  if [[ -n $PA_HTTP_REDIRECT_TARGET ]]; then
    local rs rh rp rpath
    if authz_parse_url "$PA_HTTP_REDIRECT_TARGET" rs rh rp rpath; then
      if ! authz_require_online "$rh" 1 >/dev/null 2>&1; then
        _pa_rule REVIEW "Redirect target '$rh' is outside authorized scope (not followed)"
      fi
    fi
  fi
  ui_rule
  return 0
}

mod_proto_audit_main() {
  local sub=${1:-}
  shift || true
  AN_MODULE=proto_audit
  case $sub in
    tls) session_run_check "proto-audit:tls" "endpoint:${1:-}" "target=${1:-}" _pa_cmd_tls "$@" ;;
    http-auth) session_run_check "proto-audit:http-auth" "endpoint:${1:-}" "target=${1:-}" _pa_cmd_http_auth "$@" ;;
    "" | help | -h | --help) _pa_usage ;;
    *) an_die "$EX_USAGE" "proto-audit: unknown subcommand '$sub'" ;;
  esac
}

mod_proto_audit_menu() {
  AN_MODULE=proto_audit
  local c target rc
  while :; do
    ui_banner
    printf '\n  AUTHENTICATION PROTOCOL AUDIT (authorized lab only)\n'
    ui_rule
    printf '  [1] Inspect TLS protocol & cipher (HOST[:PORT])\n'
    printf '  [2] Inspect HTTP authentication headers (URL)\n'
    printf '  [b] Back\n\n'
    read -r -p "Select: " c || return 0
    case $c in
      1)
        read -r -p "Target HOST[:PORT]: " target || return 0
        rc=0
        session_run_check "proto-audit:tls" "endpoint:$target" "target=$target" _pa_cmd_tls "$target" || rc=$?
        if ((rc == EX_AUTHZ || rc == EX_VALIDATION || rc == EX_DEPENDENCY)); then return "$rc"; fi
        ui_pause ;;
      2)
        read -r -p "Target URL: " target || return 0
        rc=0
        session_run_check "proto-audit:http-auth" "endpoint:$target" "target=$target" _pa_cmd_http_auth "$target" || rc=$?
        if ((rc == EX_AUTHZ || rc == EX_VALIDATION || rc == EX_DEPENDENCY)); then return "$rc"; fi
        ui_pause ;;
      b | B | q | Q) return 0 ;;
      *) printf 'Invalid selection.\n' ;;
    esac
  done
}
