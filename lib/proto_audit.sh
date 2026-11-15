#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034  # globals are shared across sourced files by design
# AUTHFORGE lib: Authorized Lab-Only Authentication Protocol Audit helpers.
#
# SECURITY: Every network operation passes authz_require_online + authz_resolve_target + authz_consume_request.
# Missing tools (openssl, timeout, curl) report NOT TESTED rather than silent pass.
[[ -n "${_AN_PROTO_AUDIT:-}" ]] && return 0
_AN_PROTO_AUDIT=1

PA_TLS_PROTOCOL="unknown"
PA_TLS_CIPHER="unknown"
PA_TLS_CERT_DAYS="n/a"
PA_TLS_SELF_SIGNED=0
PA_TLS_DEPRECATED=0
PA_TLS_WEAK_CIPHER=0
PA_TLS_PROBE_REASON="unknown"

PA_HTTP_STATUS="0"
PA_HTTP_AUTH_SCHEMES=""
PA_HTTP_HSTS=0
PA_HTTP_BASIC_PLAINTEXT=0
PA_HTTP_REDIRECT_TARGET=""

_pa_reset_tls() {
  PA_TLS_PROTOCOL="unknown"
  PA_TLS_CIPHER="unknown"
  PA_TLS_CERT_DAYS="n/a"
  PA_TLS_SELF_SIGNED=0
  PA_TLS_DEPRECATED=0
  PA_TLS_WEAK_CIPHER=0
}

_pa_reset_http() {
  PA_HTTP_STATUS="0"
  PA_HTTP_AUTH_SCHEMES=""
  PA_HTTP_HSTS=0
  PA_HTTP_BASIC_PLAINTEXT=0
  PA_HTTP_REDIRECT_TARGET=""
}

# Pure parser for `openssl s_client` text output.
# Requires BOTH a valid negotiated SSL/TLS protocol and a valid non-null cipher (M4-AUD-08).
# Self-signed certificates do not fail parsing when valid protocol and cipher are present.
proto_parse_tls_output() { # <openssl_output_file>
  _pa_reset_tls
  local f=$1
  [[ -s $f ]] || return 1

  local line proto_cand cipher_cand
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%$'\r'}
    case $line in
      *"Protocol  :"* | *"Protocol :"* | *"Protocol:"*)
        proto_cand=$(str_trim "${line#*:}")
        [[ -n $proto_cand ]] && PA_TLS_PROTOCOL=$proto_cand ;;
      *"Cipher    :"* | *"Cipher :"* | *"Cipher:"*)
        cipher_cand=$(str_trim "${line#*:}")
        [[ -n $cipher_cand ]] && PA_TLS_CIPHER=$cipher_cand ;;
      *"New, "* | *"Reused, "*)
        if [[ $line =~ (SSLv[23]|TLSv1(\.[0-3])?),[[:space:]]*Cipher[[:space:]]+is[[:space:]]+([^[:space:],]+) ]]; then
          [[ $PA_TLS_PROTOCOL == "unknown" ]] && PA_TLS_PROTOCOL=${BASH_REMATCH[1]}
          [[ $PA_TLS_CIPHER == "unknown" ]] && PA_TLS_CIPHER=${BASH_REMATCH[3]}
        fi ;;
      *"self-signed certificate"* | *"self signed certificate"*)
        PA_TLS_SELF_SIGNED=1 ;;
    esac
  done <"$f"

  case $PA_TLS_PROTOCOL in
    SSLv2 | SSLv3 | TLSv1 | TLSv1.0 | TLSv1.1)
      PA_TLS_DEPRECATED=1 ;;
    TLSv1.2 | TLSv1.3)
      PA_TLS_DEPRECATED=0 ;;
    *)
      return 1 ;;
  esac

  if [[ -z $PA_TLS_CIPHER ]]; then return 1; fi
  case ${PA_TLS_CIPHER^^} in
    UNKNOWN | "(NONE)" | NONE | 0000)
      return 1 ;;
  esac
  if [[ ! $PA_TLS_CIPHER =~ ^[A-Za-z0-9_.-]+$ ]]; then
    return 1
  fi

  case ${PA_TLS_CIPHER^^} in
    *RC4* | *DES* | *NULL* | *EXPORT* | *MD5* | *ADH* | *AECDH*) PA_TLS_WEAK_CIPHER=1 ;;
  esac
  return 0
}

# Pure parser for HTTP response headers (with scheme context http|https).
# Resets state whenever a new HTTP status block begins (M4-AUD-04).
proto_parse_http_headers() { # <hdr_file> <scheme>
  _pa_reset_http
  local f=$1 scheme=${2:-http}
  [[ -s $f ]] || return 1

  local line low
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%$'\r'}
    if [[ $line =~ ^HTTP/[0-9.]+\ ([0-9]{3}) ]]; then
      _pa_reset_http
      PA_HTTP_STATUS=${BASH_REMATCH[1]}
      continue
    fi
    low=${line,,}
    case $low in
      strict-transport-security:*)
        PA_HTTP_HSTS=1 ;;
      www-authenticate:*)
        local val
        val=$(str_trim "${line#*:}")
        local sname=${val%% *}
        if [[ -n $sname ]]; then
          if [[ -z $PA_HTTP_AUTH_SCHEMES ]]; then PA_HTTP_AUTH_SCHEMES=$sname
          elif [[ ",$PA_HTTP_AUTH_SCHEMES," != *",$sname,"* ]]; then PA_HTTP_AUTH_SCHEMES+=",$sname"
          fi
          if [[ ${sname,,} == "basic" && ${scheme,,} == "http" ]]; then
            PA_HTTP_BASIC_PLAINTEXT=1
          fi
        fi ;;
      location:*)
        PA_HTTP_REDIRECT_TARGET=$(str_trim "${line#*:}") ;;
    esac
  done <"$f"
  return 0
}

# Execute authorized TLS probe using openssl s_client with pinned IP and SNI (M4-AUD-01, M4-AUD-07, M4-AUD-08).
# Captures actual timeout/openssl exit code, distinguishes timeout (124), connection failures,
# empty output, and missing negotiation details, and requires valid negotiated protocol + cipher.
proto_probe_tls() { # <host> <port> <out_file>
  local host=$1 port=$2 out_file=$3
  PA_TLS_PROBE_REASON="unknown"
  validate_uint "$port" 1 65535 || return "$EX_VALIDATION"
  local rc=0 pinned_ip=""
  authz_require_online "$host" || rc=$?
  if ((rc != 0)); then return "$rc"; fi
  authz_resolve_target "$host" pinned_ip || rc=$?
  if ((rc != 0)); then return "$rc"; fi
  command -v openssl >/dev/null 2>&1 || return "$EX_DEPENDENCY"
  command -v timeout >/dev/null 2>&1 || return "$EX_DEPENDENCY"
  authz_consume_request || return "$EX_AUTHZ"

  local mto=${AN_CFG[online_max_time_sec]:-8}
  local tls_rc=0
  HTTP_PROXY="" HTTPS_PROXY="" ALL_PROXY="" NO_PROXY="*" \
  http_proxy="" https_proxy="" all_proxy="" no_proxy="*" \
    timeout "$mto" openssl s_client -connect "${pinned_ip}:${port}" -servername "$host" </dev/null >"$out_file" 2>&1 || tls_rc=$?

  if ((tls_rc == 124 || tls_rc == 137)); then
    PA_TLS_PROBE_REASON="timeout"
    log_warn "TLS probe timed out after ${mto}s for ${host}:${port}"
    return "$EX_GENERAL"
  fi
  if [[ ! -s $out_file ]]; then
    PA_TLS_PROBE_REASON="empty_output"
    log_warn "TLS probe returned empty output for ${host}:${port}"
    return "$EX_GENERAL"
  fi
  if ((tls_rc != 0)); then
    PA_TLS_PROBE_REASON="connect_failed"
    log_warn "TLS probe failed (exit $tls_rc) for ${host}:${port}"
    return "$EX_GENERAL"
  fi
  if ! proto_parse_tls_output "$out_file"; then
    PA_TLS_PROBE_REASON="missing_negotiation"
    log_warn "TLS probe output missing negotiated protocol or cipher for ${host}:${port}"
    return "$EX_GENERAL"
  fi
  PA_TLS_PROBE_REASON="ok"
  return 0
}
