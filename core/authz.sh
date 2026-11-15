#!/usr/bin/env bash
# shellcheck shell=bash
# AUTHFORGE core: authorization gate for ANY online assessment.
# Online checks are refused unless ALL hold:
#   1. --allow-online was passed explicitly,
#   2. a scope file names the authorizer, the target, an unexpired date and
#      confirms test-accounts-only,
#   3. if allow_nonlocal_targets=0 (default), the target is a local/lab target
#      (IPv4 loopback, RFC1918 private IPv4, or .test/.local/.internal/.localhost)
#      AND every DNS-resolved IP address falls within permitted lab ranges,
#   4. the per-session request budget is not exhausted.
# Automatic HTTP redirects are disabled; every redirect Location is revalidated.
# Caller-controlled proxy environment variables are ignored (--noproxy '*').
# Note: Ambiguous numeric IPv4 forms (octal, hex, 1/2/3-part shorthand, 32-bit int)
# and IPv6 target literals (e.g., ::1, [::1]) are unsupported and rejected before DNS resolution.
[[ -n "${_AN_AUTHZ:-}" ]] && return 0
_AN_AUTHZ=1

AN_ALLOW_ONLINE=${AN_ALLOW_ONLINE:-0}
AN_SCOPE_FILE=${AN_SCOPE_FILE:-}
AN_ONLINE_REQUESTS=0
_AN_AUTHZ_LAST_LOGGED=""

# Return 0 if a canonical IPv4 address is in loopback (127.0.0.0/8) or RFC1918 private space.
authz_is_lab_ip() { # <ipv4>
  local ip=$1
  validate_ipv4 "$ip" || return 1
  case $ip in
    127.*) return 0 ;;
    10.*) return 0 ;;
    192.168.*) return 0 ;;
    172.1[6-9].* | 172.2[0-9].* | 172.3[0-1].*) return 0 ;;
  esac
  return 1
}

# Return 0 if target is a canonical IPv4 loopback, RFC1918 private IPv4, or reserved lab domain.
# Ambiguous numeric IPv4 forms and IPv6 literals are rejected (M4-AUD-05, M4-P3).
authz_is_lab_target() { # <host>
  local t=${1,,}
  [[ -n $t && $t != *:* && $t != *\[* && $t != *\]* ]] || return 1
  ! validate_ipv4_ambiguous "$t" || return 1
  if validate_ipv4 "$t"; then
    authz_is_lab_ip "$t"
    return $?
  fi
  validate_hostname "$t" || return 1
  case $t in
    localhost | *.test | *.local | *.internal | *.localhost) return 0 ;;
  esac
  return 1
}

# Pre-resolve hostname and validate all returned records before connecting (M4-AUD-01, M4-P3).
# Rejects ambiguous numeric IPv4 forms before invoking getent, and rejects DNS failures,
# malformed records, and mixed public/private DNS responses when allow_nonlocal_targets=0.
# Outputs a single validated canonical IPv4 address for connection pinning.
authz_resolve_target() { # <host> <out_pinned_ip_var>
  local host=$1
  local -n _pinned_out=$2
  _pinned_out=""

  validate_target "$host" || {
    log_error "invalid target syntax: $host"
    return "$EX_VALIDATION"
  }

  local allow_nonlocal=${AN_CFG[allow_nonlocal_targets]:-0}

  if validate_ipv4 "$host"; then
    if [[ $allow_nonlocal == 0 ]] && ! authz_is_lab_ip "$host"; then
      log_error "target IP '$host' is outside permitted lab ranges (allow_nonlocal_targets=0)"
      return "$EX_AUTHZ"
    fi
    _pinned_out=$host
    return 0
  fi

  local -a ipv4_list=()
  local line addr tok

  if [[ -n ${AN_DNS_FIXTURE_FILE:-} ]]; then
    validate_regular_file "$AN_DNS_FIXTURE_FILE" || {
      log_error "DNS fixture file missing or unsafe"
      return "$EX_AUTHZ"
    }
    local matched_host=0 hkey rest
    while IFS= read -r line || [[ -n $line ]]; do
      line=${line%$'\r'}
      line=$(str_trim "$line")
      if [[ -z $line || $line == \#* ]]; then continue; fi
      hkey=${line%%[[:space:]]*}
      rest=$(str_trim "${line#"$hkey"}")
      if [[ ${hkey,,} == "${host,,}" ]]; then
        matched_host=1
        [[ -n $rest ]] || {
          log_error "malformed empty DNS record for '$host'"
          return "$EX_AUTHZ"
        }
        for tok in $rest; do
          if ! validate_ipv4 "$tok"; then
            log_error "malformed or unsupported DNS answer '$tok' for '$host'"
            return "$EX_AUTHZ"
          fi
          if [[ $allow_nonlocal == 0 ]] && ! authz_is_lab_ip "$tok"; then
            log_error "resolved IP '$tok' for '$host' is outside permitted lab ranges"
            return "$EX_AUTHZ"
          fi
          if ! in_array "$tok" "${ipv4_list[@]}"; then
            ipv4_list+=("$tok")
          fi
        done
      fi
    done <"$AN_DNS_FIXTURE_FILE"
    if ((!matched_host || ${#ipv4_list[@]} == 0)); then
      log_error "DNS resolution failed for '$host'"
      return "$EX_AUTHZ"
    fi
  else
    command -v getent >/dev/null 2>&1 || {
      log_error "getent is required for hostname resolution"
      return "$EX_DEPENDENCY"
    }
    local raw=""
    if ! raw=$(getent ahosts "$host" 2>/dev/null) || [[ -z $raw ]]; then
      log_error "DNS resolution failed for '$host'"
      return "$EX_AUTHZ"
    fi
    while IFS= read -r line || [[ -n $line ]]; do
      line=${line%$'\r'}
      line=$(str_trim "$line")
      [[ -n $line ]] || continue
      addr=${line%%[[:space:]]*}
      if validate_ipv4 "$addr"; then
        if [[ $allow_nonlocal == 0 ]] && ! authz_is_lab_ip "$addr"; then
          log_error "resolved IP '$addr' for '$host' is outside permitted lab ranges"
          return "$EX_AUTHZ"
        fi
        if ! in_array "$addr" "${ipv4_list[@]}"; then
          ipv4_list+=("$addr")
        fi
      elif [[ $addr =~ ^[0-9a-fA-F:]+$ && $addr == *:* ]]; then
        local low6=${addr,,}
        if [[ $allow_nonlocal == 0 ]] && [[ $low6 != "::1" && $low6 != fc* && $low6 != fd* && $low6 != fe80:* ]]; then
          log_error "resolved IPv6 '$addr' for '$host' is outside permitted lab ranges"
          return "$EX_AUTHZ"
        fi
      else
        log_error "malformed DNS answer '$addr' for '$host'"
        return "$EX_AUTHZ"
      fi
    done <<<"$raw"

    if ((${#ipv4_list[@]} == 0)); then
      log_error "no usable IPv4 address resolved for '$host'"
      return "$EX_AUTHZ"
    fi
  fi

  _pinned_out=${ipv4_list[0]}
  return 0
}

authz_require_online() { # <target> [quiet_0_or_1]
  local target=${1:-} quiet=${2:-0}
  validate_target "$target" || {
    ((!quiet)) && log_error "invalid target syntax"
    return "$EX_VALIDATION"
  }
  if ((!AN_ALLOW_ONLINE)); then
    ((!quiet)) && log_error "online assessment is disabled (pass --allow-online and --scope FILE)"
    return "$EX_AUTHZ"
  fi
  if [[ -z $AN_SCOPE_FILE ]] || ! validate_regular_file "$AN_SCOPE_FILE"; then
    ((!quiet)) && log_error "scope file missing or unreadable"
    return "$EX_AUTHZ"
  fi
  if [[ ${AN_CFG[allow_nonlocal_targets]:-0} == 0 ]] && ! authz_is_lab_target "$target"; then
    ((!quiet)) && log_error "target '$target' is not a local/lab target (allow_nonlocal_targets=0)"
    return "$EX_AUTHZ"
  fi
  local line key val authorized_by="" expires="" tao="" found=0
  local target_is_ip=0
  if validate_ipv4 "$target"; then target_is_ip=1; fi
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%$'\r'}
    line=$(str_trim "$line")
    if [[ -z $line || $line == \#* ]]; then continue; fi
    [[ $line =~ ^([a-z_]+)=(.*)$ ]] || continue
    key=${BASH_REMATCH[1]}
    val=$(str_trim "${BASH_REMATCH[2]}")
    case $key in
      authorized_by) authorized_by=$val ;;
      expires) expires=$val ;;
      test_accounts_only) tao=$val ;;
      target)
        # Scope target entries must also pass strict target validation so non-canonical
        # numeric IPv4 representations in a scope file are never accepted or canonicalized.
        if validate_target "$val"; then
          if ((target_is_ip)); then
            if validate_ipv4 "$val" && [[ $val == "$target" ]]; then found=1; fi
          else
            if validate_hostname "$val" && [[ ${val,,} == "${target,,}" ]]; then found=1; fi
          fi
        fi ;;
    esac
  done <"$AN_SCOPE_FILE"
  [[ -n $authorized_by ]] || { ((!quiet)) && log_error "scope: authorized_by missing"; return "$EX_AUTHZ"; }
  validate_date_ymd "$expires" || { ((!quiet)) && log_error "scope: expires missing or malformed (YYYY-MM-DD)"; return "$EX_AUTHZ"; }
  local today
  today=$(printf '%(%Y-%m-%d)T' -1)
  if [[ $expires < $today ]]; then ((!quiet)) && log_error "scope: authorization expired on $expires"; return "$EX_AUTHZ"; fi
  [[ $tao == yes ]] || { ((!quiet)) && log_error "scope: test_accounts_only=yes is required"; return "$EX_AUTHZ"; }
  ((found)) || { ((!quiet)) && log_error "scope: target is not listed in scope file"; return "$EX_AUTHZ"; }

  local log_key="${AN_SESSION_ID:-nosess}:${target}"
  if ((!quiet)) && [[ ${_AN_AUTHZ_LAST_LOGGED:-} != "$log_key" ]]; then
    log_info "online authorization verified for target (authorizer recorded in scope file)"
    _AN_AUTHZ_LAST_LOGGED=$log_key
  fi
  return 0
}

# Call before every online request: enforces budget and rate limit.
authz_consume_request() {
  local max=${AN_CFG[max_online_requests]:-100} rps=${AN_CFG[max_online_rps]:-1}
  if ((AN_ONLINE_REQUESTS >= 10#$max)); then
    log_error "online request budget exhausted ($max)"
    return "$EX_AUTHZ"
  fi
  AN_ONLINE_REQUESTS=$((AN_ONLINE_REQUESTS + 1))
  if ((AN_ONLINE_REQUESTS > 1)); then sleep "$(awk -v r="$rps" 'BEGIN{printf "%.3f", 1/r}')"; fi
  return 0
}

# Parse an http(s) URL into scheme, host, port, and path.
# Rejects userinfo (@), control chars, ambiguous numeric IPv4 forms, and IPv6 bracket literals ([::1]).
authz_parse_url() { # <url> <out_scheme> <out_host> <out_port> <out_path>
  local url=$1
  local -n _us=$2 _uh=$3 _up=$4 _upath=$5
  [[ ! $url =~ [[:cntrl:]] ]] || return 1
  if [[ $url =~ ^(https?)://([^/@:]+)(:([0-9]{1,5}))?(/.*)?$ ]]; then
    _us=${BASH_REMATCH[1],,}
    _uh=${BASH_REMATCH[2]}
    _up=${BASH_REMATCH[4]:-}
    _upath=${BASH_REMATCH[5]:-/}
    validate_target "$_uh" || return 1
    if [[ -n $_up ]]; then
      validate_uint "$_up" 1 65535 || return 1
    else
      if [[ $_us == https ]]; then _up=443; else _up=80; fi
    fi
    return 0
  fi
  return 1
}

# Safe, fail-closed HTTP(S) request wrapper using curl with redirects disabled,
# proxy environment bypass disabled (--noproxy '*' + cleared proxy env vars),
# and DNS pre-resolution pinned via --resolve (preserving HTTP Host and TLS SNI).
authz_safe_http() { # <method> <url> <out_hdr> <out_body> [insecure_tls_0_or_1]
  local method=$1 url=$2 out_hdr=$3 out_body=$4 insecure=${5:-0}
  # shellcheck disable=SC2034  # scheme and path are required nameref outputs for authz_parse_url
  local scheme host port path
  authz_parse_url "$url" scheme host port path || {
    log_error "invalid or unsafe URL"
    return "$EX_VALIDATION"
  }
  local rc=0 pinned_ip=""
  authz_require_online "$host" || rc=$?
  if ((rc != 0)); then return "$rc"; fi
  authz_resolve_target "$host" pinned_ip || rc=$?
  if ((rc != 0)); then return "$rc"; fi
  command -v curl >/dev/null 2>&1 || return "$EX_DEPENDENCY"
  authz_consume_request || return "$EX_AUTHZ"

  local cto=${AN_CFG[online_connect_timeout_sec]:-3}
  local mto=${AN_CFG[online_max_time_sec]:-8}

  local -a args=(
    -sS
    --connect-timeout "$cto"
    --max-time "$mto"
    --max-redirs 0
    --proto '=http,https'
    --noproxy '*'
    --resolve "${host}:${port}:${pinned_ip}"
    -X "$method"
    -D "$out_hdr"
    -o "$out_body"
  )
  if ((insecure)); then args+=(-k); fi
  if ! HTTP_PROXY="" HTTPS_PROXY="" ALL_PROXY="" NO_PROXY="*" \
       http_proxy="" https_proxy="" all_proxy="" no_proxy="*" \
       curl "${args[@]}" "$url"; then
    return "$EX_GENERAL"
  fi
  return 0
}
