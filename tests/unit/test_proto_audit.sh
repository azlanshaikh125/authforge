#!/usr/bin/env bash
# shellcheck shell=bash disable=SC1091,SC2034
source "$(dirname "${BASH_SOURCE[0]}")/../lib/harness.sh"
sandbox
load_core
tmp_init
trap 'tmp_cleanup; rm -rf "$SB"' EXIT

# 1. Authz lab-target & URL parser guardrails (fail-closed)
authz_is_lab_target "127.0.0.1" && t_ok "127.0.0.1 is lab target" || t_fail "127.0.0.1 lab check"
authz_is_lab_target "localhost" && t_ok "localhost is lab target" || t_fail "localhost lab check"
authz_is_lab_target "10.20.30.40" && t_ok "10.x RFC1918 is lab target" || t_fail "10.x lab check"
authz_is_lab_target "192.168.1.50" && t_ok "192.168.x is lab target" || t_fail "192.168.x lab check"
authz_is_lab_target "172.20.5.9" && t_ok "172.16-31.x is lab target" || t_fail "172.20.x lab check"
authz_is_lab_target "app.internal" && t_ok "*.internal is lab target" || t_fail "*.internal lab check"
authz_is_lab_target "example.com" && t_fail "public domain rejected by default lab check" || t_ok "public domain rejected by default lab check"
authz_is_lab_target "8.8.8.8" && t_fail "public IP rejected by default lab check" || t_ok "public IP rejected by default lab check"

# M4-AUD-05: Consistent IPv6 literal rejection across validators & parsers
validate_target "::1" && t_fail "validate_target rejects ::1" || t_ok "validate_target rejects ::1"
validate_target "[::1]" && t_fail "validate_target rejects [::1]" || t_ok "validate_target rejects [::1]"
authz_is_lab_target "::1" && t_fail "authz_is_lab_target rejects ::1" || t_ok "authz_is_lab_target rejects ::1"
authz_is_lab_target "[::1]" && t_fail "authz_is_lab_target rejects [::1]" || t_ok "authz_is_lab_target rejects [::1]"
s="" h="" p="" path=""
authz_parse_url "http://[::1]:8080/login" s h p path && t_fail "authz_parse_url rejects bracketed IPv6" || t_ok "authz_parse_url rejects bracketed IPv6"

# M4-P3: URL parser rejects ambiguous numeric IPv4 representations
for ambig_url in \
  "http://0177.0.0.1:8080/login" \
  "http://127.0.0.010:8080/login" \
  "http://127.1:8080/login" \
  "http://2130706433:8080/login" \
  "http://0x7f.0.0.1:8080/login" \
  "http://127.0.1:8080/login" \
  "http://0x7f000001:8080/login"; do
  authz_parse_url "$ambig_url" s h p path && t_fail "M4-P3: authz_parse_url rejects $ambig_url" || t_ok "M4-P3: authz_parse_url rejects $ambig_url"
done

authz_parse_url "https://127.0.0.1:8443/login" s h p path
assert_eq "https" "$s" "parses https scheme"
assert_eq "127.0.0.1" "$h" "parses host"
assert_eq "8443" "$p" "parses port"
assert_eq "/login" "$path" "parses path"

authz_parse_url "http://user:pass@127.0.0.1/login" s h p path && t_fail "rejects userinfo in URL" || t_ok "rejects userinfo in URL"
authz_parse_url "ftp://127.0.0.1/file" s h p path && t_fail "rejects non-http scheme" || t_ok "rejects non-http scheme"

# 2. M4-AUD-01: Pre-connection DNS resolution & IP pinning
cat >"$SB/dns_fixtures.txt" <<'EOF'
loopback.internal 127.0.0.1
rfc1918a.internal 10.10.20.30
rfc1918b.internal 192.168.10.25 172.20.1.9
public.internal 93.184.216.34
metadata.internal 169.254.169.254
mixed.internal 10.0.0.5 93.184.216.34
badip.internal 999.999.999.999
garbage.internal not_an_ip_token
EOF
export AN_DNS_FIXTURE_FILE="$SB/dns_fixtures.txt"

pinned=""
authz_resolve_target "loopback.internal" pinned && t_ok "resolves loopback.internal" || t_fail "resolves loopback.internal"
assert_eq "127.0.0.1" "$pinned" "pins loopback.internal to 127.0.0.1"

pinned=""
authz_resolve_target "rfc1918a.internal" pinned && t_ok "resolves 10.x RFC1918 hostname" || t_fail "resolves 10.x RFC1918 hostname"
assert_eq "10.10.20.30" "$pinned" "pins rfc1918a.internal to 10.10.20.30"

pinned=""
authz_resolve_target "rfc1918b.internal" pinned && t_ok "resolves multi-A RFC1918 hostname when all IPs are private" || t_fail "resolves multi-A RFC1918"
assert_eq "192.168.10.25" "$pinned" "pins rfc1918b.internal to first validated private IP"

rc=0
authz_resolve_target "public.internal" pinned 2>/dev/null || rc=$?
assert_eq 5 "$rc" "rejects .internal hostname resolving to public IP (EX_AUTHZ=5)"
assert_eq "" "$pinned" "clears pinned IP on public DNS rejection"

rc=0
authz_resolve_target "metadata.internal" pinned 2>/dev/null || rc=$?
assert_eq 5 "$rc" "rejects cloud metadata 169.254.169.254 IP (EX_AUTHZ=5)"

rc=0
authz_resolve_target "mixed.internal" pinned 2>/dev/null || rc=$?
assert_eq 5 "$rc" "rejects mixed private+public DNS answer (EX_AUTHZ=5)"

rc=0
authz_resolve_target "badip.internal" pinned 2>/dev/null || rc=$?
assert_eq 5 "$rc" "rejects malformed IPv4 octet in DNS answer (EX_AUTHZ=5)"

rc=0
authz_resolve_target "garbage.internal" pinned 2>/dev/null || rc=$?
assert_eq 5 "$rc" "rejects non-IP token in DNS answer (EX_AUTHZ=5)"

rc=0
authz_resolve_target "nxdomain.internal" pinned 2>/dev/null || rc=$?
assert_eq 5 "$rc" "rejects unresolvable NXDOMAIN host (EX_AUTHZ=5)"

# Verify proto_probe_tls passes pinned IP in -connect and hostname in -servername, and clears proxy vars
mkdir -p "$SB/bin"
cat >"$SB/bin/openssl" <<EOF
#!/usr/bin/env bash
printf 'ARGS=%s\nPROXY=%s|%s|%s|%s\n' "\$*" "\${HTTP_PROXY:-}" "\${HTTPS_PROXY:-}" "\${ALL_PROXY:-}" "\${NO_PROXY:-}" >"$SB/openssl_args.txt"
printf 'Protocol  : TLSv1.3\nCipher    : TLS_AES_256_GCM_SHA384\n'
exit 0
EOF
chmod +x "$SB/bin/openssl"
printf 'authorized_by=UnitTest\ntarget=rfc1918a.internal\ntarget=localhost\nexpires=2999-01-01\ntest_accounts_only=yes\n' >"$SB/tls_scope.txt"

(
  export PATH="$SB/bin:$PATH"
  export HTTP_PROXY="http://127.0.0.1:9999" HTTPS_PROXY="http://127.0.0.1:9999" ALL_PROXY="http://127.0.0.1:9999"
  AN_ALLOW_ONLINE=1 AN_SCOPE_FILE="$SB/tls_scope.txt"
  proto_probe_tls "rfc1918a.internal" 8443 "$SB/tls_probe_out.txt"
)
assert_eq 0 $? "proto_probe_tls succeeds with pinned hostname"
assert_contains "$(<"$SB/openssl_args.txt")" "s_client -connect 10.10.20.30:8443 -servername rfc1918a.internal" "openssl s_client pins resolved IP and preserves SNI hostname"
assert_contains "$(<"$SB/openssl_args.txt")" "PROXY=|||*" "proto_probe_tls scrubs proxy environment variables"

# M4-AUD-06: Verify authz_safe_http passes --noproxy '*' and scrubs all uppercase/lowercase proxy env vars
cat >"$SB/bin/curl" <<EOF
#!/usr/bin/env bash
printf 'ARGS=%s\nUP=%s|%s|%s\nLO=%s|%s|%s\nNP=%s|%s\n' \
  "\$*" \
  "\${HTTP_PROXY:-}" "\${HTTPS_PROXY:-}" "\${ALL_PROXY:-}" \
  "\${http_proxy:-}" "\${https_proxy:-}" "\${all_proxy:-}" \
  "\${NO_PROXY:-}" "\${no_proxy:-}" >"$SB/curl_capture.txt"
exit 0
EOF
chmod +x "$SB/bin/curl"

(
  export PATH="$SB/bin:$PATH"
  export HTTP_PROXY="http://127.0.0.1:8888" HTTPS_PROXY="http://127.0.0.1:8888" ALL_PROXY="socks5://127.0.0.1:8888"
  export http_proxy="http://127.0.0.1:8888" https_proxy="http://127.0.0.1:8888" all_proxy="socks5://127.0.0.1:8888"
  export NO_PROXY="" no_proxy=""
  AN_ALLOW_ONLINE=1 AN_SCOPE_FILE="$SB/tls_scope.txt"
  authz_safe_http GET "http://rfc1918a.internal:8080/login" "$SB/chdr.txt" "$SB/cbody.txt" 0
)
assert_eq 0 $? "M4-AUD-06: authz_safe_http succeeds with shimmed curl"
assert_contains "$(<"$SB/curl_capture.txt")" "--noproxy * --resolve rfc1918a.internal:8080:10.10.20.30" "M4-AUD-06: curl receives --noproxy '*' and --resolve pinned IP"
assert_contains "$(<"$SB/curl_capture.txt")" "UP=||" "M4-AUD-06: uppercase HTTP_PROXY/HTTPS_PROXY/ALL_PROXY scrubbed"
assert_contains "$(<"$SB/curl_capture.txt")" "LO=||" "M4-AUD-06: lowercase http_proxy/https_proxy/all_proxy scrubbed"
assert_contains "$(<"$SB/curl_capture.txt")" "NP=*|*" "M4-AUD-06: NO_PROXY and no_proxy forced to '*'"

# M4-P3: Verify authz_safe_http returns EX_DEPENDENCY (4) specifically from missing curl after getent DNS resolution succeeds
mkdir -p "$SB/nocurl_bin"
for cmd_bin in bash env awk sed grep tr cut sort uniq wc head tail cat cp od id rm mkdir chmod stat mktemp readlink realpath sha256sum date sleep find getent timeout openssl; do
  p=$(command -v "$cmd_bin" 2>/dev/null || true)
  [[ -n $p ]] && ln -sf "$p" "$SB/nocurl_bin/$cmd_bin"
done
rc_nc=0
(
  unset AN_DNS_FIXTURE_FILE
  export PATH="$SB/nocurl_bin"
  AN_ALLOW_ONLINE=1 AN_SCOPE_FILE="$SB/tls_scope.txt"
  AN_ONLINE_REQUESTS=0
  command -v getent >/dev/null 2>&1 || exit 91
  ! command -v curl >/dev/null 2>&1 || exit 92
  pinned_nc=""
  authz_resolve_target "localhost" pinned_nc || exit 93
  [[ $pinned_nc == "127.0.0.1" ]] || exit 94
  authz_safe_http GET "http://localhost:8080/login" "$SB/nc_hdr.txt" "$SB/nc_body.txt" 0 2>/dev/null
) || rc_nc=$?
assert_eq 4 "$rc_nc" "M4-P3: authz_safe_http returns EX_DEPENDENCY (4) specifically when curl is missing after getent DNS resolution succeeds"

ln -sf "$SB/bin/curl" "$SB/nocurl_bin/curl"
rc_wc=0
(
  unset AN_DNS_FIXTURE_FILE
  export PATH="$SB/nocurl_bin"
  AN_ALLOW_ONLINE=1 AN_SCOPE_FILE="$SB/tls_scope.txt"
  authz_safe_http GET "http://localhost:8080/login" "$SB/wc_hdr.txt" "$SB/wc_body.txt" 0 2>/dev/null
) || rc_wc=$?
assert_eq 0 "$rc_wc" "M4-P3: adding curl binary to identical PATH makes authz_safe_http succeed (0)"

# M4-AUD-07: Verify proto_probe_tls returns EX_DEPENDENCY (4) specifically from missing timeout
# Populate $SB/notimeout_bin with getent, openssl, and all required utilities, deliberately excluding timeout.
mkdir -p "$SB/notimeout_bin"
for cmd_bin in bash env awk sed grep tr cut sort uniq wc head tail cat cp od id rm mkdir chmod stat mktemp readlink realpath sha256sum date sleep find getent curl; do
  p=$(command -v "$cmd_bin" 2>/dev/null || true)
  [[ -n $p ]] && ln -sf "$p" "$SB/notimeout_bin/$cmd_bin"
done
ln -sf "$SB/bin/openssl" "$SB/notimeout_bin/openssl"
TIMEOUT_REAL=$(command -v timeout)

rc_nt=0
(
  unset AN_DNS_FIXTURE_FILE
  export PATH="$SB/notimeout_bin"
  AN_ALLOW_ONLINE=1 AN_SCOPE_FILE="$SB/tls_scope.txt"
  command -v getent >/dev/null 2>&1 || exit 91
  command -v openssl >/dev/null 2>&1 || exit 92
  ! command -v timeout >/dev/null 2>&1 || exit 93
  pinned_nt=""
  authz_resolve_target "localhost" pinned_nt || exit 94
  [[ $pinned_nt == "127.0.0.1" ]] || exit 95
  proto_probe_tls "localhost" 8443 "$SB/tls_nt.txt" 2>/dev/null
) || rc_nt=$?
assert_eq 4 "$rc_nt" "M4-AUD-07: proto_probe_tls returns EX_DEPENDENCY (4) specifically when timeout is missing after getent DNS resolution succeeds"

# Prove that adding ONLY timeout to the exact same PATH makes proto_probe_tls succeed (rc=0)
ln -sf "$TIMEOUT_REAL" "$SB/notimeout_bin/timeout"
rc_wt=0
(
  unset AN_DNS_FIXTURE_FILE
  export PATH="$SB/notimeout_bin"
  AN_ALLOW_ONLINE=1 AN_SCOPE_FILE="$SB/tls_scope.txt"
  proto_probe_tls "localhost" 8443 "$SB/tls_wt.txt" 2>/dev/null
) || rc_wt=$?
assert_eq 0 "$rc_wt" "M4-AUD-07: adding timeout binary to identical PATH makes proto_probe_tls succeed (0)"

# M4-AUD-08: Mandatory TLS probe & parser failure/success regression tests
# (1) Timeout exit code 124
cat >"$SB/bin/timeout" <<'EOF'
#!/usr/bin/env bash
printf 'Connecting to 10.10.20.30...\n'
exit 124
EOF
chmod +x "$SB/bin/timeout"
rc_to=0
(
  export PATH="$SB/bin:$PATH"
  AN_ALLOW_ONLINE=1 AN_SCOPE_FILE="$SB/tls_scope.txt"
  proto_probe_tls "rfc1918a.internal" 8443 "$SB/tls_to.txt" 2>/dev/null && exit 0
  printf '%s' "$PA_TLS_PROBE_REASON" >"$SB/reason_to.txt"
  exit 1
) || rc_to=$?
assert_eq 1 "$rc_to" "M4-AUD-08 (1): timeout exit code 124 fails proto_probe_tls"
assert_eq "timeout" "$(<"$SB/reason_to.txt")" "M4-AUD-08 (1): timeout exit code 124 sets PA_TLS_PROBE_REASON=timeout"
rm -f "$SB/bin/timeout"

# (2) OpenSSL connection refused (non-zero exit with error output)
cat >"$SB/bin/openssl" <<'EOF'
#!/usr/bin/env bash
printf '40D7F1:error:8000006F:system library:BIO_connect:Connection refused\nconnect:errno=111\n'
exit 1
EOF
chmod +x "$SB/bin/openssl"
rc_cr=0
(
  export PATH="$SB/bin:$PATH"
  AN_ALLOW_ONLINE=1 AN_SCOPE_FILE="$SB/tls_scope.txt"
  proto_probe_tls "rfc1918a.internal" 8443 "$SB/tls_cr.txt" 2>/dev/null && exit 0
  printf '%s' "$PA_TLS_PROBE_REASON" >"$SB/reason_cr.txt"
  exit 1
) || rc_cr=$?
assert_eq 1 "$rc_cr" "M4-AUD-08 (2): OpenSSL connection refused fails proto_probe_tls"
assert_eq "connect_failed" "$(<"$SB/reason_cr.txt")" "M4-AUD-08 (2): OpenSSL connection refused sets PA_TLS_PROBE_REASON=connect_failed"

# (3) Empty OpenSSL output
cat >"$SB/bin/openssl" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$SB/bin/openssl"
rc_emp=0
(
  export PATH="$SB/bin:$PATH"
  AN_ALLOW_ONLINE=1 AN_SCOPE_FILE="$SB/tls_scope.txt"
  proto_probe_tls "rfc1918a.internal" 8443 "$SB/tls_emp.txt" 2>/dev/null && exit 0
  printf '%s' "$PA_TLS_PROBE_REASON" >"$SB/reason_emp.txt"
  exit 1
) || rc_emp=$?
assert_eq 1 "$rc_emp" "M4-AUD-08 (3): empty OpenSSL output fails proto_probe_tls"
assert_eq "empty_output" "$(<"$SB/reason_emp.txt")" "M4-AUD-08 (3): empty OpenSSL output sets PA_TLS_PROBE_REASON=empty_output"
: >"$SB/empty_file.txt"
proto_parse_tls_output "$SB/empty_file.txt" && t_fail "M4-AUD-08 (3): parser rejects empty file" || t_ok "M4-AUD-08 (3): parser rejects empty file"

# (4) Non-empty output but missing protocol
cat >"$SB/no_proto.txt" <<'EOF'
CONNECTED(00000003)
    Cipher    : TLS_AES_256_GCM_SHA384
EOF
proto_parse_tls_output "$SB/no_proto.txt" && t_fail "M4-AUD-08 (4): parser rejects output missing protocol" || t_ok "M4-AUD-08 (4): parser rejects output missing protocol"

# (5) Non-empty output but missing or null cipher
cat >"$SB/no_cipher.txt" <<'EOF'
CONNECTED(00000003)
    Protocol  : TLSv1.3
EOF
proto_parse_tls_output "$SB/no_cipher.txt" && t_fail "M4-AUD-08 (5): parser rejects output missing cipher" || t_ok "M4-AUD-08 (5): parser rejects output missing cipher"

cat >"$SB/null_cipher.txt" <<'EOF'
CONNECTED(00000003)
    Protocol  : TLSv1.2
    Cipher    : 0000
EOF
proto_parse_tls_output "$SB/null_cipher.txt" && t_fail "M4-AUD-08 (5): parser rejects 0000/NONE unnegotiated cipher" || t_ok "M4-AUD-08 (5): parser rejects 0000/NONE unnegotiated cipher"

# (6) Valid TLS 1.2 negotiated output
cat >"$SB/tls12_ok.txt" <<'EOF'
CONNECTED(00000003)
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES128-GCM-SHA256
EOF
proto_parse_tls_output "$SB/tls12_ok.txt" && t_ok "M4-AUD-08 (6): parser accepts valid TLS 1.2 output" || t_fail "M4-AUD-08 (6): parser accepts valid TLS 1.2 output"
assert_eq "TLSv1.2" "$PA_TLS_PROTOCOL" "M4-AUD-08 (6): parses TLSv1.2 protocol"
assert_eq "ECDHE-RSA-AES128-GCM-SHA256" "$PA_TLS_CIPHER" "M4-AUD-08 (6): parses TLS 1.2 AEAD cipher"
assert_eq 0 "$PA_TLS_DEPRECATED" "M4-AUD-08 (6): TLS 1.2 is not deprecated"
assert_eq 0 "$PA_TLS_WEAK_CIPHER" "M4-AUD-08 (6): AES128-GCM is not weak"

# (7) Valid TLS 1.3 negotiated output
cat >"$SB/tls13_ok.txt" <<'EOF'
CONNECTED(00000003)
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
EOF
proto_parse_tls_output "$SB/tls13_ok.txt" && t_ok "M4-AUD-08 (7): parser accepts valid TLS 1.3 output" || t_fail "M4-AUD-08 (7): parser accepts valid TLS 1.3 output"
assert_eq "TLSv1.3" "$PA_TLS_PROTOCOL" "M4-AUD-08 (7): parses TLSv1.3 protocol"
assert_eq "TLS_AES_256_GCM_SHA384" "$PA_TLS_CIPHER" "M4-AUD-08 (7): parses TLS 1.3 cipher"
assert_eq 0 "$PA_TLS_DEPRECATED" "M4-AUD-08 (7): TLS 1.3 is not deprecated"
assert_eq 0 "$PA_TLS_WEAK_CIPHER" "M4-AUD-08 (7): TLS_AES_256_GCM_SHA384 is not weak"

# (8) Self-signed certificate with valid negotiated TLS details
cat >"$SB/tls_weak.txt" <<'EOF'
    Protocol  : TLSv1.1
    Cipher    : ECDHE-RSA-RC4-SHA
depth=0 CN = lab.test
verify error:num=18:self-signed certificate
EOF
proto_parse_tls_output "$SB/tls_weak.txt" && t_ok "M4-AUD-08 (8): parser accepts self-signed cert when protocol and cipher are negotiated" || t_fail "M4-AUD-08 (8): self-signed cert parse"
assert_eq "TLSv1.1" "$PA_TLS_PROTOCOL" "parses TLSv1.1"
assert_eq 1 "$PA_TLS_DEPRECATED" "flags TLSv1.1 as deprecated"
assert_eq 1 "$PA_TLS_WEAK_CIPHER" "flags RC4 cipher as weak"
assert_eq 1 "$PA_TLS_SELF_SIGNED" "detects self-signed cert"

# (10) Authorization failure & request-budget failure remain fail-closed in proto_probe_tls
rc_unauth=0
(
  AN_ALLOW_ONLINE=0 AN_SCOPE_FILE="$SB/tls_scope.txt"
  proto_probe_tls "rfc1918a.internal" 8443 "$SB/tls_unauth.txt" 2>/dev/null
) || rc_unauth=$?
assert_eq 5 "$rc_unauth" "M4-AUD-08 (10): proto_probe_tls fails closed (EX_AUTHZ=5) without --allow-online"

rc_b0=0
(
  AN_ALLOW_ONLINE=1 AN_SCOPE_FILE="$SB/tls_scope.txt" AN_CFG["max_online_requests"]=0
  proto_probe_tls "rfc1918a.internal" 8443 "$SB/tls_b0.txt" 2>/dev/null
) || rc_b0=$?
assert_eq 5 "$rc_b0" "M4-AUD-08 (10): proto_probe_tls fails closed (EX_AUTHZ=5) when request budget=0"

unset AN_DNS_FIXTURE_FILE

# 3. HTTP auth header parser + M4-AUD-04 multi-block reset
printf 'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm="Lab"\r\nLocation: http://evil.com/out\r\n\r\n' >"$SB/hdr.txt"
proto_parse_http_headers "$SB/hdr.txt" "http"
assert_eq "401" "$PA_HTTP_STATUS" "parses HTTP 401"
assert_eq "Basic" "$PA_HTTP_AUTH_SCHEMES" "parses Basic auth scheme"
assert_eq 1 "$PA_HTTP_BASIC_PLAINTEXT" "flags Basic over HTTP"
assert_eq "http://evil.com/out" "$PA_HTTP_REDIRECT_TARGET" "captures redirect target without following"

printf 'HTTP/1.1 302 Found\r\nStrict-Transport-Security: max-age=31536000\r\nWWW-Authenticate: Basic realm="Old"\r\nLocation: https://127.0.0.1/next\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n' >"$SB/hdr_multi.txt"
proto_parse_http_headers "$SB/hdr_multi.txt" "http"
assert_eq "200" "$PA_HTTP_STATUS" "M4-AUD-04: multi-block parser captures final HTTP status"
assert_eq 0 "$PA_HTTP_HSTS" "M4-AUD-04: multi-block parser resets HSTS from earlier status block"
assert_eq "" "$PA_HTTP_AUTH_SCHEMES" "M4-AUD-04: multi-block parser resets WWW-Authenticate from earlier block"
assert_eq 0 "$PA_HTTP_BASIC_PLAINTEXT" "M4-AUD-04: multi-block parser resets Basic plaintext flag"
assert_eq "" "$PA_HTTP_REDIRECT_TARGET" "M4-AUD-04: multi-block parser resets Location from earlier block"

t_summary
