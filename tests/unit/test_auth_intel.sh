#!/usr/bin/env bash
# shellcheck shell=bash disable=SC1091,SC2034
source "$(dirname "${BASH_SOURCE[0]}")/../lib/harness.sh"
sandbox
load_core
tmp_init
trap 'tmp_cleanup; rm -rf "$SB"' EXIT

cat >"$SB/oidc.json" <<'EOF'
{
  "issuer": "http://127.0.0.1:8080",
  "response_types_supported": ["code", "token"],
  "code_challenge_methods_supported": ["plain"]
}
EOF
auth_intel_parse_oidc "$SB/oidc.json"
assert_eq 1 "$AI_OIDC_FOUND" "detects OIDC discovery document"
assert_eq 0 "$AI_OIDC_ISSUER_HTTPS" "flags non-HTTPS OIDC issuer"
assert_eq 0 "$AI_OIDC_PKCE_S256" "flags missing PKCE S256"
assert_eq 1 "$AI_OIDC_IMPLICIT_FLOW" "detects legacy implicit token flow"

printf 'HTTP/1.1 200 OK\r\nServer: LabAuth/1.0\r\n\r\n' >"$SB/hdr.txt"
auth_intel_parse_server_header "$SB/hdr.txt"
assert_eq "LabAuth/1.0" "$AI_SERVER_BANNER" "extracts Server header"

# M4-AUD-04: Reset Server header state when a new HTTP status block begins
printf 'HTTP/1.1 301 Moved\r\nServer: ProxyEdge/1.0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n' >"$SB/hdr_multi.txt"
auth_intel_parse_server_header "$SB/hdr_multi.txt"
assert_eq "" "$AI_SERVER_BANNER" "M4-AUD-04: auth_intel_parse_server_header resets Server across status blocks"

t_summary
