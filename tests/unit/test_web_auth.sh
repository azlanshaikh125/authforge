#!/usr/bin/env bash
# shellcheck shell=bash disable=SC1091,SC2034
source "$(dirname "${BASH_SOURCE[0]}")/../lib/harness.sh"
sandbox
load_core
tmp_init
trap 'tmp_cleanup; rm -rf "$SB"' EXIT

printf 'HTTP/1.1 200 OK\r\nContent-Security-Policy: default-src '\''self'\''\r\nX-Frame-Options: DENY\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-RateLimit-Remaining: 4\r\nSet-Cookie: sid=SecretTok123; Path=/; HttpOnly\r\n\r\n' >"$SB/hdr_ok.txt"
web_auth_parse_headers "$SB/hdr_ok.txt"
assert_eq 1 "$WA_HAS_CSP" "detects CSP header"
assert_eq 1 "$WA_HAS_XFO" "detects X-Frame-Options header"
assert_eq 1 "$WA_HAS_CACHE_NOSTORE" "detects Cache-Control: no-store"
assert_eq 1 "$WA_HAS_REFERRER" "detects Referrer-Policy"
assert_eq 1 "$WA_HAS_RATELIMIT_HDR" "detects X-RateLimit header"
assert_eq 1 "$WA_COOKIE_COUNT" "captures 1 Set-Cookie header"

printf 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n' >"$SB/hdr_bad.txt"
web_auth_parse_headers "$SB/hdr_bad.txt"
assert_eq 0 "$WA_HAS_CSP" "detects missing CSP"
assert_eq 0 "$WA_HAS_XFO" "detects missing X-Frame-Options"
assert_eq 0 "$WA_HAS_CACHE_NOSTORE" "detects missing Cache-Control: no-store"
assert_eq 0 "$WA_HAS_RATELIMIT_HDR" "detects missing rate-limit headers"

# M4-AUD-04: Reset header parser state when a new HTTP status block begins
printf 'HTTP/1.1 302 Found\r\nContent-Security-Policy: default-src '\''self'\''\r\nX-Frame-Options: DENY\r\nSet-Cookie: pre=1; Secure; HttpOnly\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n' >"$SB/hdr_multi.txt"
web_auth_parse_headers "$SB/hdr_multi.txt"
assert_eq 0 "$WA_HAS_CSP" "M4-AUD-04: web_auth_parse_headers resets CSP across status blocks"
assert_eq 0 "$WA_HAS_XFO" "M4-AUD-04: web_auth_parse_headers resets XFO across status blocks"
assert_eq 0 "$WA_COOKIE_COUNT" "M4-AUD-04: web_auth_parse_headers resets Set-Cookie list across status blocks"

t_summary
