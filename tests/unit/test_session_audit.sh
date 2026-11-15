#!/usr/bin/env bash
# shellcheck shell=bash disable=SC1091,SC2034
source "$(dirname "${BASH_SOURCE[0]}")/../lib/harness.sh"
sandbox
load_core
tmp_init
trap 'tmp_cleanup; rm -rf "$SB"' EXIT

# 1. Valid descriptor parsing
sess_parse_descriptor "$TEST_ROOT/fixtures/sample-session.conf"
assert_eq 0 $? "sample-session.conf parses cleanly"
assert_eq "64" "${SESS_DESC[session_id_entropy_bits]}" "parses session_id_entropy_bits=64"
assert_eq "1" "${SESS_DESC[session_id_in_url]}" "parses session_id_in_url=1"

# 2. Command-injection & unknown-key rejection
printf 'session_id_entropy_bits=$(touch %s/PWNED_SESS)\n' "$SB" >"$SB/inj.conf"
sess_parse_descriptor "$SB/inj.conf" 2>/dev/null && t_fail "command substitution in session descriptor rejected" || t_ok "command substitution in session descriptor rejected"
[[ ! -e $SB/PWNED_SESS ]] && t_ok "session descriptor never executed" || t_fail "session descriptor never executed"

# 3. Set-Cookie header parsing (value never stored in CK_* globals)
sess_parse_cookie_header "Set-Cookie: __Host-sid=SuperSecretSessionToken999; Path=/; Secure; HttpOnly; SameSite=Strict"
assert_eq 0 $? "valid Set-Cookie header parses"
assert_eq "__Host-sid" "$CK_NAME" "extracts cookie name"
assert_eq "__Host-" "$CK_PREFIX" "detects __Host- prefix"
assert_eq 1 "$CK_SECURE" "detects Secure flag"
assert_eq 1 "$CK_HTTPONLY" "detects HttpOnly flag"
assert_eq "Strict" "$CK_SAMESITE" "detects SameSite=Strict"

sess_parse_cookie_header "malformed_cookie_no_equals" && t_fail "malformed cookie rejected" || t_ok "malformed cookie rejected"

t_summary
