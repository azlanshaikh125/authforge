#!/usr/bin/env bash
# shellcheck shell=bash disable=SC1091,SC2034
source "$(dirname "${BASH_SOURCE[0]}")/../lib/harness.sh"
sandbox
load_core
tmp_init
trap 'tmp_cleanup; rm -rf "$SB"' EXIT

# 1. Valid descriptor parsing
pwr_parse_descriptor "$TEST_ROOT/fixtures/sample-pwreset.conf"
assert_eq 0 $? "sample-pwreset.conf parses cleanly"
assert_eq "48" "${PWR_DESC[reset_token_entropy_bits]}" "parses reset_token_entropy_bits=48"
assert_eq "1" "${PWR_DESC[reset_send_password_in_email]}" "parses reset_send_password_in_email=1"

# 2. Command-injection & unknown-key rejection
printf 'reset_token_ttl_min=$(touch %s/PWNED_PWR)\n' "$SB" >"$SB/inj.conf"
pwr_parse_descriptor "$SB/inj.conf" 2>/dev/null && t_fail "command substitution in pwreset descriptor rejected" || t_ok "command substitution in pwreset descriptor rejected"
[[ ! -e $SB/PWNED_PWR ]] && t_ok "pwreset descriptor never executed" || t_fail "pwreset descriptor never executed"

printf 'bad_reset_key=1\n' >"$SB/unk.conf"
pwr_parse_descriptor "$SB/unk.conf" 2>/dev/null && t_fail "unknown key in pwreset descriptor rejected" || t_ok "unknown key in pwreset descriptor rejected"

t_summary
