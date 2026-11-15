#!/usr/bin/env bash
# shellcheck shell=bash disable=SC1091,SC2034
source "$(dirname "${BASH_SOURCE[0]}")/../lib/harness.sh"
sandbox
load_core
tmp_init
trap 'tmp_cleanup; rm -rf "$SB"' EXIT

# 1. Valid descriptor parsing
mfa_parse_descriptor "$TEST_ROOT/fixtures/sample-mfa.conf"
assert_eq 0 $? "sample-mfa.conf parses cleanly"
assert_eq "SHA1" "${MFA_DESC[totp_algorithm]}" "parses totp_algorithm=SHA1"
assert_eq "3" "${MFA_DESC[totp_window_steps]}" "parses totp_window_steps=3"

# 2. Malformed & command-injection descriptor rejection (never sourced/eval'd)
printf 'mfa_enabled=$(touch %s/PWNED_MFA)\n' "$SB" >"$SB/inj.conf"
mfa_parse_descriptor "$SB/inj.conf" 2>/dev/null && t_fail "command substitution in MFA descriptor rejected" || t_ok "command substitution in MFA descriptor rejected"
[[ ! -e $SB/PWNED_MFA ]] && t_ok "MFA descriptor never executed" || t_fail "MFA descriptor never executed"

printf 'evil_unknown_key=1\n' >"$SB/unk.conf"
mfa_parse_descriptor "$SB/unk.conf" 2>/dev/null && t_fail "unknown key in MFA descriptor rejected" || t_ok "unknown key in MFA descriptor rejected"

# 3. Recovery-code dataset streaming analysis
mfa_check_codes_file "$TEST_ROOT/fixtures/sample-recovery-codes.txt" 64
assert_eq 5 "$MFA_RC_TOTAL" "recovery codes total = 5"
assert_eq 5 "$MFA_RC_NONEMPTY" "recovery codes non-empty = 5"
assert_eq 4 "$MFA_RC_UNIQUE" "recovery codes unique = 4"
assert_eq 1 "$MFA_RC_DUPS" "recovery codes duplicate groups = 1"
assert_eq 8 "$MFA_RC_MIN_LEN" "recovery codes min clean length = 8 (1234-5678)"
[[ $MFA_RC_WEAK_COUNT -ge 1 ]] && t_ok "recovery codes flags low-entropy numeric code" || t_fail "weak recovery code detection"

t_summary
