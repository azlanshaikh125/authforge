#!/usr/bin/env bash
# shellcheck shell=bash disable=SC1091,SC2034
# TUI test through a real pseudo-terminal (util-linux `script`).
# Timing-based by nature (keystrokes are paced with short sleeps).
source "$(dirname "${BASH_SOURCE[0]}")/../lib/harness.sh"
sandbox
if ! command -v script >/dev/null; then t_skip "TUI pty tests" "util-linux 'script' not installed"; t_summary; exit; fi

export TERM=xterm
SECRET='TuiSecret!9zQ'
HASH_SECRET='$2b$10$TuiHashSalt9999999999uABCDEFGHIJKLMNOPQRSTUVWXYZ01234'
{ sleep 1
  printf '01\n'; sleep 0.6; printf 'b\n'; sleep 0.5
  printf '02\n'; sleep 0.6; printf '1\n'; sleep 0.6; printf '%s\n' "$SECRET"; sleep 0.6
  printf '\n'; sleep 0.4; printf 'b\n'; sleep 0.5
  printf '03\n'; sleep 0.6; printf '1\n'; sleep 0.6; printf '%s\n' "$HASH_SECRET"; sleep 0.6
  printf '\n'; sleep 0.4; printf 'b\n'; sleep 0.5
  printf '04\n'; sleep 0.6; printf 'b\n'; sleep 0.5
  printf '05\n'; sleep 0.6; printf 'b\n'; sleep 0.5
  printf '06\n'; sleep 0.6; printf 'b\n'; sleep 0.5
  printf '07\n'; sleep 0.6; printf 'b\n'; sleep 0.5
  printf '08\n'; sleep 0.6; printf 'b\n'; sleep 0.5
  printf '09\n'; sleep 0.6; printf 'b\n'; sleep 0.5
  printf '10\n'; sleep 0.6; printf '1\n'; sleep 0.5; printf '\n'; sleep 0.6; printf '\n'; sleep 0.4; printf 'b\n'; sleep 0.5
  printf '13\n'; sleep 0.6; printf 'b\n'; sleep 0.5
  printf '99\n'; sleep 0.4; printf '\n'; sleep 0.4
  printf '14\n'; sleep 1.2; printf '\n'; sleep 0.4; printf 'q\n'; sleep 0.8; } |
  script -qec "stty cols 100 rows 40; '$AN_BIN' menu" /dev/null >"$SB/raw" 2>&1
rc=$?
txt=$(sed -e 's/\x1b\[[0-9;?]*[a-zA-Z]//g' -e 's/\r//g' "$SB/raw" | LC_ALL=C tr -cd '\11\12\40-\176')

assert_eq 0 "$rc" "menu exits 0 on quit"
assert_contains "$txt" "ENTERPRISE SECURITY ENGINE" "banner rendered"
assert_contains "$txt" "[01] Authentication Intelligence" "main menu lists Authentication Intelligence"
assert_contains "$txt" "[06] Authentication Protocol Audit" "main menu lists Protocol Audit"
assert_contains "$txt" "[09] Web Authentication Assessment" "main menu lists Web Auth Assessment"
assert_contains "$txt" "[11] Compliance Assessment" "main menu lists Compliance Assessment"
assert_contains "$txt" "[12] Evidence Management" "main menu lists Evidence Management"
assert_not_contains "$txt" "[planned M5]" "completed M5 entries and footer no longer show planned M5"
assert_contains "$txt" "AUTHENTICATION INTELLIGENCE" "submenu 01 reachable"
assert_contains "$txt" "AUTHENTICATION PROTOCOL AUDIT" "submenu 06 reachable"
assert_contains "$txt" "WEB AUTHENTICATION ASSESSMENT" "submenu 09 reachable"
assert_contains "$txt" "PASSWORD SECURITY ENGINE" "password submenu (02) reachable"
assert_contains "$txt" "Estimated entropy" "password analysis runs inside the TUI"
assert_contains "$txt" "HASH INTELLIGENCE ENGINE" "hash submenu (03) reachable"
assert_contains "$txt" "Identified format" "hash analysis runs inside the TUI"
assert_contains "$txt" "RISK INTELLIGENCE ENGINE" "risk submenu (10) reachable"
assert_contains "$txt" "AUTHFORGE RISK INTELLIGENCE REPORT" "risk evaluation runs inside the TUI"
assert_contains "$txt" "Invalid selection" "invalid input handled gracefully"
assert_contains "$txt" "Summary: 0 failure(s)" "diagnostics reachable from menu (14)"
assert_not_contains "$txt" "$SECRET" "typed secret is never echoed to the terminal"
assert_not_contains "$txt" "TuiSecret" "no fragment of the secret echoed"
assert_not_contains "$txt" "TuiHashSalt9999999999u" "typed hash is never echoed to the terminal"

# M4-AUD-02: Verify EX_AUTHZ (5) propagates through TUI menu when request budget is exhausted
printf 'authorized_by=TUI Test\ntarget=127.0.0.1\nexpires=2999-01-01\ntest_accounts_only=yes\n' >"$SB/tui_scope.txt"
printf 'max_online_requests=0\n' >"$SB/tui_budget0.conf"
{ sleep 0.8
  printf '09\n'; sleep 0.5
  printf '1\n'; sleep 0.5
  printf 'http://127.0.0.1:18080/login\n'; sleep 0.6; } |
  script -qec "stty cols 100 rows 40; '$AN_BIN' -c '$SB/tui_budget0.conf' --allow-online --scope '$SB/tui_scope.txt' menu" /dev/null >"$SB/raw_authz" 2>&1
rc_tui_authz=$?
assert_eq 5 "$rc_tui_authz" "M4-AUD-02: TUI menu propagates EX_AUTHZ (5) on request-budget exhaustion"

# M4-P3: Verify EX_DEPENDENCY (4) propagates through TUI menu when curl is missing
mkdir -p "$SB/tui_nocurl_bin"
for cmd_bin in bash sh stty env awk sed grep tr cut sort uniq wc head tail cat cp od id rm mkdir chmod stat mktemp readlink realpath sha256sum date sleep find getent timeout openssl tput; do
  p=$(command -v "$cmd_bin" 2>/dev/null || true)
  [[ -n $p ]] && ln -sf "$p" "$SB/tui_nocurl_bin/$cmd_bin"
done
{ sleep 0.8
  printf '09\n'; sleep 0.5
  printf '1\n'; sleep 0.5
  printf 'http://127.0.0.1:18080/login\n'; sleep 0.6; } |
  script -qec "export PATH='$SB/tui_nocurl_bin'; stty cols 100 rows 40; '$AN_BIN' --allow-online --scope '$SB/tui_scope.txt' menu" /dev/null >"$SB/raw_nocurl" 2>&1
rc_tui_nocurl=$?
txt_nocurl=$(sed -e 's/\x1b\[[0-9;?]*[a-zA-Z]//g' -e 's/\r//g' "$SB/raw_nocurl" | LC_ALL=C tr -cd '\11\12\40-\176')
assert_eq 4 "$rc_tui_nocurl" "M4-P3: TUI menu propagates EX_DEPENDENCY (4) when curl is missing"
assert_contains "$txt_nocurl" "curl not installed; web-auth headers skipped" "M4-P3: TUI menu displays NOT TESTED explanation when curl is missing"

t_summary
