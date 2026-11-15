#!/usr/bin/env bash
# shellcheck shell=bash disable=SC1091,SC2034
source "$(dirname "${BASH_SOURCE[0]}")/../lib/harness.sh"
sandbox

an --version; assert_eq 0 $RC "--version exits 0"; assert_contains "$OUT" "AUTHFORGE 0.1.0" "--version prints version"
an --help; assert_eq 0 $RC "--help exits 0"; assert_contains "$OUT" "Exit codes" "help documents exit codes"
an; assert_eq 2 $RC "no command + no TTY => usage error (2)"
an bogus; assert_eq 2 $RC "unknown command => 2"
an --nope; assert_eq 2 $RC "unknown option => 2"
an --profile; assert_eq 2 $RC "option missing its argument => 2"
an --fail-on SEVERE modules; assert_eq 2 $RC "invalid --fail-on => 2"
an -p nonexistent modules; assert_eq 3 $RC "unknown profile => config error (3)"
an -p '../../etc/passwd' modules; assert_eq 3 $RC "profile path traversal rejected (3)"
an -c "$SB/missing.conf" modules; assert_eq 3 $RC "missing config file => 3"
an modules; assert_eq 0 $RC "modules lists"; assert_contains "$OUT" "password" "password module registered"
assert_contains "$OUT" "hash" "hash module registered"
assert_contains "$OUT" "wordlist" "wordlist module registered"
assert_contains "$OUT" "risk" "risk module registered"
assert_contains "$OUT" "mfa" "mfa module registered"
assert_contains "$OUT" "session_sec" "session_sec module registered"
assert_contains "$OUT" "pwreset" "pwreset module registered"
assert_contains "$OUT" "auth_intel" "auth_intel module registered"
assert_contains "$OUT" "proto_audit" "proto_audit module registered"
assert_contains "$OUT" "web_auth" "web_auth module registered"
assert_contains "$OUT" "compliance" "compliance module registered"
assert_contains "$OUT" "evidence" "evidence module registered"
assert_not_contains "$OUT" "example_hello" "plugins disabled by default"

# colour: never emit ESC when not a TTY
an doctor; assert_not_contains "$OUT" $'\e' "no ANSI escapes when output is not a TTY"
an doctor; assert_eq 0 $RC "doctor passes on this platform"
assert_contains "$OUT" "bash 5" "doctor reports bash version"

# analyze: session artefacts, permissions, and B-1 plugin load logging
rm -rf "$AN_DATA_DIR/reports"/* "$AN_DATA_DIR/logs"/* "$AN_DATA_DIR/evidence"/*
an_stdin 'Summer2024!' -d password analyze
assert_eq 0 $RC "analyze exits 0"
assert_contains "$OUT" "variant" "analyze reports common-variant"
sid=$(ls "$AN_DATA_DIR/reports" | head -1)
assert_eq 700 "$(stat -c %a "$AN_DATA_DIR/reports/$sid")" "session report dir is 0700"
assert_eq 700 "$(stat -c %a "$AN_DATA_DIR/evidence/$sid")" "session evidence dir is 0700"
assert_eq 600 "$(stat -c %a "$AN_DATA_DIR/logs/$sid.log")" "session log is 0600"
assert_eq 600 "$(stat -c %a "$AN_DATA_DIR/reports/$sid/findings.dat")" "findings file is 0600"
assert_contains "$(<"$AN_DATA_DIR/logs/$sid.log")" "session started" "structured log written"
assert_contains "$(<"$AN_DATA_DIR/logs/$sid.log")" "registered module password" "REGRESSION B-1: module registration recorded in session log file"

an_stdin '' password analyze;           assert_eq 6 $RC "empty password => validation error (6)"
long=$(printf 'a%.0s' $(seq 1 1100))
an_stdin "$long" password analyze;      assert_eq 6 $RC "over-long input rejected (6)"
an password analyze;                    assert_eq 6 $RC "no stdin / no TTY => 'no input' validation error (6)"
an_stdin 'Zx9#kQ2!vLp7@wMn' password analyze extra; assert_eq 0 $RC "extra positional arg is ignored, never treated as a password"
assert_not_contains "$OUT$ERR" "extra" "extra arg is not echoed anywhere"
an password frobnicate;                 assert_eq 2 $RC "unknown password subcommand => 2"

# --fail-on threshold semantics
an_stdin 'password' --fail-on HIGH password analyze
assert_eq 10 $RC "--fail-on HIGH with common password => exit 10"
an_stdin 'Zx9#kQ2!vLp7@wMn' --fail-on HIGH password analyze
assert_eq 0 $RC "--fail-on HIGH with strong password => exit 0"
an_stdin 'password' password analyze
assert_eq 0 $RC "findings do not change exit code without --fail-on"

# policy-check across profiles
an_stdin 'Tr0ub4dor&3x' -p default password policy-check
assert_contains "$OUT" "[PASS] minimum length >= 12" "default profile: 12-char password passes length"
an_stdin 'Tr0ub4dor&3x' -p nist-aligned password policy-check
assert_contains "$OUT" "[FAIL] minimum length >= 15" "nist-aligned profile: 12 chars fails min 15"
an_stdin 'Tr0ub4dor&3x' -c "$SB/none.conf" password policy-check
assert_eq 3 $RC "bad -c path aborts policy-check"

# policy-review across profiles
an -p legacy-audit password policy-review
assert_contains "$OUT" "[FAIL] common-password blocklist disabled" "legacy profile review flags missing blocklist"
assert_contains "$OUT" "[FAIL] maximum length 16 is below 64" "legacy profile review flags low max length"
an -p nist-aligned password policy-review
assert_not_contains "$OUT" "[FAIL]" "nist-aligned profile review has no FAIL"

# check-file (fixture known: 7 entries, 4 common, 2 distinct reused covering 4)
an password check-file "$TEST_ROOT/fixtures/sample-passwords.txt"
assert_contains "$OUT" "Non-empty entries          7" "check-file counts entries"
assert_contains "$OUT" "4 entries match" "check-file counts common-password matches"
assert_contains "$OUT" "2 distinct value(s) reused, covering 4 entries" "check-file detects reuse"
assert_not_contains "$OUT" "Tr0ub4dor" "check-file never prints dataset secrets"
# CRLF check-file regression test
sed 's/$/\r/' "$TEST_ROOT/fixtures/sample-passwords.txt" >"$SB/crlf-pw.txt"
chmod 600 "$SB/crlf-pw.txt"
an password check-file "$SB/crlf-pw.txt"
assert_contains "$OUT" "4 entries match" "REGRESSION CRLF: check-file matches common passwords on CRLF input"
assert_contains "$OUT" "2 distinct value(s) reused, covering 4 entries" "REGRESSION CRLF: check-file detects reuse on CRLF input"

an password check-file "$SB/nope.txt"; assert_eq 6 $RC "check-file missing file => 6"
an password check-file; assert_eq 2 $RC "check-file without arg => 2"
ln -s "$TEST_ROOT/fixtures/sample-passwords.txt" "$SB/link.txt"
an password check-file "$SB/link.txt"; assert_eq 6 $RC "check-file refuses symlinks"

# generate
an password generate -l 30 -n 3; assert_eq 0 $RC "generate exits 0"
assert_eq 3 "$(printf '%s\n' "$OUT" | wc -l)" "generate -n 3 prints 3 lines"
assert_eq 30 "$(printf '%s\n' "$OUT" | head -1 | tr -d '\n' | wc -c)" "generate -l 30 honours length"
an password generate -l 3;   assert_eq 6 $RC "generate length <8 rejected"
an password generate -l abc; assert_eq 6 $RC "generate non-numeric length rejected"
an password generate -n 999; assert_eq 6 $RC "generate count >50 rejected"

# --- M1: Hash Intelligence Engine CLI
an hash help; assert_eq 0 $RC "hash help exits 0"
an hash bogus; assert_eq 2 $RC "unknown hash subcommand => 2"
an_stdin '' hash identify; assert_eq 6 $RC "empty hash => validation error (6)"
long_h=$(printf 'a%.0s' $(seq 1 2100))
an_stdin "$long_h" hash identify; assert_eq 6 $RC "over-long hash rejected (6)"
an hash identify; assert_eq 6 $RC "hash identify with no stdin => 6"
an_stdin '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQxMjM0NTY3OA$RdescudvJCsgt3ub+b+dWRWJTmaaJObG' hash identify extra_arg
assert_eq 0 $RC "hash identify Argon2id exits 0"
assert_contains "$OUT" "argon2id" "hash identify reports argon2id"
assert_contains "$OUT" "strong" "hash identify reports strong tier"
assert_not_contains "$OUT$ERR" "extra_arg" "hash extra positional arg ignored and never echoed"
assert_not_contains "$OUT$ERR" "RdescudvJCsgt3ub" "hash digest never printed to console"

an_stdin '5f4dcc3b5aa765d61d8327deb882cf99' --fail-on HIGH hash analyze
assert_eq 10 $RC "hash analyze raw MD5 with --fail-on HIGH => exit 10"
assert_contains "$OUT" "raw-md5-or-ntlm" "hash analyze identifies raw 32-hex"
assert_contains "$OUT" "yes (heuristic" "hash analyze flags ambiguity on raw 32-hex"

an_stdin '$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234' -p default hash policy-check
assert_contains "$OUT" "[FAIL] bcrypt cost >= 12 (observed 10)" "default profile fails bcrypt cost 10"
an_stdin '$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234' -p legacy-audit hash policy-check
assert_contains "$OUT" "[PASS] bcrypt cost >= 8 (observed 10)" "legacy-audit profile passes bcrypt cost 10"

an -p legacy-audit hash policy-review
assert_contains "$OUT" "[FAIL] legacy hash schemes permitted" "legacy-audit hash policy-review flags legacy allowed"
an -p nist-aligned hash policy-review
assert_not_contains "$OUT" "[FAIL]" "nist-aligned hash policy-review has no FAIL"

an hash check-file "$TEST_ROOT/fixtures/sample-hashes.txt"
assert_eq 0 $RC "hash check-file exits 0"
assert_contains "$OUT" "Non-empty entries          9" "hash check-file counts 9 non-empty entries"
assert_contains "$OUT" "1 distinct hash(es) reused, covering 2 entries" "hash check-file detects duplicate hash"
assert_not_contains "$OUT$ERR" "5f4dcc3b5aa765d61d8327deb882cf99" "hash check-file never prints raw hashes"
assert_not_contains "$OUT$ERR" "svc_locked" "hash check-file never prints shadow account names"
an hash check-file; assert_eq 2 $RC "hash check-file without arg => 2"
an hash check-file "$SB/no-hashes.txt"; assert_eq 6 $RC "hash check-file missing file => 6"
ln -s "$TEST_ROOT/fixtures/sample-hashes.txt" "$SB/hlink.txt"
an hash check-file "$SB/hlink.txt"; assert_eq 6 $RC "hash check-file refuses symlinks"

# --- M1: Wordlist Analytics Engine CLI
an wordlist help; assert_eq 0 $RC "wordlist help exits 0"
an wordlist bogus; assert_eq 2 $RC "unknown wordlist subcommand => 2"
an wordlist analyze "$TEST_ROOT/fixtures/sample-wordlist.txt"
assert_eq 0 $RC "wordlist analyze exits 0"
assert_contains "$OUT" "total=10 non-empty=10" "wordlist analyze reports line counts"
assert_contains "$OUT" "unique=8 reused_values=2 duplicate_entries=4" "wordlist analyze reports duplicates"
assert_not_contains "$OUT$ERR" "Winter2025" "wordlist analyze never prints wordlist entries"
an wordlist analyze; assert_eq 2 $RC "wordlist analyze without arg => 2"
an wordlist analyze "$SB/missing-wl.txt"; assert_eq 6 $RC "wordlist analyze missing file => 6"
ln -s "$TEST_ROOT/fixtures/sample-wordlist.txt" "$SB/wlink.txt"
an wordlist analyze "$SB/wlink.txt"; assert_eq 6 $RC "wordlist analyze refuses symlinks"

an wordlist compare "$TEST_ROOT/fixtures/sample-wordlist.txt" "$TEST_ROOT/fixtures/common-passwords-sample.txt"
assert_eq 0 $RC "wordlist compare exits 0"
assert_contains "$OUT" "Shared entries (overlap)     2" "wordlist compare finds 2 shared entries (password, 123456)"
assert_not_contains "$OUT$ERR" "dragon" "wordlist compare never prints entries"
an wordlist compare "$TEST_ROOT/fixtures/sample-wordlist.txt"; assert_eq 2 $RC "wordlist compare missing second arg => 2"

an wordlist clean "$TEST_ROOT/fixtures/sample-wordlist.txt" -o "$SB/clean-wl.txt" --min-length 8
assert_eq 0 $RC "wordlist clean exits 0"
assert_eq 600 "$(stat -c %a "$SB/clean-wl.txt")" "cleaned wordlist is 0600"
assert_eq 7 "$(wc -l <"$SB/clean-wl.txt" | tr -d ' ')" "cleaned wordlist has 7 unique entries >= 8 chars"
an wordlist clean "$TEST_ROOT/fixtures/sample-wordlist.txt" -o "$SB/clean-wl.txt"
assert_eq 6 $RC "wordlist clean refuses to overwrite existing output file"
an wordlist clean "$TEST_ROOT/fixtures/sample-wordlist.txt" -o "$SB/clean2.txt" --min-length 50 --max-length 10
assert_eq 6 $RC "wordlist clean rejects min-length > max-length"

# --- M3: Offline MFA, Session Security & Password Reset CLI
an mfa help; assert_eq 0 $RC "mfa help exits 0"
an mfa bogus; assert_eq 2 $RC "unknown mfa subcommand => 2"
an --fail-on HIGH mfa audit-config "$TEST_ROOT/fixtures/sample-mfa.conf"
assert_eq 10 $RC "mfa audit-config flags HIGH findings (--fail-on HIGH => 10)"
assert_contains "$OUT" "[COMPATIBILITY] TOTP uses HMAC-SHA1" "mfa audit-config distinguishes compatibility warning"
assert_contains "$OUT" "[REQUIREMENT] TOTP replay protection disabled" "mfa audit-config flags missing replay protection"
an -p nist-aligned mfa audit-config "$TEST_ROOT/fixtures/sample-mfa.conf"
assert_contains "$OUT" "[REQUIREMENT] Weak out-of-band MFA" "nist-aligned profile upgrades SMS fallback to requirement failure"
an --fail-on CRITICAL mfa audit-recovery "$TEST_ROOT/fixtures/sample-mfa.conf"
assert_eq 10 $RC "mfa audit-recovery flags CRITICAL plaintext recovery codes"
an mfa check-codes "$TEST_ROOT/fixtures/sample-recovery-codes.txt"
assert_eq 0 $RC "mfa check-codes exits 0"
assert_contains "$OUT" "duplicates=1" "mfa check-codes detects duplicate recovery code"
assert_not_contains "$OUT$ERR" "ABCD-EFGH" "mfa check-codes never prints recovery codes"
ln -s "$TEST_ROOT/fixtures/sample-mfa.conf" "$SB/mfalink.conf"
an mfa audit-config "$SB/mfalink.conf"; assert_eq 6 $RC "mfa audit-config refuses symlinks"

an session-audit help; assert_eq 0 $RC "session-audit help exits 0"
an session-audit bogus; assert_eq 2 $RC "unknown session-audit subcommand => 2"
an --fail-on CRITICAL session-audit analyze "$TEST_ROOT/fixtures/sample-session.conf"
assert_eq 10 $RC "session-audit analyze flags CRITICAL low session entropy"
assert_contains "$OUT" "[REQUIREMENT] Cookie Secure flag disabled" "session-audit flags missing Secure flag"
an_stdin 'Set-Cookie: sid=TopSecretCookie123456; Path=/; HttpOnly' session-audit check-cookie
assert_eq 0 $RC "session-audit check-cookie exits 0"
assert_contains "$OUT" "Missing Secure flag" "check-cookie flags missing Secure"
assert_not_contains "$OUT$ERR" "TopSecretCookie123456" "check-cookie never prints cookie value"

an pwreset help; assert_eq 0 $RC "pwreset help exits 0"
an pwreset bogus; assert_eq 2 $RC "unknown pwreset subcommand => 2"
an --fail-on CRITICAL pwreset analyze "$TEST_ROOT/fixtures/sample-pwreset.conf"
assert_eq 10 $RC "pwreset analyze flags CRITICAL plaintext password email"
assert_contains "$OUT" "[REQUIREMENT] Reset links trust HTTP Host header" "pwreset flags Host header poisoning"

# Verify M3 findings integrate with risk correlate (CORR-05, CORR-06)
rm -rf "$AN_DATA_DIR/reports"/* "$AN_DATA_DIR/logs"/* "$AN_DATA_DIR/evidence"/*
an mfa audit-config "$TEST_ROOT/fixtures/sample-mfa.conf"
an session-audit analyze "$TEST_ROOT/fixtures/sample-session.conf"
an pwreset analyze "$TEST_ROOT/fixtures/sample-pwreset.conf"
lat_m3=$(ls "$AN_DATA_DIR/reports" | sort | tail -1)
cat "$AN_DATA_DIR"/reports/*/findings.dat >"$SB/merged_m3.dat"
cp "$SB/merged_m3.dat" "$AN_DATA_DIR/reports/$lat_m3/findings.dat"
an risk correlate --session "$lat_m3"
assert_contains "$OUT" "CORR-05" "risk correlate detects CORR-05 (weak MFA + weak pwreset)"
assert_contains "$OUT" "CORR-06" "risk correlate detects CORR-06 (insecure session + MFA/pwreset)"

# --- M4: Fail-closed authorization, DNS pinning, budget propagation & loopback mock HTTP integration
an proto-audit http-auth http://127.0.0.1:18080/login; assert_eq 5 $RC "proto-audit refused without --allow-online"
an auth-intel scan http://127.0.0.1:18080/login;       assert_eq 5 $RC "auth-intel refused without --allow-online"
an web-auth headers http://127.0.0.1:18080/login;      assert_eq 5 $RC "web-auth refused without --allow-online"

# M4-AUD-05: Consistent IPv6 literal rejection on CLI
an --allow-online authz-check "::1"; assert_eq 6 $RC "M4-AUD-05: authz-check rejects ::1 with EX_VALIDATION (6)"
an --allow-online proto-audit tls "[::1]:443"; assert_eq 6 $RC "M4-AUD-05: proto-audit tls rejects [::1]:443 with EX_VALIDATION (6)"
an --allow-online web-auth headers "http://[::1]:18080/login"; assert_eq 6 $RC "M4-AUD-05: web-auth headers rejects bracketed IPv6 URL with EX_VALIDATION (6)"

# M4-P3: Ambiguous numeric IPv4 representations rejected on CLI with EX_VALIDATION (6)
for ambig_cli in "0177.0.0.1" "127.0.0.010" "127.1" "2130706433" "0x7f.0.0.1" "127.0.1" "0x7f000001"; do
  an --allow-online authz-check "$ambig_cli"
  assert_eq 6 $RC "M4-P3: authz-check rejects $ambig_cli with EX_VALIDATION (6)"
  an --allow-online proto-audit tls "${ambig_cli}:443"
  assert_eq 6 $RC "M4-P3: proto-audit tls rejects ${ambig_cli}:443 with EX_VALIDATION (6)"
  an --allow-online proto-audit http-auth "http://${ambig_cli}:8080/login"
  assert_eq 6 $RC "M4-P3: proto-audit http-auth rejects http://${ambig_cli}:8080/login with EX_VALIDATION (6)"
  an --allow-online auth-intel scan "http://${ambig_cli}:8080/login"
  assert_eq 6 $RC "M4-P3: auth-intel scan rejects http://${ambig_cli}:8080/login with EX_VALIDATION (6)"
  an --allow-online auth-intel oidc-check "http://${ambig_cli}:8080"
  assert_eq 6 $RC "M4-P3: auth-intel oidc-check rejects http://${ambig_cli}:8080 with EX_VALIDATION (6)"
  an --allow-online web-auth headers "http://${ambig_cli}:8080/login"
  assert_eq 6 $RC "M4-P3: web-auth headers rejects http://${ambig_cli}:8080/login with EX_VALIDATION (6)"
done

printf 'authorized_by=Lab Lead\ntarget=example.com\nexpires=2999-01-01\ntest_accounts_only=yes\n' >"$SB/pub_scope.txt"
an --allow-online --scope "$SB/pub_scope.txt" authz-check example.com; assert_eq 5 $RC "non-lab target refused when allow_nonlocal_targets=0"

if command -v socat >/dev/null 2>&1; then
  MOCK_PORT=18943
  cat >"$SB/mock_resp.txt" <<'HTTP'
HTTP/1.1 401 Unauthorized
Server: MockLab/1.0
WWW-Authenticate: Basic realm="Lab"
Set-Cookie: labsid=MockCookieSecret9988; Path=/; HttpOnly
Content-Length: 2

OK
HTTP
  socat -T 2 TCP-LISTEN:"$MOCK_PORT",bind=127.0.0.1,reuseaddr,fork SYSTEM:"cat '$SB/mock_resp.txt'" >/dev/null 2>&1 &
  MOCK_PID=$!
  sleep 0.3
  printf 'authorized_by=Lab Lead\ntarget=127.0.0.1\ntarget=localhost\ntarget=loopback.internal\ntarget=public.internal\ntarget=mixed.internal\ntarget=nxdomain.internal\nexpires=2999-01-01\ntest_accounts_only=yes\n' >"$SB/loop_scope.txt"

  an --allow-online --scope "$SB/loop_scope.txt" --fail-on CRITICAL proto-audit http-auth "http://127.0.0.1:$MOCK_PORT/login"
  assert_eq 10 $RC "proto-audit http-auth flags CRITICAL Basic-over-HTTP on loopback"
  assert_contains "$OUT" "Basic" "proto-audit reports Basic auth scheme"

  an --allow-online --scope "$SB/loop_scope.txt" auth-intel scan "http://127.0.0.1:$MOCK_PORT/login"
  assert_eq 0 $RC "auth-intel scan exits 0 on loopback"
  assert_contains "$OUT" "MockLab/1.0" "auth-intel reports Server header"

  an --allow-online --scope "$SB/loop_scope.txt" web-auth headers "http://127.0.0.1:$MOCK_PORT/login"
  assert_eq 0 $RC "web-auth headers exits 0 on loopback"
  assert_contains "$OUT" "Missing Content-Security-Policy" "web-auth flags missing CSP"

  an --allow-online --scope "$SB/loop_scope.txt" web-auth cookies "http://127.0.0.1:$MOCK_PORT/login"
  assert_eq 0 $RC "web-auth cookies exits 0 on loopback"
  assert_contains "$OUT" "labsid" "web-auth cookies reports cookie name"
  assert_not_contains "$OUT$ERR" "MockCookieSecret9988" "web-auth cookies never prints cookie value"

  rm -rf "$AN_DATA_DIR/logs"/*
  an --allow-online --scope "$SB/loop_scope.txt" web-auth rate-limit-check "http://127.0.0.1:$MOCK_PORT/login"
  assert_eq 0 $RC "web-auth rate-limit-check completes bounded 3-probe check"
  rl_sid=$(ls "$AN_DATA_DIR/logs" | head -1)
  authz_log_cnt=$(grep -c "online authorization verified for target" "$AN_DATA_DIR/logs/$rl_sid" || true)
  assert_eq 1 "$authz_log_cnt" "M4-AUD-03: multi-probe command logs authorization verification exactly once"

  # M4-AUD-01: Hostname pinning via curl --resolve and DNS refusal on public/mixed/NXDOMAIN records
  cat >"$SB/cli_dns.txt" <<'EOF'
loopback.internal 127.0.0.1
public.internal 93.184.216.34
mixed.internal 127.0.0.1 93.184.216.34
EOF
  export AN_DNS_FIXTURE_FILE="$SB/cli_dns.txt"

  an --allow-online --scope "$SB/loop_scope.txt" auth-intel scan "http://loopback.internal:$MOCK_PORT/login"
  assert_eq 0 $RC "M4-AUD-01: loopback.internal resolves and connects via curl --resolve"
  assert_contains "$OUT" "http://loopback.internal:$MOCK_PORT/login" "M4-AUD-01: preserves original hostname in URL/output"

  # M4-AUD-06: Caller-controlled proxy environment variables are ignored and request connects directly to pinned IP
  PROXY_PORT=18944
  cat >"$SB/proxy_resp.txt" <<'HTTP'
HTTP/1.1 200 OK
Server: EvilProxy/9.9
Content-Length: 2

NO
HTTP
  socat -T 2 TCP-LISTEN:"$PROXY_PORT",bind=127.0.0.1,reuseaddr,fork SYSTEM:"touch '$SB/proxy_hit'; cat '$SB/proxy_resp.txt'" >/dev/null 2>&1 &
  PROXY_PID=$!
  sleep 0.2
  export HTTP_PROXY="http://127.0.0.1:$PROXY_PORT" HTTPS_PROXY="http://127.0.0.1:$PROXY_PORT" ALL_PROXY="http://127.0.0.1:$PROXY_PORT"
  export http_proxy="http://127.0.0.1:$PROXY_PORT" https_proxy="http://127.0.0.1:$PROXY_PORT" all_proxy="http://127.0.0.1:$PROXY_PORT"
  an --allow-online --scope "$SB/loop_scope.txt" auth-intel scan "http://loopback.internal:$MOCK_PORT/login"
  unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
  kill "$PROXY_PID" 2>/dev/null || true
  wait "$PROXY_PID" 2>/dev/null || true
  assert_eq 0 $RC "M4-AUD-06: request succeeds directly to pinned IP despite proxy env vars"
  assert_contains "$OUT" "MockLab/1.0" "M4-AUD-06: response comes from pinned target, not proxy"
  assert_not_contains "$OUT" "EvilProxy" "M4-AUD-06: proxy response banner never observed"
  [[ ! -e "$SB/proxy_hit" ]] && t_ok "M4-AUD-06: zero connections made to caller-controlled proxy" || t_fail "M4-AUD-06: proxy was contacted"

  # M4-AUD-07: Missing timeout binary returns EX_DEPENDENCY (4) and reports explicit NOT TESTED message on CLI
  mkdir -p "$SB/notimeout_path"
  for cmd_bin in bash env awk sed grep tr cut sort uniq wc head tail cat cp mv ln flock od id rm mkdir chmod stat mktemp readlink realpath sha256sum date sleep find getent curl openssl; do
    p=$(command -v "$cmd_bin" 2>/dev/null || true)
    [[ -n $p ]] && ln -sf "$p" "$SB/notimeout_path/$cmd_bin"
  done
  SAVED_PATH=$PATH
  export PATH="$SB/notimeout_path"
  an --allow-online --scope "$SB/loop_scope.txt" proto-audit tls "127.0.0.1:$MOCK_PORT"
  export PATH=$SAVED_PATH
  assert_eq 4 $RC "M4-AUD-07: proto-audit tls returns EX_DEPENDENCY (4) when timeout is missing"
  assert_contains "$OUT" "[NOT TESTED] timeout not installed; TLS check skipped" "M4-AUD-07: clear NOT TESTED message when timeout is missing"

  # M4-P3: Missing curl binary returns EX_DEPENDENCY (4) and preserves NOT TESTED across all 6 curl-dependent commands
  mkdir -p "$SB/nocurl_path"
  for cmd_bin in bash env awk sed grep tr cut sort uniq wc head tail cat cp mv ln flock od id rm mkdir chmod stat mktemp readlink realpath sha256sum date sleep find getent timeout openssl; do
    p=$(command -v "$cmd_bin" 2>/dev/null || true)
    [[ -n $p ]] && ln -sf "$p" "$SB/nocurl_path/$cmd_bin"
  done
  unset AN_DNS_FIXTURE_FILE
  export PATH="$SB/nocurl_path"

  an --allow-online --scope "$SB/loop_scope.txt" proto-audit http-auth "http://localhost:$MOCK_PORT/login"
  assert_eq 4 $RC "M4-P3: proto-audit http-auth returns EX_DEPENDENCY (4) when curl is missing"
  assert_contains "$OUT" "[NOT TESTED] curl not installed; HTTP auth check skipped" "M4-P3: proto-audit http-auth preserves NOT TESTED message when curl is missing"

  an --allow-online --scope "$SB/loop_scope.txt" auth-intel scan "http://localhost:$MOCK_PORT/login"
  assert_eq 4 $RC "M4-P3: auth-intel scan returns EX_DEPENDENCY (4) when curl is missing"
  assert_contains "$OUT" "[NOT TESTED] curl not installed; auth-intel scan skipped" "M4-P3: auth-intel scan preserves NOT TESTED message when curl is missing"

  an --allow-online --scope "$SB/loop_scope.txt" auth-intel oidc-check "http://localhost:$MOCK_PORT"
  assert_eq 4 $RC "M4-P3: auth-intel oidc-check returns EX_DEPENDENCY (4) when curl is missing"
  assert_contains "$OUT" "[NOT TESTED] curl not installed; OIDC check skipped" "M4-P3: auth-intel oidc-check preserves NOT TESTED message when curl is missing"

  an --allow-online --scope "$SB/loop_scope.txt" web-auth headers "http://localhost:$MOCK_PORT/login"
  assert_eq 4 $RC "M4-P3: web-auth headers returns EX_DEPENDENCY (4) when curl is missing"
  assert_contains "$OUT" "[NOT TESTED] curl not installed; web-auth headers skipped" "M4-P3: web-auth headers preserves NOT TESTED message when curl is missing"

  an --allow-online --scope "$SB/loop_scope.txt" web-auth cookies "http://localhost:$MOCK_PORT/login"
  assert_eq 4 $RC "M4-P3: web-auth cookies returns EX_DEPENDENCY (4) when curl is missing"
  assert_contains "$OUT" "[NOT TESTED] curl not installed; web-auth cookies skipped" "M4-P3: web-auth cookies preserves NOT TESTED message when curl is missing"

  an --allow-online --scope "$SB/loop_scope.txt" web-auth rate-limit-check "http://localhost:$MOCK_PORT/login"
  assert_eq 4 $RC "M4-P3: web-auth rate-limit-check returns EX_DEPENDENCY (4) when curl is missing"
  assert_contains "$OUT" "[NOT TESTED] curl not installed; rate-limit check skipped" "M4-P3: web-auth rate-limit-check preserves NOT TESTED message when curl is missing"

  export PATH=$SAVED_PATH
  export AN_DNS_FIXTURE_FILE="$SB/cli_dns.txt"

  # M4-AUD-08: CLI TLS handshake failure vs valid negotiation tests (never reports PASS on failed/incomplete handshake)
  mkdir -p "$SB/tls_shim_bin"
  # 1. Timeout (exit 124) on CLI
  cat >"$SB/tls_shim_bin/timeout" <<'EOF'
#!/usr/bin/env bash
printf 'Connecting...\n'
exit 124
EOF
  chmod +x "$SB/tls_shim_bin/timeout"
  export PATH="$SB/tls_shim_bin:$SAVED_PATH"
  an --allow-online --scope "$SB/loop_scope.txt" proto-audit tls "127.0.0.1:$MOCK_PORT"
  export PATH=$SAVED_PATH
  assert_eq 0 $RC "M4-AUD-08: CLI proto-audit tls exits 0 with NOT TESTED on timeout (124)"
  assert_contains "$OUT" "[NOT TESTED] TLS handshake timed out" "M4-AUD-08: CLI reports TLS handshake timed out"
  assert_not_contains "$OUT" "[PASS]" "M4-AUD-08: timed-out TLS handshake never produces PASS"
  rm -f "$SB/tls_shim_bin/timeout"

  # 2. Connection refused (exit 1) on CLI
  cat >"$SB/tls_shim_bin/openssl" <<'EOF'
#!/usr/bin/env bash
printf 'connect:errno=111\n'
exit 1
EOF
  chmod +x "$SB/tls_shim_bin/openssl"
  export PATH="$SB/tls_shim_bin:$SAVED_PATH"
  an --allow-online --scope "$SB/loop_scope.txt" proto-audit tls "127.0.0.1:$MOCK_PORT"
  export PATH=$SAVED_PATH
  assert_contains "$OUT" "[NOT TESTED] unable to establish TLS handshake" "M4-AUD-08: CLI reports unable to establish TLS handshake on connection refused"
  assert_not_contains "$OUT" "[PASS]" "M4-AUD-08: connection-refused TLS probe never produces PASS"

  # 3. Non-empty output missing cipher on CLI
  cat >"$SB/tls_shim_bin/openssl" <<'EOF'
#!/usr/bin/env bash
printf 'CONNECTED(00000003)\nProtocol  : TLSv1.3\nCipher    : 0000\n'
exit 0
EOF
  chmod +x "$SB/tls_shim_bin/openssl"
  export PATH="$SB/tls_shim_bin:$SAVED_PATH"
  an --allow-online --scope "$SB/loop_scope.txt" proto-audit tls "127.0.0.1:$MOCK_PORT"
  export PATH=$SAVED_PATH
  assert_contains "$OUT" "[NOT TESTED] incomplete TLS negotiation" "M4-AUD-08: CLI reports incomplete TLS negotiation when cipher is missing/0000"
  assert_not_contains "$OUT" "[PASS]" "M4-AUD-08: incomplete TLS negotiation never produces PASS"

  # 4. Self-signed certificate with valid TLS 1.3 negotiation on CLI continues assessment
  cat >"$SB/tls_shim_bin/openssl" <<'EOF'
#!/usr/bin/env bash
printf 'CONNECTED(00000003)\ndepth=0 CN = loopback.internal\nverify error:num=18:self-signed certificate\nProtocol  : TLSv1.3\nCipher    : TLS_AES_256_GCM_SHA384\n'
exit 0
EOF
  chmod +x "$SB/tls_shim_bin/openssl"
  export PATH="$SB/tls_shim_bin:$SAVED_PATH"
  an --allow-online --scope "$SB/loop_scope.txt" proto-audit tls "127.0.0.1:$MOCK_PORT"
  export PATH=$SAVED_PATH
  assert_eq 0 $RC "M4-AUD-08: self-signed cert with valid TLS 1.3 negotiation completes assessment"
  assert_contains "$OUT" "[PASS] TLS protocol acceptable (TLSv1.3)" "M4-AUD-08: reports PASS for TLSv1.3 protocol with self-signed cert"
  assert_contains "$OUT" "[PASS] Cipher suite acceptable (TLS_AES_256_GCM_SHA384)" "M4-AUD-08: reports PASS for strong cipher with self-signed cert"
  assert_contains "$OUT" "[REVIEW] Self-signed certificate detected" "M4-AUD-08: reports REVIEW for self-signed cert"

  an --allow-online --scope "$SB/loop_scope.txt" web-auth headers "http://public.internal:$MOCK_PORT/login"
  assert_eq 5 $RC "M4-AUD-01: public DNS answer for .internal host refused with EX_AUTHZ (5)"
  assert_not_contains "$OUT" "NOT TESTED" "M4-AUD-01/02: DNS authz failure does not emit NOT TESTED"

  an --allow-online --scope "$SB/loop_scope.txt" web-auth headers "http://mixed.internal:$MOCK_PORT/login"
  assert_eq 5 $RC "M4-AUD-01: mixed private+public DNS answer refused with EX_AUTHZ (5)"

  an --allow-online --scope "$SB/loop_scope.txt" web-auth headers "http://nxdomain.internal:$MOCK_PORT/login"
  assert_eq 5 $RC "M4-AUD-01: NXDOMAIN DNS failure refused with EX_AUTHZ (5)"

  unset AN_DNS_FIXTURE_FILE

  # M4-AUD-02: Request-budget exhaustion propagates EX_AUTHZ (5) immediately and stops network calls
  printf 'max_online_requests=2\nmax_online_rps=50\n' >"$SB/budget2.conf"
  an -c "$SB/budget2.conf" --allow-online --scope "$SB/loop_scope.txt" web-auth rate-limit-check "http://127.0.0.1:$MOCK_PORT/login"
  assert_eq 5 $RC "M4-AUD-02: rate-limit-check aborts with EX_AUTHZ (5) when budget=2 exhausted on probe 3"
  assert_not_contains "$OUT" "No rate-limit headers" "M4-AUD-02: no heuristic finding emitted when aborted by budget exhaustion"

  printf 'max_online_requests=0\n' >"$SB/budget0.conf"
  an -c "$SB/budget0.conf" --allow-online --scope "$SB/loop_scope.txt" proto-audit tls "127.0.0.1:$MOCK_PORT"
  assert_eq 5 $RC "M4-AUD-02/08: proto-audit tls exits 5 (not 0/NOT TESTED) when budget=0"
  an -c "$SB/budget0.conf" --allow-online --scope "$SB/loop_scope.txt" proto-audit http-auth "http://127.0.0.1:$MOCK_PORT/login"
  assert_eq 5 $RC "M4-AUD-02: proto-audit http-auth exits 5 (not 0/NOT TESTED) when budget=0"
  an -c "$SB/budget0.conf" --allow-online --scope "$SB/loop_scope.txt" auth-intel scan "http://127.0.0.1:$MOCK_PORT/login"
  assert_eq 5 $RC "M4-AUD-02: auth-intel scan exits 5 (not 0/NOT TESTED) when budget=0"
  an -c "$SB/budget0.conf" --allow-online --scope "$SB/loop_scope.txt" web-auth cookies "http://127.0.0.1:$MOCK_PORT/login"
  assert_eq 5 $RC "M4-AUD-02: web-auth cookies exits 5 (not 0/NOT TESTED) when budget=0"

  # M4-P3: Safe launcher (scripts/authforge-safe.sh) regression tests
  SAFE_BIN="$TEST_ROOT/scripts/authforge-safe.sh"
  cat >"$SB/canary_be.sh" <<EOF
touch "$SB/canary_be_ran"
EOF
  rm -f "$SB/canary_be_ran"
  safe_out=$(BASH_ENV="$SB/canary_be.sh" ENV="$SB/canary_be.sh" "$SAFE_BIN" --no-color --version 2>&1)
  safe_rc=$?
  assert_eq 0 "$safe_rc" "M4-P3: direct execution of scripts/authforge-safe.sh --version exits 0"
  assert_contains "$safe_out" "AUTHFORGE 0.1.0" "M4-P3: scripts/authforge-safe.sh prints version"
  [[ ! -e "$SB/canary_be_ran" ]] && t_ok "M4-P3: direct execution of scripts/authforge-safe.sh prevents BASH_ENV execution" || t_fail "M4-P3: BASH_ENV ran on direct execution"

  # Verify documented limitation: invoking 'bash scripts/authforge-safe.sh' processes BASH_ENV in the outer bash before launcher starts
  rm -f "$SB/canary_be_ran"
  BASH_ENV="$SB/canary_be.sh" bash "$SAFE_BIN" --no-color --version >/dev/null 2>&1 || true
  [[ -e "$SB/canary_be_ran" ]] && t_ok "M4-P3: documented limitation confirmed (bash scripts/authforge-safe.sh processes outer BASH_ENV before launcher starts)" || t_fail "M4-P3: outer bash BASH_ENV check"

  rm -f "$SB/canary_be_ran"
  env -u BASH_ENV -u ENV bash "$SAFE_BIN" --no-color --version >/dev/null 2>&1
  assert_eq 0 $? "M4-P3: env -u BASH_ENV -u ENV bash scripts/authforge-safe.sh exits 0"
  [[ ! -e "$SB/canary_be_ran" ]] && t_ok "M4-P3: env -u BASH_ENV -u ENV bash scripts/authforge-safe.sh prevents BASH_ENV execution" || t_fail "M4-P3: BASH_ENV ran despite env -u"

  # Verify scripts/authforge-safe.sh scrubs proxy, linker, CDPATH, and hook variables while preserving CLI exit codes
  safe_scan_out=$(
    HTTP_PROXY="http://127.0.0.1:19999" HTTPS_PROXY="http://127.0.0.1:19999" ALL_PROXY="http://127.0.0.1:19999" \
    http_proxy="http://127.0.0.1:19999" https_proxy="http://127.0.0.1:19999" all_proxy="http://127.0.0.1:19999" \
    CDPATH="/tmp" PROMPT_COMMAND="touch '$SB/pwn_prompt'" OPENSSL_CONF="/nonexistent/openssl.cnf" CURL_HOME="/nonexistent" \
    "$SAFE_BIN" --no-color --allow-online --scope "$SB/loop_scope.txt" auth-intel scan "http://127.0.0.1:$MOCK_PORT/login" 2>&1
  )
  assert_eq 0 $? "M4-P3: scripts/authforge-safe.sh online scan succeeds with scrubbed environment"
  assert_contains "$safe_scan_out" "MockLab/1.0" "M4-P3: scripts/authforge-safe.sh online scan reaches loopback target directly"
  [[ ! -e "$SB/pwn_prompt" ]] && t_ok "M4-P3: scripts/authforge-safe.sh scrubs PROMPT_COMMAND" || t_fail "M4-P3: PROMPT_COMMAND executed"

  rc_safe_val=0
  "$SAFE_BIN" --no-color --allow-online authz-check "0177.0.0.1" >/dev/null 2>&1 || rc_safe_val=$?
  assert_eq 6 "$rc_safe_val" "M4-P3: scripts/authforge-safe.sh preserves EX_VALIDATION (6) on ambiguous numeric IPv4"

  kill "$MOCK_PID" 2>/dev/null || true
  wait "$MOCK_PID" 2>/dev/null || true
else
  t_skip "loopback mock HTTP tests" "socat not installed"
fi

# findings export (JSON, CSV, Markdown, TXT + unsupported format check)
an findings export --session 19990101-000000-abcdef; assert_eq 6 $RC "export unknown session => 6"
an findings export --session '../../x';              assert_eq 6 $RC "export rejects traversal in session id"
rm -rf "$AN_DATA_DIR/reports"/* "$AN_DATA_DIR/logs"/* "$AN_DATA_DIR/evidence"/*
an hash check-file "$TEST_ROOT/fixtures/sample-hashes.txt"
an findings export -o "$SB/out.json"; assert_eq 0 $RC "export to file"
assert_eq 600 "$(stat -c %a "$SB/out.json")" "exported report is 0600"
an findings export -o "$SB/out.json"; assert_eq 6 $RC "export refuses to overwrite"
an findings export --format csv -o "$SB/out.csv"; assert_eq 0 $RC "export CSV to file"
assert_eq 600 "$(stat -c %a "$SB/out.csv")" "exported CSV report is 0600"
assert_contains "$(<"$SB/out.csv")" "session,priority,score,id" "exported CSV contains header"
an findings export --format md -o "$SB/out.md"; assert_eq 0 $RC "export Markdown to file"
assert_eq 600 "$(stat -c %a "$SB/out.md")" "exported Markdown report is 0600"
assert_contains "$(<"$SB/out.md")" "# AUTHFORGE Security Assessment Report" "exported Markdown contains title"
an findings export --format txt -o "$SB/out.txt"; assert_eq 0 $RC "export TXT to file"
assert_eq 600 "$(stat -c %a "$SB/out.txt")" "exported TXT report is 0600"
an findings export --format xml; assert_eq 2 $RC "unsupported format is an explicit error (no silent fallback)"

# --- M2: Risk Intelligence Engine CLI
an risk help; assert_eq 0 $RC "risk help exits 0"
an risk bogus; assert_eq 2 $RC "unknown risk subcommand => 2"
an risk evaluate; assert_eq 0 $RC "risk evaluate exits 0"
assert_contains "$OUT" "AUTHFORGE RISK INTELLIGENCE REPORT" "risk evaluate prints report banner"
assert_contains "$OUT" "P2-HIGH" "risk evaluate prioritizes HIGH findings"
an risk prioritize; assert_eq 0 $RC "risk prioritize exits 0"
assert_contains "$OUT" "Prioritized remediation queue" "risk prioritize prints remediation queue"
an risk correlate; assert_eq 0 $RC "risk correlate exits 0"
assert_contains "$OUT" "CORR-03" "risk correlate detects hash reuse + unsalted correlation"
an risk report --format md -o "$SB/risk-report.md"; assert_eq 0 $RC "risk report --format md writes file"
assert_eq 600 "$(stat -c %a "$SB/risk-report.md")" "risk report file is 0600"
an risk report --format md -o "$SB/risk-report.md"; assert_eq 6 $RC "risk report refuses to overwrite existing file"
an risk report --format yaml; assert_eq 2 $RC "risk report rejects unsupported format"

# Suppression + manifest verification via CLI
an risk suppress AN-hash-001 --reason "Accepted legacy system during migration" --status risk_accepted
assert_eq 0 $RC "risk suppress exits 0"
an risk suppressions; assert_eq 0 $RC "risk suppressions lists active suppressions"
assert_contains "$OUT" "AN-hash-001" "suppressions output lists AN-hash-001"
assert_contains "$OUT" "risk_accepted" "suppressions output lists status"
an risk unsuppress AN-hash-001; assert_eq 0 $RC "risk unsuppress exits 0"
an risk unsuppress AN-hash-999; assert_eq 6 $RC "risk unsuppress unknown finding => 6"
an risk suppress AN-hash-001; assert_eq 2 $RC "risk suppress without --reason => 2"

an risk manifest; assert_eq 0 $RC "risk manifest exits 0"
assert_contains "$OUT" "findings.dat" "risk manifest includes findings.dat"
an risk verify; assert_eq 0 $RC "risk verify exits 0 on intact session"
an findings verify; assert_eq 0 $RC "findings verify exits 0 on intact session"
lat_sid=$(ls "$AN_DATA_DIR/reports" | head -1)
printf 'corrupt\n' >>"$AN_DATA_DIR/reports/$lat_sid/findings.dat"
an risk verify; assert_eq 6 $RC "risk verify exits 6 when findings.dat is tampered"
sed -i '$d' "$AN_DATA_DIR/reports/$lat_sid/findings.dat"
an risk verify; assert_eq 0 $RC "risk verify passes after restoring findings.dat"

# authz via CLI
an authz-check lab.example.test; assert_eq 5 $RC "authz-check refused by default"
printf 'authorized_by=T\ntarget=lab.example.test\nexpires=2999-01-01\ntest_accounts_only=yes\n' >"$SB/scope.txt"
an --allow-online --scope "$SB/scope.txt" authz-check lab.example.test; assert_eq 0 $RC "authz-check passes with valid scope"
an --allow-online --scope "$SB/scope.txt" authz-check evil.example.test; assert_eq 5 $RC "authz-check rejects out-of-scope target"

# verbosity
an_stdin 'password' -v password analyze; assert_contains "$ERR" "session started" "-v shows info logs on stderr"
an_stdin 'password' password analyze;    assert_not_contains "$ERR" "session started" "default hides info logs"
an_stdin 'password' -d password analyze; assert_contains "$ERR" "registered" "-d shows debug logs"

# config backup/restore (on an isolated clone so the repo is not mutated)
clone_repo
export AN_DATA_DIR="$SB/cdata"; mkdir -p "$AN_DATA_DIR"
AN_BIN=$CLONE_BIN
an config backup; assert_eq 0 $RC "config backup"; bdir=$OUT
assert_eq 700 "$(stat -c %a "$bdir")" "backup dir is 0700"
sed -i 's/^policy_min_length=.*/policy_min_length=99/' "$CLONE/config/authforge.conf"
an config restore "$bdir"; assert_eq 0 $RC "config restore"
assert_contains "$(<"$CLONE/config/authforge.conf")" "policy_min_length=12" "restore reverted the modification"
assert_contains "$(<"$bdir/authforge.conf")" "policy_min_length=12" "REGRESSION: restore does not clobber the backup it restores from"
assert_eq 2 "$(ls "$AN_DATA_DIR/backups" | wc -l)" "same-second backup + restore safety copy get distinct directories"
an config restore /etc; assert_eq 6 $RC "restore outside backups dir rejected"
printf 'policy_min_length=$(evil)\n' >"$bdir/authforge.conf"
before=$(<"$CLONE/config/authforge.conf")
an config restore "$bdir"; assert_eq 3 $RC "restore of tampered backup rejected"
assert_eq "$before" "$(<"$CLONE/config/authforge.conf")" "tampered restore left config unchanged"
an config validate; assert_eq 0 $RC "config validate passes on shipped files"

# plugin loader safety (clone)
chmod 666 "$CLONE/modules/password.sh"
an modules; assert_not_contains "$OUT" "password" "world-writable module refused"
assert_contains "$ERR" "unsafe file" "refusal is logged as a warning"
chmod 644 "$CLONE/modules/password.sh"
mv "$CLONE/modules/password.sh" "$SB/real_password.sh"; ln -s "$SB/real_password.sh" "$CLONE/modules/password.sh"
an modules; assert_not_contains "$OUT" "password" "symlinked module refused"
rm "$CLONE/modules/password.sh"; mv "$SB/real_password.sh" "$CLONE/modules/password.sh"
printf 'plugins_enabled=1\n' >"$SB/plug.conf"
an -c "$SB/plug.conf" modules; assert_contains "$OUT" "example_hello" "plugins load when explicitly enabled"
printf '#!/usr/bin/env bash\nmod_bad_info() { :; }\n' >"$CLONE/plugins/bad.sh"
an -c "$SB/plug.conf" modules; assert_contains "$ERR" "missing function" "plugin violating contract is rejected"

# --- M5-P1: Compliance Assessment & Evidence Management CLI integration
an compliance help; assert_eq 0 $RC "compliance help exits 0"
an compliance bogus; assert_eq 2 $RC "unknown compliance subcommand => 2"
an compliance catalog; assert_eq 0 $RC "compliance catalog exits 0"
assert_contains "$OUT" "40 controls" "compliance catalog lists 40 controls"
an compliance catalog --framework NIST; assert_eq 0 $RC "compliance catalog --framework NIST exits 0"
assert_contains "$OUT" "11 controls" "compliance catalog NIST lists 11 controls"
an compliance catalog --framework BOGUS; assert_eq 2 $RC "compliance catalog invalid framework => 2"

rm -rf "$AN_DATA_DIR/reports"/* "$AN_DATA_DIR/logs"/* "$AN_DATA_DIR/evidence"/*
an -p legacy-audit password policy-review
an compliance evaluate
assert_eq 0 $RC "compliance evaluate exits 0"
assert_contains "$OUT" "v5.0.0-6.2.4" "compliance evaluate includes ASVS v5.0.0-6.2.4"
assert_contains "$OUT" "Sec.3.1.1.2" "compliance evaluate includes NIST Sec.3.1.1.2"
an compliance gaps --framework ASVS
assert_eq 0 $RC "compliance gaps --framework ASVS exits 0"
an compliance export --format json -o "$SB/comp.json"
assert_eq 0 $RC "compliance export JSON to file exits 0"
assert_eq 600 "$(stat -c %a "$SB/comp.json")" "exported compliance JSON is 0600"
an compliance export --format json -o "$SB/comp.json"
assert_eq 6 $RC "compliance export refuses to overwrite existing file"

an evidence help; assert_eq 0 $RC "evidence help exits 0"
an evidence bogus; assert_eq 2 $RC "unknown evidence subcommand => 2"
an evidence list; assert_eq 0 $RC "evidence list exits 0"
assert_contains "$OUT" "password:policy-review" "evidence list shows recorded check in checks.dat"
an evidence manifest; assert_eq 0 $RC "evidence manifest exits 0"
assert_contains "$OUT" "checks.dat" "evidence manifest includes checks.dat"
an evidence verify; assert_eq 0 $RC "evidence verify exits 0"
an evidence bundle -o "$SB/ev-bundle.tar.gz"; assert_eq 0 $RC "evidence bundle creates tar.gz"
assert_eq 600 "$(stat -c %a "$SB/ev-bundle.tar.gz")" "evidence bundle is 0600"
an evidence bundle -o "$SB/ev-bundle.tar.gz"; assert_eq 6 $RC "evidence bundle refuses to overwrite existing file"
an evidence verify-bundle "$SB/ev-bundle.tar.gz"; assert_eq 0 $RC "evidence verify-bundle passes on exported bundle"

# Blocker 3 CLI regression: normal M0-M4 CLI and compliance/evidence commands work without tar or find in PATH,
# while evidence bundle / verify-bundle fail closed with EX_DEPENDENCY (4) when tar is missing
mkdir -p "$SB/notar_cli_path"
for cmd_bin in bash env awk sed grep tr cut sort uniq wc head tail cat cp mv ln flock od id rm mkdir chmod stat mktemp readlink realpath sha256sum date; do
  p=$(command -v "$cmd_bin" 2>/dev/null || true)
  [[ -n $p ]] && ln -sf "$p" "$SB/notar_cli_path/$cmd_bin"
done
SAVED_CLI_PATH=$PATH
export PATH="$SB/notar_cli_path"
an -p default password policy-review
assert_eq 0 $RC "Blocker 3 CLI: password policy-review succeeds without tar or find in PATH"
an compliance evaluate
assert_eq 0 $RC "Blocker 3 CLI: compliance evaluate succeeds without tar or find in PATH"
an evidence verify
assert_eq 0 $RC "Blocker 3 CLI: evidence verify succeeds without tar or find in PATH"
an evidence bundle -o "$SB/notar-out.tar.gz"
assert_eq 4 $RC "Blocker 3 CLI: evidence bundle returns EX_DEPENDENCY (4) when tar is missing"
an evidence verify-bundle "$SB/ev-bundle.tar.gz"
assert_eq 4 $RC "Blocker 3 CLI: evidence verify-bundle returns EX_DEPENDENCY (4) when tar is missing"
export PATH=$SAVED_CLI_PATH

# --- M5-P2: CLI Installation & Uninstallation integration
CLI_INST_HOME="$SB/cli_inst_home"
mkdir -p "$CLI_INST_HOME"
chmod 700 "$CLI_INST_HOME"
HOME="$CLI_INST_HOME" "$TEST_ROOT/scripts/install.sh" --dry-run >/dev/null 2>&1
assert_eq 0 $? "M5-P2 CLI: scripts/install.sh --dry-run exits 0"
HOME="$CLI_INST_HOME" "$TEST_ROOT/scripts/install.sh" >/dev/null 2>&1
assert_eq 0 $? "M5-P2 CLI: scripts/install.sh user-local install exits 0"
HOME="$CLI_INST_HOME" AN_DATA_DIR="" "$CLI_INST_HOME/.local/bin/authforge" --no-color doctor >/dev/null 2>&1
assert_eq 0 $? "M5-P2 CLI: installed launcher passes doctor with separated AN_DATA_DIR"
HOME="$CLI_INST_HOME" "$TEST_ROOT/scripts/uninstall.sh" >/dev/null 2>&1
assert_eq 0 $? "M5-P2 CLI: scripts/uninstall.sh exits 0 and preserves user data"
[[ -d "$CLI_INST_HOME/.local/state/authforge" ]] && t_ok "M5-P2 CLI: user state dir preserved on default uninstall" || t_fail "M5-P2 CLI: user state dir missing"

t_summary
