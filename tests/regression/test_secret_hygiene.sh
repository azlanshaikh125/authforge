#!/usr/bin/env bash
# shellcheck shell=bash disable=SC1091,SC2034
# Regression suite for the core promise: secrets, hashes, tokens, and recovery codes never leak.
source "$(dirname "${BASH_SOURCE[0]}")/../lib/harness.sh"
sandbox

SECRET='Zq7!UniqueMarker9xK'
VARIANT_SECRET='Summer2024!UniqueTail'
HASH_BCRYPT='$2b$08$UniqueBcryptSalt99999uUniqueBcryptDigest0123456789012'
HASH_ARGON2='$argon2id$v=19$m=8192,t=1,p=1$VW5pcXVlQXJnb25TYWx0$VW5pcXVlQXJnb25EaWdlc3Q'
HASH_RAW_HEX='deadbeefcafe1234deadbeefcafe5678'
SHADOW_LINE="secretuser99:${HASH_BCRYPT}:19700:0:99999:7:::"
WL_MARKER='UltraSecretWordlistEntry_9942!'
SUP_SECRET='SuppressionLeakToken_7711'
RC_MARKER='SecretRecovCode_8844!'
COOKIE_TOKEN='CookieSecretVal_9933!'

printf '%s\n%s\n' "$SHADOW_LINE" "$HASH_RAW_HEX" >"$SB/hashes.txt"
chmod 600 "$SB/hashes.txt"
printf '%s\n%s\nSecondWord_8821#\n' "$WL_MARKER" "$WL_MARKER" >"$SB/wordlist.txt"
chmod 600 "$SB/wordlist.txt"
printf '%s\n%s\n' "$RC_MARKER" "AnotherCode_1122!" >"$SB/rcodes.txt"
chmod 600 "$SB/rcodes.txt"

# 1. No secret, hash, cookie token, or recovery code in stdout/stderr/logs/findings/reports
for flags in "" "-v" "-d"; do
  # shellcheck disable=SC2086
  an_stdin "$SECRET" $flags password analyze
  assert_not_contains "$OUT$ERR" "$SECRET" "secret absent from console output (flags='$flags')"
  # shellcheck disable=SC2086
  an_stdin "$HASH_BCRYPT" $flags hash identify
  assert_not_contains "$OUT$ERR" "UniqueBcryptSalt" "bcrypt hash absent from console output (flags='$flags')"
  # shellcheck disable=SC2086
  an_stdin "$HASH_ARGON2" $flags hash policy-check
  assert_not_contains "$OUT$ERR" "VW5pcXVlQXJnb25" "argon2 hash absent from policy-check output (flags='$flags')"
  # shellcheck disable=SC2086
  an_stdin "Set-Cookie: mysid=$COOKIE_TOKEN; Path=/; HttpOnly" $flags session-audit check-cookie
  assert_not_contains "$OUT$ERR" "$COOKIE_TOKEN" "cookie token absent from console output (flags='$flags')"
done
an_stdin "$SECRET" password policy-check
assert_not_contains "$OUT$ERR" "$SECRET" "secret absent from policy-check output"

an -d hash check-file "$SB/hashes.txt"
assert_not_contains "$OUT$ERR" "secretuser99" "shadow username absent from hash check-file output"
assert_not_contains "$OUT$ERR" "UniqueBcryptSalt" "bcrypt hash absent from hash check-file output"
assert_not_contains "$OUT$ERR" "$HASH_RAW_HEX" "raw hex hash absent from hash check-file output"

an -d wordlist analyze "$SB/wordlist.txt"
assert_not_contains "$OUT$ERR" "$WL_MARKER" "wordlist entry absent from wordlist analyze output"
an -d wordlist compare "$SB/wordlist.txt" "$TEST_ROOT/fixtures/common-passwords-sample.txt"
assert_not_contains "$OUT$ERR" "$WL_MARKER" "wordlist entry absent from wordlist compare output"

an -d mfa check-codes "$SB/rcodes.txt"
assert_not_contains "$OUT$ERR" "$RC_MARKER" "recovery code absent from mfa check-codes output"

# M2: Risk evaluation, suppression redaction, and multi-format exports never leak secrets
an_stdin "$HASH_BCRYPT" hash identify
an risk suppress AN-hash-001 --reason "Legacy test password=$SUP_SECRET"
an risk evaluate
assert_not_contains "$OUT$ERR" "UniqueBcryptSalt" "bcrypt hash absent from risk evaluate output"
assert_not_contains "$OUT$ERR" "$SUP_SECRET" "secret inside suppression reason redacted in risk evaluate"
for fmt in json csv md txt; do
  an risk report --format "$fmt" -o "$SB/rep.$fmt"
  assert_file_not_contains "$SB/rep.$fmt" "UniqueBcryptSalt" "bcrypt hash absent from exported $fmt report"
  assert_file_not_contains "$SB/rep.$fmt" "$SUP_SECRET" "suppression secret absent from exported $fmt report"
done

assert_file_not_contains "$AN_DATA_DIR" "$SECRET" "secret absent from every file under data dir (logs/reports/evidence)"
assert_file_not_contains "$AN_DATA_DIR" "UniqueMarker9xK" "partial secret absent from data dir"
assert_file_not_contains "$AN_DATA_DIR" "UniqueBcryptSalt" "bcrypt hash absent from data dir"
assert_file_not_contains "$AN_DATA_DIR" "VW5pcXVlQXJnb25" "argon2 hash absent from data dir"
assert_file_not_contains "$AN_DATA_DIR" "$HASH_RAW_HEX" "raw hex hash absent from data dir"
assert_file_not_contains "$AN_DATA_DIR" "secretuser99" "shadow username absent from data dir"
assert_file_not_contains "$AN_DATA_DIR" "$WL_MARKER" "wordlist entry absent from data dir"
assert_file_not_contains "$AN_DATA_DIR" "$SUP_SECRET" "suppression secret absent from data dir"
assert_file_not_contains "$AN_DATA_DIR" "$RC_MARKER" "recovery code absent from data dir"
assert_file_not_contains "$AN_DATA_DIR" "$COOKIE_TOKEN" "cookie token absent from data dir"

# 2. Secrets absent from the private temp dir after exit (cleanup) and nothing left behind
left=$(find "$SB/tmp" -mindepth 1 | head -1)
assert_eq "" "$left" "no temp files left behind after normal runs"

# 3. Secret/hash/wordlist/recovery-code/cookie never appears on any subprocess command line (visible via ps)
mkdir -p "$SB/shim"
shim_log=$SB/argv.log
: >"$shim_log"
for c in awk sed grep sort uniq tr head wc od cat date stat mktemp sha256sum; do
  real=$(command -v "$c")
  printf '#!/bin/bash\nprintf "%%s\\0" "$@" >>"%s"\nexec "%s" "$@"\n' "$shim_log" "$real" >"$SB/shim/$c"
  chmod +x "$SB/shim/$c"
done
PATH="$SB/shim:$PATH" bash -c "printf '%s\n' '$SECRET' | '$AN_BIN' password analyze" >/dev/null 2>&1
PATH="$SB/shim:$PATH" bash -c "printf '%s\n' '$VARIANT_SECRET' | '$AN_BIN' password policy-check" >/dev/null 2>&1
PATH="$SB/shim:$PATH" bash -c "printf '%s\n' '$HASH_BCRYPT' | '$AN_BIN' hash identify" >/dev/null 2>&1
PATH="$SB/shim:$PATH" bash -c "printf '%s\n' '$HASH_ARGON2' | '$AN_BIN' hash policy-check" >/dev/null 2>&1
PATH="$SB/shim:$PATH" "$AN_BIN" hash check-file "$SB/hashes.txt" >/dev/null 2>&1
PATH="$SB/shim:$PATH" "$AN_BIN" wordlist analyze "$SB/wordlist.txt" >/dev/null 2>&1
PATH="$SB/shim:$PATH" "$AN_BIN" mfa check-codes "$SB/rcodes.txt" >/dev/null 2>&1
PATH="$SB/shim:$PATH" bash -c "printf 'Set-Cookie: mysid=%s; Path=/\n' '$COOKIE_TOKEN' | '$AN_BIN' session-audit check-cookie" >/dev/null 2>&1
PATH="$SB/shim:$PATH" "$AN_BIN" risk evaluate >/dev/null 2>&1
[[ -s $shim_log ]] && t_ok "argv shim recorded subprocess calls (test is not vacuous)" || t_fail "argv shim recorded nothing"
assert_file_not_contains "$shim_log" "UniqueMarker9xK" "secret never passed on any subprocess argv"
assert_file_not_contains "$shim_log" "UniqueTail" "variant secret never passed on any subprocess argv"
assert_file_not_contains "$shim_log" "UniqueBcryptSalt" "bcrypt hash never passed on any subprocess argv"
assert_file_not_contains "$shim_log" "VW5pcXVlQXJnb25" "argon2 hash never passed on any subprocess argv"
assert_file_not_contains "$shim_log" "$HASH_RAW_HEX" "raw hex hash never passed on any subprocess argv"
assert_file_not_contains "$shim_log" "$WL_MARKER" "wordlist entry never passed on any subprocess argv"
assert_file_not_contains "$shim_log" "$RC_MARKER" "recovery code never passed on any subprocess argv"
assert_file_not_contains "$shim_log" "$COOKIE_TOKEN" "cookie token never passed on any subprocess argv"

# 4. Findings records contain only metadata, never the value
an_stdin "$SECRET" --fail-on INFO password analyze
an findings export
assert_not_contains "$OUT" "UniqueMarker9xK" "JSON export contains no password secret"
an_stdin "$HASH_BCRYPT" --fail-on INFO hash identify
an findings export
assert_not_contains "$OUT" "UniqueBcryptSalt" "JSON export contains no hash value"

# 5. Logger redaction is enforced even if a caller mistakes (including M1 hashes & M3 tokens)
(
  load_core
  session_init
  log_warn "debug dump password=hunter2hunter2 token=abcdefTOKEN phc=$HASH_ARGON2 hex=$HASH_RAW_HEX recovery_code=$RC_MARKER"
  grep -q hunter2hunter2 "$AN_LOG_FILE" && echo LEAK >"$SB/leak" || echo clean >"$SB/leak"
  grep -q abcdefTOKEN "$AN_LOG_FILE" && echo LEAK >>"$SB/leak" || echo clean >>"$SB/leak"
  grep -q VW5pcXVlQXJnb25 "$AN_LOG_FILE" && echo LEAK >>"$SB/leak" || echo clean >>"$SB/leak"
  grep -q "$HASH_RAW_HEX" "$AN_LOG_FILE" && echo LEAK >>"$SB/leak" || echo clean >>"$SB/leak"
  grep -q "$RC_MARKER" "$AN_LOG_FILE" && echo LEAK >>"$SB/leak" || echo clean >>"$SB/leak"
) 2>/dev/null
assert_eq "clean clean clean clean clean" "$(tr '\n' ' ' <"$SB/leak" | sed 's/ $//')" "log file redacts secrets, M1 hashes, and M3 recovery codes passed by mistake"

# 6. Debug mode never enables xtrace (would print expanded secrets)
an_stdin "$SECRET" -d password analyze
assert_not_contains "$ERR" "+ " "debug mode does not enable set -x style tracing"
an_stdin "$HASH_BCRYPT" -d hash identify
assert_not_contains "$ERR" "+ " "hash debug mode does not enable set -x style tracing"

# 7. Exit-time cleanup on SIGTERM: process exits 130, temp dir removed
mkfifo "$SB/in"
"$AN_BIN" password analyze <"$SB/in" >/dev/null 2>&1 &
pid=$!
exec 3>"$SB/in"
sleep 1
had=$(find "$SB/tmp" -maxdepth 1 -name 'authforge.*' | wc -l)
kill -TERM "$pid"
wait "$pid"; rc=$?
exec 3>&-
assert_eq 1 "$had" "private temp dir existed while running"
assert_eq 130 "$rc" "SIGTERM -> graceful exit code 130"
assert_eq 0 "$(find "$SB/tmp" -maxdepth 1 -name 'authforge.*' | wc -l)" "temp dir removed after interruption"

t_summary
