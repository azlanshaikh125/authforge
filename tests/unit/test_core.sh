#!/usr/bin/env bash
# shellcheck shell=bash disable=SC1091,SC2034,SC2154  # SC2154: assoc-array keys are false positives
source "$(dirname "${BASH_SOURCE[0]}")/../lib/harness.sh"
sandbox
load_core
tmp_init
trap 'tmp_cleanup; rm -rf "$SB"' EXIT

# --- strutil
assert_eq "a b" "$(str_trim "   a b  ")" "str_trim strips both ends"
assert_eq 'a\"b\\c\nd' "$(json_escape $'a"b\\c\nd')" "json_escape quotes, backslash, newline"
assert_eq "a b c" "$(field_clean $'a\tb\x1fc')" "field_clean removes record separators"
assert_eq "-----" "$(str_repeat - 5)" "str_repeat"
assert_eq '"a""b,c"' "$(csv_escape 'a"b,c')" "csv_escape quotes and doubles embedded quotes"
assert_eq "\"'=SUM(A1:A2)\"" "$(csv_escape '=SUM(A1:A2)')" "csv_escape neutralizes formula injection"
assert_eq 'a\|b c' "$(md_escape $'a|b\nc')" "md_escape escapes pipes and newlines"

# --- log redaction (M0 + M1 + M3)
r() { printf '%s' "$1" | log_redact; }
assert_not_contains "$(r 'login password=hunter2 ok')" hunter2 "redacts password=value"
assert_not_contains "$(r 'passwd: s3cr3tValue')" s3cr3tValue "redacts passwd: value"
assert_not_contains "$(r 'Authorization: Bearer abc.def-ghi')" abc.def-ghi "redacts bearer tokens"
assert_not_contains "$(r 'Set-Cookie: sid=zzzTOPSECRETzzz; Path=/')" zzzTOPSECRETzzz "redacts cookies"
assert_not_contains "$(r 'hash $2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ0123')" 'abcdefghijklmnopqrstuu' "redacts crypt-style hashes"
assert_not_contains "$(r 'md5 5f4dcc3b5aa765d61d8327deb882cf99 seen')" 5f4dcc3b5aa765d61d8327deb882cf99 "redacts long hex digests"
assert_eq 'user admin logged in' "$(r 'user admin logged in')" "benign text unchanged"
assert_not_contains "$(r 'api_key=AKIAFAKEKEY123 and token: abc123')" AKIAFAKEKEY123 "redacts api_key"
assert_not_contains "$(r 'phc $argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub')" c29tZXNhbHQ "redacts Argon2id PHC hashes"
assert_not_contains "$(r 'mod $pbkdf2-sha256$29000$saltsalt$hashhashhash')" saltsalt "redacts modular PBKDF2 hashes"
assert_not_contains "$(r 'dj pbkdf2_sha256$600000$UniqueSalt99$UniqueDigest88=')" UniqueSalt99 "redacts Django PBKDF2 hashes"
assert_not_contains "$(r 'wk scrypt:32768:8:1$SaltVal123$HexDigest999')" SaltVal123 "redacts Werkzeug scrypt hashes"
assert_not_contains "$(r 'ldap {SSHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=')" W6ph5Mm5Pz8GgiULbPgzG37mj9g "redacts LDAP SSHA hashes"
assert_not_contains "$(r 'mysql *2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19')" 2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19 "redacts MySQL5 hashes"
assert_not_contains "$(r 'uri otpauth://totp/App:user?secret=JBSWY3DPEHPK3PXP&issuer=App')" JBSWY3DPEHPK3PXP "redacts otpauth secret parameter"
assert_not_contains "$(r 'rec recovery_code=REC99887766 reset_token=RST11223344')" REC99887766 "redacts recovery_code"
assert_not_contains "$(r 'rec recovery_code=REC99887766 reset_token=RST11223344')" RST11223344 "redacts reset_token"

# --- validation
validate_uint 5 1 10 && t_ok "uint in range" || t_fail "uint in range"
validate_uint 11 1 10 && t_fail "uint above max rejected" || t_ok "uint above max rejected"
validate_uint '5;rm' && t_fail "uint rejects injection" || t_ok "uint rejects injection"
validate_ipv4 10.0.0.5 && t_ok "ipv4 valid" || t_fail "ipv4 valid"
validate_ipv4 999.1.1.1 && t_fail "ipv4 octet>255 rejected" || t_ok "ipv4 octet>255 rejected"
validate_hostname lab.example.test && t_ok "hostname valid" || t_fail "hostname valid"
validate_hostname "example.com" && t_ok "validate_hostname accepts example.com" || t_fail "validate_hostname example.com"
validate_hostname "localhost" && t_ok "validate_hostname accepts localhost" || t_fail "validate_hostname localhost"
validate_hostname "loopback.internal" && t_ok "validate_hostname accepts loopback.internal" || t_fail "validate_hostname loopback.internal"
validate_hostname "a-b.example.test" && t_ok "validate_hostname accepts a-b.example.test" || t_fail "validate_hostname a-b.example.test"
validate_hostname "-invalid.example" && t_fail "validate_hostname rejects -invalid.example" || t_ok "validate_hostname rejects -invalid.example"
validate_hostname "invalid-.example" && t_fail "validate_hostname rejects invalid-.example" || t_ok "validate_hostname rejects invalid-.example"
validate_hostname "example..com" && t_fail "validate_hostname rejects example..com" || t_ok "validate_hostname rejects example..com"
validate_hostname 'bad host;' && t_fail "hostname injection rejected" || t_ok "hostname injection rejected"
validate_target '$(id)' && t_fail "target command-substitution rejected" || t_ok "target command-substitution rejected"

# --- M4-P3: Strict canonical numeric IPv4 validation & ambiguous numeric IPv4 rejection
for canon_ip in "127.0.0.1" "10.0.0.1" "192.168.1.50" "172.16.0.1"; do
  validate_ipv4 "$canon_ip" && t_ok "M4-P3: validate_ipv4 accepts canonical $canon_ip" || t_fail "M4-P3: validate_ipv4 $canon_ip"
  validate_target "$canon_ip" && t_ok "M4-P3: validate_target accepts canonical $canon_ip" || t_fail "M4-P3: validate_target $canon_ip"
  validate_hostname "$canon_ip" && t_fail "M4-P3: validate_hostname rejects IPv4 literal $canon_ip" || t_ok "M4-P3: validate_hostname rejects IPv4 literal $canon_ip"
done

for valid_host in "host1.lab.local" "10host.internal" "web-01.test"; do
  validate_hostname "$valid_host" && t_ok "M4-P3: validate_hostname accepts legitimate hostname $valid_host" || t_fail "M4-P3: validate_hostname $valid_host"
  validate_target "$valid_host" && t_ok "M4-P3: validate_target accepts legitimate hostname $valid_host" || t_fail "M4-P3: validate_target $valid_host"
done

for ambig in "0177.0.0.1" "127.0.0.010" "127.1" "2130706433" "0x7f.0.0.1" "127.0.1" "0x7f000001" "127.0.0.0x1" "010.0.0.1" "127.00.0.1" "1.2.3.4.5"; do
  validate_ipv4 "$ambig" && t_fail "M4-P3: validate_ipv4 rejects $ambig" || t_ok "M4-P3: validate_ipv4 rejects $ambig"
  validate_ipv4_ambiguous "$ambig" && t_ok "M4-P3: validate_ipv4_ambiguous detects $ambig" || t_fail "M4-P3: validate_ipv4_ambiguous $ambig"
  validate_hostname "$ambig" && t_fail "M4-P3: validate_hostname rejects $ambig" || t_ok "M4-P3: validate_hostname rejects $ambig"
  validate_target "$ambig" && t_fail "M4-P3: validate_target rejects $ambig" || t_ok "M4-P3: validate_target rejects $ambig"
  authz_is_lab_target "$ambig" && t_fail "M4-P3: authz_is_lab_target rejects $ambig" || t_ok "M4-P3: authz_is_lab_target rejects $ambig"
done

validate_date_ymd 2026-02-30 && t_ok "date shape ok (calendar check not claimed)" || t_fail "date shape"
validate_date_ymd 2026-13-01 && t_fail "month 13 rejected" || t_ok "month 13 rejected"
validate_path_within "$SB/a/../b" "$SB" && t_ok "path within base" || t_fail "path within base"
validate_path_within "$SB/../etc" "$SB" && t_fail "traversal rejected" || t_ok "traversal rejected"
ln -s /etc/passwd "$SB/lnk"
validate_regular_file "$SB/lnk" && t_fail "symlink rejected as regular file" || t_ok "symlink rejected as regular file"

# --- config parsing (parsed, never sourced)
cfg() { printf '%s\n' "$2" >"$SB/$1.conf"; }
cfg ok $'# c\nlog_level=debug\npolicy_min_length=14\nhash_min_bcrypt_cost=13\nhash_min_argon2_mib=32'
(config_defaults; _config_parse_file "$SB/ok.conf" apply 2>/dev/null && [[ ${AN_CFG[policy_min_length]} == 14 && ${AN_CFG[hash_min_bcrypt_cost]} == 13 ]]) && t_ok "valid config applied" || t_fail "valid config applied"
cfg unk 'evil_key=1'
_config_parse_file "$SB/unk.conf" check 2>/dev/null && t_fail "unknown key rejected" || t_ok "unknown key rejected"
cfg bad 'log_level=verbose'
_config_parse_file "$SB/bad.conf" check 2>/dev/null && t_fail "bad enum value rejected" || t_ok "bad enum value rejected"
cfg badbc 'hash_min_bcrypt_cost=35'
_config_parse_file "$SB/badbc.conf" check 2>/dev/null && t_fail "bcrypt cost >31 rejected" || t_ok "bcrypt cost >31 rejected"
cfg inj 'policy_min_length=$(touch '"$SB"'/PWNED)'
_config_parse_file "$SB/inj.conf" check 2>/dev/null && t_fail "command substitution in value rejected" || t_ok "command substitution in value rejected"
[[ ! -e $SB/PWNED ]] && t_ok "config value never executed" || t_fail "config value never executed"
cfg mal 'this is not key value'
_config_parse_file "$SB/mal.conf" check 2>/dev/null && t_fail "malformed line rejected" || t_ok "malformed line rejected"
(config_defaults; AN_CFG[policy_min_length]=50 AN_CFG[policy_max_length]=20; config_validate_effective 2>/dev/null) && t_fail "min>max rejected" || t_ok "min>max rejected"
(config_defaults; AN_CFG[session_max_idle_min]=600 AN_CFG[session_max_absolute_min]=480; config_validate_effective 2>/dev/null) && t_fail "session idle>absolute rejected" || t_ok "session idle>absolute rejected"

# --- findings model + evidence rule
(
  session_init
  AN_MODULE=unit
  findings_add HIGH HIGH verified "no evidence" d r "" 2>/dev/null && echo "BAD" >"$SB/r1" || echo "refused" >"$SB/r1"
  findings_add SEVERE HIGH heuristic t d r 2>/dev/null && echo BAD >"$SB/r2" || echo refused >"$SB/r2"
  findings_add LOW MEDIUM heuristic "ok title" "pw password=hunter2 here" "fix" "" && echo ok >"$SB/r3"
  findings_add MEDIUM HIGH verified "with ev" d r "evidence=1"; echo "$AN_SESSION_FINDINGS" >"$SB/ff"
  echo "$(findings_max_rank)" >"$SB/rank"
)
assert_eq refused "$(<"$SB/r1")" "verified finding without evidence is refused"
assert_eq refused "$(<"$SB/r2")" "invalid severity is refused"
assert_eq ok "$(<"$SB/r3")" "heuristic finding without evidence accepted"
assert_eq 2 "$(<"$SB/rank")" "findings_max_rank = MEDIUM(2)"
FF=$(<"$SB/ff")
assert_file_not_contains "$FF" hunter2 "secrets redacted inside stored findings"
js=$(findings_export_json sess-1 "$FF")
[[ $js == *'"MEDIUM":1'* && $js == *'"LOW":1'* && $js == *'"id":"AN-unit-001"'* && $js == *'"id":"AN-unit-002"'* ]] &&
  t_ok "JSON export is valid and counts match" || t_fail "JSON export valid"

# --- authorization gate
scope=$SB/scope.txt
mk_scope() { printf 'authorized_by=Test Lead\ntarget=lab.example.test\nexpires=%s\ntest_accounts_only=%s\n' "$1" "$2" >"$scope"; }
(AN_ALLOW_ONLINE=0; authz_require_online lab.example.test 2>/dev/null); assert_eq 5 $? "online refused without --allow-online"
(AN_ALLOW_ONLINE=1 AN_SCOPE_FILE=""; authz_require_online lab.example.test 2>/dev/null); assert_eq 5 $? "online refused without scope file"
mk_scope 2999-01-01 yes
(AN_ALLOW_ONLINE=1 AN_SCOPE_FILE=$scope; authz_require_online lab.example.test 2>/dev/null); assert_eq 0 $? "online allowed with valid scope"
(AN_ALLOW_ONLINE=1 AN_SCOPE_FILE=$scope; authz_require_online other.example.test 2>/dev/null); assert_eq 5 $? "target outside scope refused"
mk_scope 2000-01-01 yes
(AN_ALLOW_ONLINE=1 AN_SCOPE_FILE=$scope; authz_require_online lab.example.test 2>/dev/null); assert_eq 5 $? "expired authorization refused"
mk_scope 2999-01-01 no
(AN_ALLOW_ONLINE=1 AN_SCOPE_FILE=$scope; authz_require_online lab.example.test 2>/dev/null); assert_eq 5 $? "test_accounts_only=no refused"
(AN_ALLOW_ONLINE=1 AN_SCOPE_FILE=$scope; authz_require_online 'a;b' 2>/dev/null); assert_eq 6 $? "malformed target rejected before anything else"
(AN_CFG[max_online_requests]=2 AN_CFG[max_online_rps]=50; authz_consume_request; authz_consume_request; authz_consume_request 2>/dev/null); assert_eq 5 $? "request budget enforced"

# --- M4-P3: Verify ambiguous numeric IPv4 rejected before DNS resolution and cannot disagree with scope
printf 'authorized_by=Test Lead\ntarget=127.0.0.1\ntarget=0177.0.0.1\ntarget=127.1\nexpires=2999-01-01\ntest_accounts_only=yes\n' >"$SB/ambig_scope.txt"
mkdir -p "$SB/getent_spy"
cat >"$SB/getent_spy/getent" <<EOF
#!/usr/bin/env bash
touch "$SB/getent_was_called"
exit 0
EOF
chmod +x "$SB/getent_spy/getent"
for ambig in "0177.0.0.1" "127.0.0.010" "127.1" "2130706433" "0x7f.0.0.1"; do
  (PATH="$SB/getent_spy:$PATH" AN_ALLOW_ONLINE=1 AN_SCOPE_FILE="$SB/ambig_scope.txt"; authz_require_online "$ambig" 2>/dev/null)
  assert_eq 6 $? "M4-P3: authz_require_online rejects $ambig with EX_VALIDATION (6)"
  (PATH="$SB/getent_spy:$PATH" AN_ALLOW_ONLINE=1 AN_SCOPE_FILE="$SB/ambig_scope.txt"; p=""; authz_resolve_target "$ambig" p 2>/dev/null)
  assert_eq 6 $? "M4-P3: authz_resolve_target rejects $ambig with EX_VALIDATION (6) before getent"
done
[[ ! -e "$SB/getent_was_called" ]] && t_ok "M4-P3: getent never invoked for ambiguous numeric IPv4 forms" || t_fail "M4-P3: getent was called"

printf 'authorized_by=Test Lead\ntarget=0177.0.0.1\ntarget=127.1\nexpires=2999-01-01\ntest_accounts_only=yes\n' >"$SB/only_ambig_scope.txt"
(AN_ALLOW_ONLINE=1 AN_SCOPE_FILE="$SB/only_ambig_scope.txt"; authz_require_online "127.0.0.1" 2>/dev/null)
assert_eq 5 $? "M4-P3: non-canonical scope entries (0177.0.0.1, 127.1) cannot authorize canonical 127.0.0.1"

# --- UI: resize + degradation
(COLUMNS=40; ui_cols_refresh; [[ $AN_COLS == 40 ]]) && t_ok "ui_cols_refresh honours COLUMNS" || t_fail "ui_cols_refresh"
(COLUMNS=40; ui_cols_refresh; ui_banner | grep -q '╔') && t_fail "narrow terminal uses compact banner" || t_ok "narrow terminal uses compact banner"
(COLUMNS=100; ui_cols_refresh; ui_banner | grep -q '╔') && t_ok "wide UTF-8 terminal uses ASCII-art banner" || t_fail "wide banner"
(LANG=C LC_ALL=C COLUMNS=100; ui_cols_refresh; ui_banner | grep -q '╔') && t_fail "non-UTF-8 falls back to plain banner" || t_ok "non-UTF-8 falls back to plain banner"
(COLUMNS=80; ui_init; COLUMNS=55; kill -WINCH "$BASHPID"; sleep 0.1; [[ $AN_COLS == 55 ]]) && t_ok "SIGWINCH triggers re-measure" || t_fail "SIGWINCH handler"

t_summary
