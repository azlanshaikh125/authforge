#!/usr/bin/env bash
# shellcheck shell=bash disable=SC1091,SC2034
source "$(dirname "${BASH_SOURCE[0]}")/../lib/harness.sh"
sandbox
load_core
# Load M5-P1 libraries
source "$TEST_ROOT/lib/compliance.sh"
source "$TEST_ROOT/lib/evidence.sh"
tmp_init
trap 'tmp_cleanup; rm -rf "$SB"' EXIT

# 1. Verify external 13-column TSV catalog file (data/compliance_mappings.dat)
[[ -f "$TEST_ROOT/data/compliance_mappings.dat" && ! -L "$TEST_ROOT/data/compliance_mappings.dat" ]] &&
  t_ok "external catalog data/compliance_mappings.dat exists and is a regular file" ||
  t_fail "external catalog data/compliance_mappings.dat missing"

cat_all="$SB/cat_all.dat"
compliance_load_catalog "$cat_all" ALL
assert_eq 0 $? "compliance_load_catalog ALL succeeds from data/compliance_mappings.dat"
assert_eq 40 "$(wc -l <"$cat_all" | tr -d ' ')" "catalog contains exactly 40 controls"

cat_asvs="$SB/cat_asvs.dat"
compliance_load_catalog "$cat_asvs" ASVS
assert_eq 25 "$(wc -l <"$cat_asvs" | tr -d ' ')" "ASVS catalog contains 25 controls"

cat_nist="$SB/cat_nist.dat"
compliance_load_catalog "$cat_nist" NIST
assert_eq 11 "$(wc -l <"$cat_nist" | tr -d ' ')" "NIST catalog contains 11 controls"

cat_cis="$SB/cat_cis.dat"
compliance_load_catalog "$cat_cis" CIS
assert_eq 4 "$(wc -l <"$cat_cis" | tr -d ' ')" "CIS catalog contains 4 safeguards"

non_partial=$(LC_ALL=C awk 'BEGIN{FS=sprintf("%c",31)} $11 != "PARTIAL" {c++} END{print c+0}' "$cat_all")
assert_eq 0 "$non_partial" "all 40 controls have max_status = PARTIAL"

# Reject symlinked, world-writable, or malformed external catalog files
ln -s "$TEST_ROOT/data/compliance_mappings.dat" "$SB/symlink_cat.dat"
(AN_COMPLIANCE_CATALOG="$SB/symlink_cat.dat" compliance_load_catalog "$SB/out_sym.dat" ALL 2>/dev/null) &&
  t_fail "symlinked catalog should be rejected" || t_ok "symlinked catalog rejected"

cp "$TEST_ROOT/data/compliance_mappings.dat" "$SB/writable_cat.dat"
chmod 666 "$SB/writable_cat.dat"
(AN_COMPLIANCE_CATALOG="$SB/writable_cat.dat" compliance_load_catalog "$SB/out_wr.dat" ALL 2>/dev/null) &&
  t_fail "world-writable catalog should be rejected" || t_ok "world-writable catalog rejected"

printf 'ASVS\t5.0.0\tonly_three_cols\n' >"$SB/bad_cat.dat"
chmod 600 "$SB/bad_cat.dat"
(AN_COMPLIANCE_CATALOG="$SB/bad_cat.dat" compliance_load_catalog "$SB/out_bad.dat" ALL 2>/dev/null) &&
  t_fail "malformed catalog should be rejected" || t_ok "malformed catalog rejected"

# Verify Sec.3.1.1.1 summary does not claim blocklist screening (which belongs to Sec.3.1.1.2)
sec3111_sum=$(LC_ALL=C awk 'BEGIN{FS=sprintf("%c",31)} $3 == "Sec.3.1.1.1" {print $7}' "$cat_nist")
assert_not_contains "$sec3111_sum" "blocklist" "NIST Sec.3.1.1.1 summary does not conflate blocklist screening"
sec3112_sum=$(LC_ALL=C awk 'BEGIN{FS=sprintf("%c",31)} $3 == "Sec.3.1.1.2" {print $7}' "$cat_nist")
assert_contains "$sec3112_sum" "blocklist" "NIST Sec.3.1.1.2 summary includes blocklist screening"

# 2. Empty session -> all 40 controls evaluate to NOT TESTED
session_init
SID_EMPTY=$AN_SESSION_ID
compliance_evaluate_session "$SID_EMPTY" "$SB/eval_empty.dat" ALL
assert_eq 40 "${COMP_SUMMARY_COUNTS[TOTAL]}" "empty session total controls = 40"
assert_eq 40 "${COMP_SUMMARY_COUNTS[NOT TESTED]}" "empty session has 40 NOT TESTED controls"
assert_eq 0 "${COMP_SUMMARY_COUNTS[PASS]}" "empty session has 0 PASS controls"
assert_eq 0 "${COMP_SUMMARY_COUNTS[PARTIAL]}" "empty session has 0 PARTIAL controls"
assert_eq 0 "${COMP_SUMMARY_COUNTS[FAIL]}" "empty session has 0 FAIL controls"

# 3. Conservative NIST Sec.3.1.1.1, Sec.3.1.1.2, and Sec.3.2.5 evaluation
# Even when local datasets contain common passwords, unsalted hashes, legacy profiles,
# or mfa_enabled=0 / mfa_webauthn_enabled=0, NIST Sec.3.1.1.1, Sec.3.1.1.2, and Sec.3.2.5
# must evaluate to PARTIAL (never FAIL or PASS) while preserving findings in findings.dat.
session_init
SID_NIST=$AN_SESSION_ID
AN_MODULE=password
findings_add HIGH HIGH verified "Password found in common-password dataset" \
  "Common password in sample dataset." "Reject common passwords." "dataset=sample.txt; match=exact"
findings_add HIGH MEDIUM heuristic "Minimum password length below commonly accepted floor" \
  "policy_min_length=6." "Raise min length." "setting=policy_min_length=6"
findings_add INFO MEDIUM heuristic "Mandatory composition rules configured" \
  "policy_require_classes=4." "Remove composition rules." "setting=policy_require_classes=4"
session_record_check "password:policy-review" "COMPLETED" 0 "profile:legacy-audit" "min_len=6;max_len=16;classes=4;block_common=0"
session_record_check "password:check-file" "COMPLETED" 0 "dataset:sample-passwords.txt" "dataset=sample-passwords.txt"

AN_MODULE="hash"
findings_add HIGH HIGH verified "Dataset contains unsalted password digests" \
  "Unsalted digests in local file." "Use salted KDF." "dataset=sample-hashes.txt; unsalted=3; total=9"
session_record_check "hash:check-file" "COMPLETED" 0 "dataset:sample-hashes.txt" "dataset=sample-hashes.txt"

AN_MODULE=mfa
findings_add CRITICAL HIGH verified "Multi-factor authentication is disabled" \
  "mfa_enabled=0 in local descriptor." "Enable MFA." "file=sample-mfa.conf; setting=mfa_enabled=0"
findings_add MEDIUM HIGH verified "Phishing-resistant MFA (WebAuthn) not enabled" \
  "mfa_webauthn_enabled=0." "Enable WebAuthn." "file=sample-mfa.conf; setting=mfa_webauthn_enabled=0"
session_record_check "mfa:audit-config" "COMPLETED" 0 "descriptor:sample-mfa.conf" "file=sample-mfa.conf"

compliance_evaluate_session "$SID_NIST" "$SB/eval_nist.dat" ALL
st_3111=$(LC_ALL=C awk 'BEGIN{FS=sprintf("%c",31)} $3 == "Sec.3.1.1.1" {print $6}' "$SB/eval_nist.dat")
st_3112=$(LC_ALL=C awk 'BEGIN{FS=sprintf("%c",31)} $3 == "Sec.3.1.1.2" {print $6}' "$SB/eval_nist.dat")
st_325=$(LC_ALL=C awk 'BEGIN{FS=sprintf("%c",31)} $3 == "Sec.3.2.5" {print $6}' "$SB/eval_nist.dat")
assert_eq "PARTIAL" "$st_3111" "NIST Sec.3.1.1.1 is conservatively PARTIAL on local profile"
assert_eq "PARTIAL" "$st_3112" "NIST Sec.3.1.1.2 is conservatively PARTIAL on unlinked local dataset/profile"
assert_eq "PARTIAL" "$st_325" "NIST Sec.3.2.5 is conservatively PARTIAL on offline MFA descriptor"

# Simultaneously, ASVS v5.0.0-6.2.1, v5.0.0-6.2.4, v5.0.0-11.4.2, and CIS 6.3 DO record FAIL
st_asvs_621=$(LC_ALL=C awk 'BEGIN{FS=sprintf("%c",31)} $3 == "v5.0.0-6.2.1" {print $6}' "$SB/eval_nist.dat")
st_asvs_624=$(LC_ALL=C awk 'BEGIN{FS=sprintf("%c",31)} $3 == "v5.0.0-6.2.4" {print $6}' "$SB/eval_nist.dat")
st_asvs_1142=$(LC_ALL=C awk 'BEGIN{FS=sprintf("%c",31)} $3 == "v5.0.0-11.4.2" {print $6}' "$SB/eval_nist.dat")
st_cis_63=$(LC_ALL=C awk 'BEGIN{FS=sprintf("%c",31)} $3 == "6.3" {print $6}' "$SB/eval_nist.dat")
assert_eq "FAIL" "$st_asvs_621" "ASVS v5.0.0-6.2.1 fails on policy_min_length < 8 finding"
assert_eq "FAIL" "$st_asvs_624" "ASVS v5.0.0-6.2.4 fails on common-password match"
assert_eq "FAIL" "$st_asvs_1142" "ASVS v5.0.0-11.4.2 fails on unsalted hash dataset finding"
assert_eq "FAIL" "$st_cis_63" "CIS 6.3 fails when mfa_enabled=0 in audited descriptor"

# 4. Verify untrusted manual injection of target_linked=1 or verifier_behavior_established=1
# into checks.dat CANNOT cause NIST Sec.3.1.1.1, Sec.3.1.1.2, or Sec.3.2.5 to FAIL or PASS
printf 'password:check-file\x1fCOMPLETED\x1f0\x1fdataset:sample.txt\x1f2026-11-15T00:00:00+0000\x1ftarget_linked=1;verifier_behavior_established=1;auth_factor_mode=single_factor\n' \
  >>"$AN_DATA_DIR/reports/$SID_NIST/checks.dat"
compliance_evaluate_session "$SID_NIST" "$SB/eval_spoof.dat" NIST
st_spoof_3112=$(LC_ALL=C awk 'BEGIN{FS=sprintf("%c",31)} $3 == "Sec.3.1.1.2" {print $6}' "$SB/eval_spoof.dat")
assert_eq "PARTIAL" "$st_spoof_3112" "untrusted target_linked/verifier_behavior_established in checks.dat cannot force Sec.3.1.1.2 FAIL"

# 5. Failed/incomplete online probes (tls_handshake_ok=0, oidc_found=0, cookies_seen=0)
# must remain NOT TESTED, never PARTIAL or PASS
session_init
SID_PROBE=$AN_SESSION_ID
session_record_check "proto-audit:tls" "COMPLETED" 0 "endpoint:127.0.0.1:443" "tls_handshake_ok=0;reason=timeout"
session_record_check "auth-intel:oidc-check" "COMPLETED" 0 "endpoint:http://127.0.0.1:8080" "http_probe_ok=1;oidc_found=0"
session_record_check "web-auth:cookies" "COMPLETED" 0 "endpoint:http://127.0.0.1:8080" "http_probe_ok=1;cookies_seen=0"
compliance_evaluate_session "$SID_PROBE" "$SB/eval_probe.dat" ASVS
st_tls_1211=$(LC_ALL=C awk 'BEGIN{FS=sprintf("%c",31)} $3 == "v5.0.0-12.1.1" {print $6}' "$SB/eval_probe.dat")
st_oidc_1046=$(LC_ALL=C awk 'BEGIN{FS=sprintf("%c",31)} $3 == "v5.0.0-10.4.6" {print $6}' "$SB/eval_probe.dat")
st_ck_331=$(LC_ALL=C awk 'BEGIN{FS=sprintf("%c",31)} $3 == "v5.0.0-3.3.1" {print $6}' "$SB/eval_probe.dat")
assert_eq "NOT TESTED" "$st_tls_1211" "timed-out TLS probe leaves v5.0.0-12.1.1 NOT TESTED"
assert_eq "NOT TESTED" "$st_oidc_1046" "missing OIDC metadata leaves v5.0.0-10.4.6 NOT TESTED"
assert_eq "NOT TESTED" "$st_ck_331" "zero Set-Cookie headers leaves v5.0.0-3.3.1 NOT TESTED"

# Successful TLS handshake with no findings -> PARTIAL (never PASS)
session_record_check "proto-audit:tls" "COMPLETED" 0 "endpoint:127.0.0.1:443" "tls_handshake_ok=1;protocol=TLSv1.3;cipher=TLS_AES_256_GCM_SHA384;self_signed=0"
compliance_evaluate_session "$SID_PROBE" "$SB/eval_probe_ok.dat" ASVS
st_tls_ok=$(LC_ALL=C awk 'BEGIN{FS=sprintf("%c",31)} $3 == "v5.0.0-12.1.1" {print $6}' "$SB/eval_probe_ok.dat")
assert_eq "PARTIAL" "$st_tls_ok" "clean TLSv1.3 handshake evaluates v5.0.0-12.1.1 to PARTIAL (capped at max_status)"

# 6. Multi-format exports (JSON, CSV, Markdown, TXT)
js_comp=$(compliance_export_json "$SID_NIST" ALL)
assert_contains "$js_comp" '"total": 40' "compliance JSON export reports total 40"
assert_contains "$js_comp" '"control_id":"v5.0.0-6.2.1"' "compliance JSON export includes v5.0.0-6.2.1"

csv_comp=$(compliance_export_csv "$SID_NIST" NIST)
assert_eq 12 "$(printf '%s\n' "$csv_comp" | wc -l | tr -d ' ')" "compliance CSV export for NIST has 1 header + 11 rows = 12 lines"

md_comp=$(compliance_export_markdown "$SID_NIST" CIS)
assert_contains "$md_comp" "# AUTHFORGE Compliance Assessment Report" "compliance Markdown export has title"
assert_contains "$md_comp" "3.10" "compliance Markdown export for CIS includes 3.10"

txt_comp=$(compliance_export_txt "$SID_NIST" ALL)
assert_contains "$txt_comp" "AUTHFORGE COMPLIANCE ASSESSMENT REPORT" "compliance TXT export has banner"
assert_not_contains "$txt_comp" $'\e' "compliance TXT export contains no ANSI escapes"

t_summary
