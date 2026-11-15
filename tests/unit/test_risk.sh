#!/usr/bin/env bash
# shellcheck shell=bash disable=SC1091,SC2034
source "$(dirname "${BASH_SOURCE[0]}")/../lib/harness.sh"
sandbox
load_core
tmp_init
trap 'tmp_cleanup; rm -rf "$SB"' EXIT

# 1. Empty findings evaluation -> CLEAN posture 100
: >"$SB/empty.dat"
risk_evaluate_file "$SB/empty.dat" "$SB/out_empty.dat"
assert_eq "CLEAN" "$RISK_OVERALL_RATING" "empty session rated CLEAN"
assert_eq 100 "$RISK_POSTURE_INDEX" "empty session posture index = 100"
assert_eq 0 "$RISK_TOTAL_RAW" "empty session total raw = 0"

# 2. Multi-severity scoring, deduplication, and cross-module correlation (CORR-01..04)
session_init
SID=$AN_SESSION_ID
FF="$AN_SESSION_FINDINGS"

# Emit findings across password, hash, and wordlist modules (including duplicates)
AN_MODULE=password
findings_add HIGH HIGH verified "Password found in common-password dataset" \
  "Common password detected." "Reject common passwords." "dataset=sample.txt; match=exact"
# Exact duplicate of the above finding (should collapse into occurrences=2)
findings_add HIGH HIGH verified "Password found in common-password dataset" \
  "Common password detected." "Reject common passwords." "dataset=sample.txt; match=exact"
findings_add MEDIUM MEDIUM verified "Password reuse detected within the dataset" \
  "2 distinct passwords reused." "Require unique passwords." "reused_values=2; entries=4"
findings_add MEDIUM HIGH verified "Common-password blocklist disabled in policy" \
  "policy_block_common=0." "Enable blocklist." "setting=policy_block_common=0"

AN_MODULE="hash"
findings_add CRITICAL HIGH verified "Cryptographically broken password storage scheme (lm-ntlm-pwdump)" \
  "Active LM hash present." "Disable LM and migrate to Argon2id." "format=lm-ntlm-pwdump; broken=1; total=9"
findings_add HIGH HIGH verified "Dataset contains unsalted password digests" \
  "Unsalted digests present." "Migrate to salted KDF." "dataset=hashes.txt; unsalted=3; total=9"
findings_add MEDIUM HIGH verified "Identical password hashes reused across dataset entries" \
  "Hash reuse detected." "Rotate shared credentials." "dataset=hashes.txt; reused_hashes=1; entries=2"

AN_MODULE=wordlist
findings_add LOW HIGH verified "Wordlist contains significant duplicate entries" \
  "20% redundant lines." "Deduplicate wordlist." "file=wl.txt; dup_pct=20.0"
findings_add INFO HIGH verified "Wordlist uses Windows CRLF line endings" \
  "CRLF lines found." "Normalize line endings." "file=wl.txt; crlf=5"

risk_evaluate_file "$FF" "$SB/enriched.dat"
assert_eq 9 "$RISK_TOTAL_RAW" "total raw findings = 9"
assert_eq 8 "$RISK_UNIQUE_COUNT" "unique deduplicated findings = 8"
assert_eq 8 "$RISK_ACTIVE_COUNT" "active findings = 8"
assert_eq 1 "$RISK_DUP_GROUPS" "1 duplicate group detected"
assert_eq 1 "$RISK_DUP_EXTRA" "1 redundant duplicate instance collapsed"
assert_eq "CRITICAL" "$RISK_OVERALL_RATING" "overall session rating is CRITICAL"
assert_eq "10.0" "$RISK_MAX_SCORE" "peak risk score is 10.0 (CRITICAL + correlation boost)"
assert_eq 4 "$RISK_CORR_COUNT" "all 4 correlation chains (CORR-01..04) detected"
assert_eq 1 "${RISK_SEV_COUNTS[CRITICAL]}" "1 active CRITICAL finding"
assert_eq 2 "${RISK_SEV_COUNTS[HIGH]}" "2 active HIGH findings (duplicate collapsed)"
assert_eq 3 "${RISK_SEV_COUNTS[MEDIUM]}" "3 active MEDIUM findings"
assert_eq 1 "${RISK_SEV_COUNTS[LOW]}" "1 active LOW finding"
assert_eq 1 "${RISK_SEV_COUNTS[INFO]}" "1 active INFO finding"

# Check prioritization order: first line in enriched.dat must be P1-IMMEDIATE
first_pri=$(head -n 1 "$SB/enriched.dat" | cut -d $'\x1f' -f1)
assert_eq "P1-IMMEDIATE" "$first_pri" "highest-priority finding is P1-IMMEDIATE"
last_pri=$(tail -n 1 "$SB/enriched.dat" | cut -d $'\x1f' -f1)
assert_eq "P5-INFO" "$last_pri" "lowest-priority active finding is P5-INFO"

# Check that collapsed duplicate has occurrences=2
dup_occ=$(awk -v FS='\x1f' '$3 == "AN-password-001" {print $12}' "$SB/enriched.dat")
assert_eq 2 "$dup_occ" "collapsed duplicate AN-password-001 records occurrences=2"

# 3. False-positive / risk-acceptance suppression workflow
risk_suppress_add "$SID" "AN-hash-005" "false_positive" "Honeypot test account in lab fixture"
risk_evaluate_file "$FF" "$SB/enriched_sup.dat"
assert_eq 7 "$RISK_ACTIVE_COUNT" "active count drops to 7 after suppressing AN-hash-005"
assert_eq 1 "$RISK_SUPPRESSED_COUNT" "suppressed count is 1"
assert_eq 0 "${RISK_SEV_COUNTS[CRITICAL]}" "active CRITICAL count is 0 after suppression"
assert_eq "HIGH" "$RISK_OVERALL_RATING" "overall rating updates from CRITICAL to HIGH after suppressing only CRITICAL finding"
sup_line=$(tail -n 1 "$SB/enriched_sup.dat")
assert_contains "$sup_line" "SUPPRESSED" "suppressed finding sorted to bottom with SUPPRESSED priority"
assert_contains "$sup_line" "false_positive" "suppressed finding records status=false_positive"

risk_suppress_remove "$SID" "AN-hash-005"
risk_evaluate_file "$FF" "$SB/enriched_unsup.dat"
assert_eq 8 "$RISK_ACTIVE_COUNT" "unsuppress restores active count to 8"
assert_eq "CRITICAL" "$RISK_OVERALL_RATING" "unsuppress restores CRITICAL rating"

# 4. Multi-format exports (JSON, CSV, Markdown, TXT)
js_out=$(findings_export_json "$SID" "$FF")
assert_contains "$js_out" '"risk_summary":' "JSON export includes risk_summary object"
assert_contains "$js_out" '"correlations":' "JSON export includes correlations array"
assert_contains "$js_out" '"CORR-01"' "JSON export includes CORR-01"
assert_contains "$js_out" '"priority":"P1-IMMEDIATE"' "JSON export includes priority field"

csv_out=$(findings_export_csv "$SID" "$FF")
assert_contains "$(printf '%s\n' "$csv_out" | head -n 1)" "session,priority,score,id,timestamp,module,severity" "CSV export has expected header"
assert_eq 9 "$(printf '%s\n' "$csv_out" | wc -l | tr -d ' ')" "CSV export has 1 header + 8 unique finding rows = 9 lines"

md_out=$(findings_export_markdown "$SID" "$FF")
assert_contains "$md_out" "# AUTHFORGE Security Assessment Report" "Markdown export has report title"
assert_contains "$md_out" "## Correlated Attack Chains" "Markdown export includes correlation section"
assert_contains "$md_out" "## Prioritized Findings & Remediation Plan" "Markdown export includes findings table"

txt_out=$(findings_export_txt "$SID" "$FF")
assert_contains "$txt_out" "AUTHFORGE RISK INTELLIGENCE REPORT" "TXT export has report banner"
assert_not_contains "$txt_out" $'\e' "TXT export contains no ANSI escape sequences"

# 5. Evidence tracking & SHA-256 integrity manifest verification + tamper detection
risk_manifest_update "$SID"
risk_manifest_verify "$SID" >/dev/null
assert_eq 0 $? "manifest verification passes on intact session"

# Tamper with findings.dat and verify detection
printf 'tampered\n' >>"$FF"
risk_manifest_verify "$SID" >/dev/null 2>&1 && t_fail "tampered findings.dat should fail verification" || t_ok "tampered findings.dat detected by SHA-256 manifest"
sed -i '$d' "$FF"
risk_manifest_verify "$SID" >/dev/null
assert_eq 0 $? "restored findings.dat passes SHA-256 verification again"

# 6. Malformed input resilience & large findings dataset (2,500 records)
LC_ALL=C awk 'BEGIN {
  print "malformed_line_without_delimiters"
  print "AN-bad-001\x1f2026\x1fmod\x1fINVALID_SEV\x1fHIGH\x1fverified\x1ft\x1fd\x1fr\x1fev=1"
  for (i = 1; i <= 2500; i++) {
    grp = i % 250
    printf "AN-load-%04d\x1f2026-11-12T00:00:00+0000\x1fhash\x1fHIGH\x1fHIGH\x1fverified\x1fIssue %d\x1fDetail %d\x1fFix %d\x1fdataset=big.txt; id=%d\n", i, grp, grp, grp, grp
  }
}' >"$SB/large_findings.dat"
risk_evaluate_file "$SB/large_findings.dat" "$SB/large_out.dat"
assert_eq 2500 "$RISK_TOTAL_RAW" "large dataset: 2,500 valid records processed (malformed lines safely ignored)"
assert_eq 250 "$RISK_UNIQUE_COUNT" "large dataset: collapsed 2,500 records into 250 unique findings"
assert_eq 250 "$RISK_DUP_GROUPS" "large dataset: 250 duplicate groups identified"
assert_eq 2250 "$RISK_DUP_EXTRA" "large dataset: 2,250 redundant instances counted"

t_summary
