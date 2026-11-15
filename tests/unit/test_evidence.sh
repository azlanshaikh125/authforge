#!/usr/bin/env bash
# shellcheck shell=bash disable=SC1091,SC2034
source "$(dirname "${BASH_SOURCE[0]}")/../lib/harness.sh"
sandbox
load_core
source "$TEST_ROOT/lib/compliance.sh"
source "$TEST_ROOT/lib/evidence.sh"
tmp_init
trap 'tmp_cleanup; rm -rf "$SB"' EXIT

# 1. Exact 8-path validation matrix for _session_verify_droot_lexical and _session_verify_report_dirs
_session_verify_droot_lexical "/home/user/authforge-data" && t_ok "matrix 1: /home/user/authforge-data accepted lexically" || t_fail "matrix 1: /home/user/authforge-data rejected"
_session_verify_droot_lexical "/tmp/data//nested" && t_fail "matrix 2: /tmp/data//nested should be rejected" || t_ok "matrix 2: /tmp/data//nested rejected"
_session_verify_droot_lexical "/tmp/./data" && t_fail "matrix 3: /tmp/./data should be rejected" || t_ok "matrix 3: /tmp/./data rejected"
_session_verify_droot_lexical "/tmp/data/../other" && t_fail "matrix 4: /tmp/data/../other should be rejected" || t_ok "matrix 4: /tmp/data/../other rejected"
_session_verify_droot_lexical "/tmp/data/." && t_fail "matrix 5: /tmp/data/. should be rejected" || t_ok "matrix 5: /tmp/data/. rejected"
_session_verify_droot_lexical "/tmp/data/.." && t_fail "matrix 6: /tmp/data/.. should be rejected" || t_ok "matrix 6: /tmp/data/.. rejected"
_session_verify_droot_lexical "/tmp/data/" && t_fail "matrix 7: /tmp/data/ trailing slash should be rejected" || t_ok "matrix 7: /tmp/data/ trailing slash rejected"
_session_verify_droot_lexical "/" && t_fail "matrix 8: / root should be rejected" || t_ok "matrix 8: / root rejected"

# 2. Containment checks in _session_verify_report_dirs (rejects .. traversal, symlinks, bad modes)
session_init
SID=$AN_SESSION_ID
_session_verify_report_dirs && t_ok "valid session report dir passes _session_verify_report_dirs" || t_fail "valid session report dir failed"

saved_sdir=$AN_SESSION_REPORT_DIR
AN_SESSION_REPORT_DIR="$AN_DATA_DIR/reports/../evidence/$SID"
_session_verify_report_dirs && t_fail "traversal in AN_SESSION_REPORT_DIR should fail" || t_ok "traversal in AN_SESSION_REPORT_DIR rejected"

AN_SESSION_REPORT_DIR="${saved_sdir}/"
_session_verify_report_dirs && t_fail "trailing slash on AN_SESSION_REPORT_DIR should fail" || t_ok "trailing slash on AN_SESSION_REPORT_DIR rejected"
AN_SESSION_REPORT_DIR=$saved_sdir

chmod 755 "$AN_SESSION_REPORT_DIR"
_session_verify_report_dirs && t_fail "mode 0755 on AN_SESSION_REPORT_DIR should fail" || t_ok "mode 0755 on AN_SESSION_REPORT_DIR rejected"
chmod 700 "$AN_SESSION_REPORT_DIR"

# 3. Lockfile symlink rejection and fail-closed /proc/<BASHPID>/fd/<lock_fd> verification
ln -s /dev/null "$AN_SESSION_REPORT_DIR/.checks.lock"
session_record_check "password:analyze" "COMPLETED" 0 "stdin_secret" "test=1" 2>/dev/null && t_fail "symlinked .checks.lock should fail" || t_ok "symlinked .checks.lock rejected fail-closed"
assert_eq 1 "$_AN_LEDGER_WRITE_FAILED" "symlinked .checks.lock sets _AN_LEDGER_WRITE_FAILED=1"
rm -f "$AN_SESSION_REPORT_DIR/.checks.lock"
_AN_LEDGER_WRITE_FAILED=0

# Normal check recording via kernel flock and /proc/<BASHPID>/fd/<lock_fd>
session_record_check "password:policy-review" "COMPLETED" 0 "profile:default" "min_len=12;target_linked=1;verifier_behavior_established=1"
assert_eq 0 $? "session_record_check succeeds on valid lockfile"
assert_eq 600 "$(stat -c %a "$AN_SESSION_REPORT_DIR/.checks.lock")" ".checks.lock is 0600"
assert_eq 600 "$(stat -c %a "$AN_SESSION_REPORT_DIR/checks.dat")" "checks.dat is 0600"
assert_file_not_contains "$AN_SESSION_REPORT_DIR/checks.dat" "target_linked" "session_record_check strips untrusted target_linked token"
assert_file_not_contains "$AN_SESSION_REPORT_DIR/checks.dat" "verifier_behavior_established" "session_record_check strips untrusted verifier_behavior_established token"

# Updating the same check_id replaces the prior entry atomically without duplicates
session_record_check "password:policy-review" "COMPLETED" 0 "profile:nist-aligned" "min_len=15"
assert_eq 1 "$(wc -l <"$AN_SESSION_REPORT_DIR/checks.dat" | tr -d ' ')" "re-recording same check_id deduplicates to 1 row"
assert_contains "$(<"$AN_SESSION_REPORT_DIR/checks.dat")" "profile:nist-aligned" "updated check row contains latest target_type"

# 4. Concurrent flock stress test (8 parallel workers recording distinct check_ids)
for i in 1 2 3 4 5 6 7 8; do
  (
    session_record_check "worker:check-${i}" "COMPLETED" 0 "worker:${i}" "iter=${i}"
  ) &
done
wait
assert_eq 9 "$(wc -l <"$AN_SESSION_REPORT_DIR/checks.dat" | tr -d ' ')" "concurrent flock writers preserve all 9 distinct check records without corruption"

# 5. Evidence manifest completeness (Blocker 1): detect unlisted extra files in reports/<sid>/ and evidence/<sid>/
AN_MODULE=password
findings_add MEDIUM HIGH verified "Common-password blocklist disabled in policy" \
  "policy_block_common=0." "Enable blocklist." "setting=policy_block_common=0"
evidence_log_event "$SID" "UNIT_TEST" "reports/$SID/findings.dat" "password=SuperSecret123! recorded"
assert_eq 0 $? "evidence_log_event succeeds on writable evidence.log"
assert_file_not_contains "$AN_DATA_DIR/evidence/$SID/evidence.log" "SuperSecret123!" "evidence_log_event redacts secrets"

evidence_manifest_update "$SID"
assert_eq 0 $? "evidence_manifest_update succeeds"
assert_contains "$(<"$AN_DATA_DIR/evidence/$SID/manifest.sha256")" "reports/$SID/checks.dat" "manifest includes checks.dat"
assert_contains "$(<"$AN_DATA_DIR/evidence/$SID/manifest.sha256")" "reports/$SID/findings.dat" "manifest includes findings.dat"
assert_contains "$(<"$AN_DATA_DIR/evidence/$SID/manifest.sha256")" "evidence/$SID/evidence.log" "manifest includes evidence.log"

evidence_manifest_verify "$SID" >/dev/null
assert_eq 0 $? "evidence_manifest_verify passes on intact session"

# Inject an unlisted extra file in reports/<sid>/ -> must fail verification
printf 'rogue report artifact\n' >"$AN_DATA_DIR/reports/$SID/unlisted_extra.txt"
chmod 600 "$AN_DATA_DIR/reports/$SID/unlisted_extra.txt"
out_extra_rep=$(evidence_manifest_verify "$SID" 2>&1)
rc_extra_rep=$?
assert_eq 6 "$rc_extra_rep" "Blocker 1: unlisted extra file in reports/<sid>/ causes evidence_manifest_verify to fail (6)"
assert_contains "$out_extra_rep" "unlisted extra file in reports directory" "Blocker 1: reports extra file reported explicitly"
rm -f "$AN_DATA_DIR/reports/$SID/unlisted_extra.txt"

# Inject an unlisted extra file in evidence/<sid>/ -> must fail verification
printf 'rogue evidence artifact\n' >"$AN_DATA_DIR/evidence/$SID/unlisted_evidence.bin"
chmod 600 "$AN_DATA_DIR/evidence/$SID/unlisted_evidence.bin"
out_extra_ev=$(evidence_manifest_verify "$SID" 2>&1)
rc_extra_ev=$?
assert_eq 6 "$rc_extra_ev" "Blocker 1: unlisted extra file in evidence/<sid>/ causes evidence_manifest_verify to fail (6)"
assert_contains "$out_extra_ev" "unlisted extra file in evidence directory" "Blocker 1: evidence extra file reported explicitly"
rm -f "$AN_DATA_DIR/evidence/$SID/unlisted_evidence.bin"

evidence_manifest_verify "$SID" >/dev/null
assert_eq 0 $? "evidence_manifest_verify passes again after removing unlisted extra files"

# 6. Bundle export, bundle verification, and rejection of unmanifested/unexpected archive files (Blocker 1)
bundle_path="$SB/evidence-${SID}.tar.gz"
evidence_export_bundle "$SID" "$bundle_path" >/dev/null
assert_eq 0 $? "evidence_export_bundle creates bundle"
assert_eq 600 "$(stat -c %a "$bundle_path")" "exported bundle is mode 0600"

evidence_verify_bundle "$bundle_path" >/dev/null
assert_eq 0 $? "evidence_verify_bundle passes on intact bundle"

# 6a. Tamper with checks.dat inside a copy of the bundle -> must fail verification
mkdir -p "$SB/tamper"
tar -C "$SB/tamper" -xzf "$bundle_path"
printf 'tampered\n' >>"$SB/tamper/$SID/reports/$SID/checks.dat"
tar -C "$SB/tamper" -czf "$SB/tampered.tar.gz" "$SID"
evidence_verify_bundle "$SB/tampered.tar.gz" >/dev/null 2>&1 && t_fail "tampered bundle should fail verification" || t_ok "tampered bundle detected by evidence_verify_bundle"

# 6b. Inject an unmanifested file inside <sid>/reports/<sid>/ in the bundle -> must fail verification
rm -rf "$SB/tamper" && mkdir -p "$SB/tamper"
tar -C "$SB/tamper" -xzf "$bundle_path"
printf 'unmanifested\n' >"$SB/tamper/$SID/reports/$SID/sneaky.txt"
tar -C "$SB/tamper" -czf "$SB/unmanifested-bundle.tar.gz" "$SID"
evidence_verify_bundle "$SB/unmanifested-bundle.tar.gz" >/dev/null 2>&1 &&
  t_fail "Blocker 1: bundle with unmanifested file in reports/<sid>/ should fail" ||
  t_ok "Blocker 1: bundle with unmanifested file in reports/<sid>/ rejected by evidence_verify_bundle"

# 6c. Inject an unexpected archive path (<sid>/unexpected.txt) in the bundle -> must fail pre-extraction check
rm -rf "$SB/tamper" && mkdir -p "$SB/tamper"
tar -C "$SB/tamper" -xzf "$bundle_path"
printf 'unexpected path\n' >"$SB/tamper/$SID/unexpected.txt"
tar -C "$SB/tamper" -czf "$SB/unexpected-path-bundle.tar.gz" "$SID"
evidence_verify_bundle "$SB/unexpected-path-bundle.tar.gz" >/dev/null 2>&1 &&
  t_fail "Blocker 1: bundle with unexpected archive path should fail" ||
  t_ok "Blocker 1: bundle with unexpected archive path rejected by evidence_verify_bundle"

# 7. Fail-closed evidence writes & manifest preservation on failure (Blocker 2)
valid_manifest_before=$(<"$AN_DATA_DIR/evidence/$SID/manifest.sha256")

# 7a. Inject write failure in evidence_log_event (symlinked evidence.log) -> returns nonzero
mv "$AN_DATA_DIR/evidence/$SID/evidence.log" "$SB/saved_evidence.log"
ln -s "$SB/saved_evidence.log" "$AN_DATA_DIR/evidence/$SID/evidence.log"
evidence_log_event "$SID" "FAIL_TEST" "reports/$SID/findings.dat" "should fail" 2>/dev/null &&
  t_fail "Blocker 2: evidence_log_event on symlinked evidence.log should return nonzero" ||
  t_ok "Blocker 2: evidence_log_event returns nonzero when append target is unsafe"

# Bundle export must abort when evidence_log_event fails (must not suppress custody-event failure)
(evidence_export_bundle "$SID" "$SB/should-not-exist.tar.gz" >/dev/null 2>&1) &&
  t_fail "Blocker 2: evidence_export_bundle should abort when evidence_log_event fails" ||
  t_ok "Blocker 2: evidence_export_bundle fails closed when custody-event write fails"
[[ ! -e "$SB/should-not-exist.tar.gz" ]] && t_ok "Blocker 2: no bundle created on custody-event failure" || t_fail "Blocker 2: bundle created despite custody-event failure"
rm -f "$AN_DATA_DIR/evidence/$SID/evidence.log"
mv "$SB/saved_evidence.log" "$AN_DATA_DIR/evidence/$SID/evidence.log"

# 7b. Inject chmod failure during evidence_log_event -> returns nonzero
mkdir -p "$SB/fail_chmod_bin"
cat >"$SB/fail_chmod_bin/chmod" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
chmod +x "$SB/fail_chmod_bin/chmod"
(PATH="$SB/fail_chmod_bin:$PATH" evidence_log_event "$SID" "CHMOD_FAIL" "none" "test" 2>/dev/null) &&
  t_fail "Blocker 2: evidence_log_event should fail when chmod fails" ||
  t_ok "Blocker 2: evidence_log_event returns nonzero when chmod fails"
# Restore manifest to include the appended line before testing manifest failure injection
evidence_manifest_update "$SID"
valid_manifest_before=$(<"$AN_DATA_DIR/evidence/$SID/manifest.sha256")

# 7c. Inject sha256sum failure during evidence_manifest_update -> returns nonzero and preserves previous manifest
mkdir -p "$SB/fail_sha_bin"
cat >"$SB/fail_sha_bin/sha256sum" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
chmod +x "$SB/fail_sha_bin/sha256sum"
(PATH="$SB/fail_sha_bin:$PATH" evidence_manifest_update "$SID" 2>/dev/null) &&
  t_fail "Blocker 2: evidence_manifest_update should fail when sha256sum fails" ||
  t_ok "Blocker 2: evidence_manifest_update returns nonzero when sha256sum fails"
assert_eq "$valid_manifest_before" "$(<"$AN_DATA_DIR/evidence/$SID/manifest.sha256")" "Blocker 2: previous valid manifest preserved when sha256sum fails"

# 7d. Inject atomic rename (mv) failure during evidence_manifest_update -> returns nonzero and preserves previous manifest
mkdir -p "$SB/fail_mv_bin"
cat >"$SB/fail_mv_bin/mv" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
chmod +x "$SB/fail_mv_bin/mv"
(PATH="$SB/fail_mv_bin:$PATH" evidence_manifest_update "$SID" 2>/dev/null) &&
  t_fail "Blocker 2: evidence_manifest_update should fail when mv rename fails" ||
  t_ok "Blocker 2: evidence_manifest_update returns nonzero when mv rename fails"
assert_eq "$valid_manifest_before" "$(<"$AN_DATA_DIR/evidence/$SID/manifest.sha256")" "Blocker 2: previous valid manifest preserved when mv rename fails"
left_tmp=$(shopt -s nullglob dotglob; echo "$AN_DATA_DIR/evidence/$SID"/.manifest.tmp.*)
assert_eq "" "$left_tmp" "Blocker 2: no .manifest.tmp.* files left behind after failed manifest update"

# 8. Restricted-PATH dependency tests (Blocker 3):
# Verify tar and find are NOT required in AN_REQUIRED_CMDS and bundle operations check tar specifically
mkdir -p "$SB/notar_nofind_bin"
for cmd_bin in bash awk sed grep sort uniq tr head wc mktemp date od stat readlink realpath cat mkdir chmod cp rm mv ln flock id sha256sum; do
  p=$(command -v "$cmd_bin" 2>/dev/null || true)
  [[ -n $p ]] && ln -sf "$p" "$SB/notar_nofind_bin/$cmd_bin"
done
(PATH="$SB/notar_nofind_bin" deps_check_required)
assert_eq 0 $? "Blocker 3: deps_check_required passes without tar or find in PATH"

(PATH="$SB/notar_nofind_bin" evidence_export_bundle "$SID" "$SB/no-tar-bundle.tar.gz" >/dev/null 2>&1)
assert_eq 4 $? "Blocker 3: evidence_export_bundle returns EX_DEPENDENCY (4) when tar is missing from PATH"

(PATH="$SB/notar_nofind_bin" evidence_verify_bundle "$bundle_path" >/dev/null 2>&1)
assert_eq 4 $? "Blocker 3: evidence_verify_bundle returns EX_DEPENDENCY (4) when tar is missing from PATH"

# 9. Legacy M0-M4 session compatibility (session without checks.dat)
session_init
SID_LEG=$AN_SESSION_ID
rm -f "$AN_DATA_DIR/reports/$SID_LEG/checks.dat"
AN_MODULE="hash"
findings_add HIGH HIGH verified "Dataset contains unsalted password digests" \
  "Unsalted digests." "Use salted KDF." "dataset=hashes.txt; unsalted=2; total=5"
risk_manifest_update "$SID_LEG"
risk_manifest_verify "$SID_LEG" >/dev/null
assert_eq 0 $? "legacy session without checks.dat passes risk_manifest_verify"

t_summary
