#!/usr/bin/env bash
# shellcheck shell=bash disable=SC1091,SC2034
source "$(dirname "${BASH_SOURCE[0]}")/../lib/harness.sh"
sandbox
load_core
source "$TEST_ROOT/lib/compliance.sh"
source "$TEST_ROOT/lib/evidence.sh"
tmp_init
trap 'tmp_cleanup; rm -rf "$SB"' EXIT

INST_BIN="$TEST_ROOT/scripts/install.sh"
UNINST_BIN="$TEST_ROOT/scripts/uninstall.sh"
SAFE_BIN="$TEST_ROOT/scripts/authforge-safe.sh"

_tree_digest() { # <dir>
  local d=$1
  (
    cd "$d" &&
    find . -type f -exec sha256sum {} + | LC_ALL=C sort | sha256sum | awk '{print $1}'
  )
}

# 1. Invalid destination paths, traversal, relative paths, overlapping dirs, and dangerous system paths
for bad_path in "relative/path" "/" "/tmp/trail/" "/tmp//double" "/tmp/./dot" "/tmp/a/../b" "/etc" "/usr" "/bin" "/var" "/tmp"; do
  "$INST_BIN" --libdir "$bad_path" --bindir "$SB/bin" --datadir "$SB/data_ok" >/dev/null 2>&1
  assert_eq 6 $? "install.sh rejects invalid/dangerous libdir: $bad_path"
done

"$INST_BIN" --libdir "$SB/same_dir" --bindir "$SB/bin" --datadir "$SB/same_dir" >/dev/null 2>&1
assert_eq 6 $? "install.sh rejects identical libdir and datadir"

"$INST_BIN" --libdir "$SB/parent" --bindir "$SB/bin" --datadir "$SB/parent/child" >/dev/null 2>&1
assert_eq 6 $? "install.sh rejects overlapping libdir and datadir"

"$INST_BIN" --libdir "$TEST_ROOT" --bindir "$SB/bin" --datadir "$SB/data_ok" >/dev/null 2>&1
assert_eq 6 $? "install.sh refuses to install over source checkout"

# 2. Symlinked parent directory and unsafe (world-writable) directory rejection
mkdir -p "$SB/real_parent"
ln -s "$SB/real_parent" "$SB/sym_parent"
"$INST_BIN" --libdir "$SB/sym_parent/authforge" --bindir "$SB/bin" --datadir "$SB/data_ok" >/dev/null 2>&1
assert_eq 6 $? "install.sh rejects symlinked parent component in libdir"

mkdir -p "$SB/world_writable"
chmod 777 "$SB/world_writable"
"$INST_BIN" --libdir "$SB/world_writable/authforge" --bindir "$SB/bin" --datadir "$SB/data_ok" >/dev/null 2>&1
assert_eq 6 $? "install.sh rejects world-writable (0777) parent directory"
chmod 700 "$SB/world_writable"

# 3. Missing dependency handling in install.sh
mkdir -p "$SB/no_flock_bin"
for c in bash env awk sed grep sort uniq tr head wc mktemp date od stat readlink realpath cat mkdir chmod cp rm mv ln id sha256sum; do
  p=$(command -v "$c" 2>/dev/null || true)
  [[ -n $p ]] && ln -sf "$p" "$SB/no_flock_bin/$c"
done
(PATH="$SB/no_flock_bin" "$INST_BIN" --dry-run --libdir "$SB/l1" --bindir "$SB/b1" --datadir "$SB/d1" >/dev/null 2>&1)
assert_eq 4 $? "install.sh returns EX_DEPENDENCY (4) when required command (flock) is missing"

# 4. Refusal to overwrite unrelated non-empty directory or unrelated binary
mkdir -p "$SB/unrelated_dir"
printf 'important user file\n' >"$SB/unrelated_dir/keep.txt"
"$INST_BIN" --libdir "$SB/unrelated_dir" --bindir "$SB/bin" --datadir "$SB/d1" >/dev/null 2>&1
assert_eq 6 $? "install.sh refuses to overwrite non-empty directory lacking AUTHFORGE manifest"
[[ -f "$SB/unrelated_dir/keep.txt" ]] && t_ok "unrelated file preserved intact" || t_fail "unrelated file lost"

mkdir -p "$SB/bin_conflict"
printf '#!/bin/sh\necho hi\n' >"$SB/bin_conflict/authforge"
"$INST_BIN" --libdir "$SB/l_conflict" --bindir "$SB/bin_conflict" --datadir "$SB/d_conflict" >/dev/null 2>&1
assert_eq 6 $? "install.sh refuses to overwrite existing non-symlink file at launcher path"

# 4b. MANDATORY SECURITY REGRESSION: Forged manifest with only valid-looking header + libdir and keep-important.txt
FORGED_DIR="$SB/forged_install"
FORGED_BIN="$SB/forged_bin"
FORGED_DATA="$SB/forged_data"
mkdir -p "$FORGED_DIR" "$FORGED_BIN" "$FORGED_DATA"
chmod 755 "$FORGED_DIR" "$FORGED_BIN"
chmod 700 "$FORGED_DATA"
printf 'CRITICAL_USER_DATA_DO_NOT_DELETE\n' >"$FORGED_DIR/keep-important.txt"
printf 'existing_service_setting=enabled\n' >"$FORGED_DIR/existing-service.conf"
keep_sha_before=$(sha256sum "$FORGED_DIR/keep-important.txt" | awk '{print $1}')
svc_sha_before=$(sha256sum "$FORGED_DIR/existing-service.conf" | awk '{print $1}')
cat >"$FORGED_DIR/.authforge-install.manifest" <<EOF
format=authforge-install-manifest-v2
libdir=$FORGED_DIR
EOF
chmod 644 "$FORGED_DIR/.authforge-install.manifest"
forged_tree_before=$(_tree_digest "$FORGED_DIR")

forged_out=$("$INST_BIN" --libdir "$FORGED_DIR" --bindir "$FORGED_BIN" --datadir "$FORGED_DATA" 2>&1)
forged_rc=$?
assert_eq 6 "$forged_rc" "install.sh rejects forged header-only manifest (exits 6)"
[[ -f "$FORGED_DIR/keep-important.txt" ]] && t_ok "keep-important.txt still exists after rejected forged-manifest install" || t_fail "keep-important.txt was deleted"
assert_eq "$keep_sha_before" "$(sha256sum "$FORGED_DIR/keep-important.txt" | awk '{print $1}')" "keep-important.txt SHA-256 unchanged after rejected install"
assert_eq "$svc_sha_before" "$(sha256sum "$FORGED_DIR/existing-service.conf" | awk '{print $1}')" "existing-service.conf SHA-256 unchanged after rejected install"
assert_eq "$forged_tree_before" "$(_tree_digest "$FORGED_DIR")" "no existing files in forged install dir were deleted or modified"
assert_not_contains "$forged_out" "Installed AUTHFORGE" "no success message reported when forged manifest is rejected"

uninst_forged_out=$("$UNINST_BIN" --libdir "$FORGED_DIR" --bindir "$FORGED_BIN" --datadir "$FORGED_DATA" 2>&1)
uninst_forged_rc=$?
assert_eq 6 "$uninst_forged_rc" "uninstall.sh rejects forged header-only manifest (exits 6)"
assert_eq "$forged_tree_before" "$(_tree_digest "$FORGED_DIR")" "uninstall.sh preserves forged install dir byte-for-byte"

# 5. Successful user-local default installation (using isolated HOME) & v2 manifest generation
FAKE_HOME="$SB/user_home"
mkdir -p "$FAKE_HOME"
chmod 700 "$FAKE_HOME"
(HOME="$FAKE_HOME" XDG_DATA_HOME="" XDG_STATE_HOME="" "$INST_BIN" >/dev/null 2>&1)
assert_eq 0 $? "default user-local installation under isolated HOME succeeds"

INST_LIB="$FAKE_HOME/.local/share/authforge"
INST_LAUNCHER="$FAKE_HOME/.local/bin/authforge"
INST_DATA="$FAKE_HOME/.local/state/authforge"

[[ -f "$INST_LIB/.authforge-install.manifest" ]] && t_ok "installation receipt created" || t_fail "installation receipt missing"
assert_eq "format=authforge-install-manifest-v2" "$(head -n 1 "$INST_LIB/.authforge-install.manifest")" "install.sh generates v2 manifest header"
assert_contains "$(<"$INST_LIB/.authforge-install.manifest")" "DIR core 755" "v2 manifest records DIR core 755 with octal mode"
[[ -L "$INST_LAUNCHER" ]] && t_ok "launcher symlink created at ~/.local/bin/authforge" || t_fail "launcher symlink missing"
assert_eq 700 "$(stat -c %a "$INST_DATA")" "installed data directory is mode 0700"
assert_eq 700 "$(stat -c %a "$INST_DATA/reports")" "installed reports directory is mode 0700"
assert_eq 700 "$(stat -c %a "$INST_DATA/evidence")" "installed evidence directory is mode 0700"

# 6. Execute installed launcher: verify code/data separation (AN_ROOT vs AN_DATA_DIR)
ver_out=$(HOME="$FAKE_HOME" AN_DATA_DIR="" "$INST_LAUNCHER" --no-color --version 2>&1)
assert_eq 0 $? "installed launcher --version exits 0"
assert_contains "$ver_out" "AUTHFORGE 0.1.0" "installed launcher prints version"

HOME="$FAKE_HOME" AN_DATA_DIR="" "$INST_LAUNCHER" --no-color -p legacy-audit password policy-review >/dev/null 2>&1
assert_eq 0 $? "installed launcher runs password policy-review"

inst_sid=$(cat "$INST_DATA/reports/.latest" 2>/dev/null || true)
[[ -n $inst_sid && -f "$INST_DATA/reports/$inst_sid/findings.dat" && -f "$INST_DATA/reports/$inst_sid/checks.dat" ]] &&
  t_ok "installed execution writes findings.dat and checks.dat to ~/.local/state/authforge (not code dir)" ||
  t_fail "installed execution did not write session files to INST_DATA"
[[ ! -d "$INST_LIB/reports" ]] && t_ok "installed code directory remains free of runtime reports/" || t_fail "reports/ created in code dir"

comp_out=$(HOME="$FAKE_HOME" AN_DATA_DIR="" "$INST_LAUNCHER" --no-color compliance evaluate 2>&1)
assert_eq 0 $? "installed launcher runs compliance evaluate"
assert_contains "$comp_out" "v5.0.0-6.2.4" "installed compliance evaluate maps findings accurately"

HOME="$FAKE_HOME" AN_DATA_DIR="" "$INST_LAUNCHER" --no-color evidence verify >/dev/null 2>&1
assert_eq 0 $? "installed launcher runs evidence verify"

# 6b. Comprehensive existing-install FILE verification matrix on $INST_LIB (install.sh & uninstall.sh)
cp -p "$INST_LIB/.authforge-install.manifest" "$SB/valid_manifest.bak"
valid_tree_sha=$(_tree_digest "$INST_LIB")

# (i) Unrelated extra file (keep-important.txt) inside otherwise valid installation
printf 'DO_NOT_LOSE_THIS_FILE\n' >"$INST_LIB/keep-important.txt"
extra_keep_sha=$(sha256sum "$INST_LIB/keep-important.txt" | awk '{print $1}')
tree_with_extra=$(_tree_digest "$INST_LIB")
extra_inst_out=$(HOME="$FAKE_HOME" "$INST_BIN" 2>&1)
assert_eq 6 $? "install.sh refuses reinstall when unmanifested keep-important.txt exists in libdir"
[[ -f "$INST_LIB/keep-important.txt" ]] && t_ok "keep-important.txt preserved when reinstall refused" || t_fail "keep-important.txt deleted"
assert_eq "$extra_keep_sha" "$(sha256sum "$INST_LIB/keep-important.txt" | awk '{print $1}')" "keep-important.txt SHA-256 intact"
assert_eq "$tree_with_extra" "$(_tree_digest "$INST_LIB")" "existing installation preserved byte-for-byte when extra file present"
assert_not_contains "$extra_inst_out" "Installed AUTHFORGE" "no success message printed on extra-file rejection"
rm -f "$INST_LIB/keep-important.txt"

# (ii) Missing manifest in existing installation
mv "$INST_LIB/.authforge-install.manifest" "$SB/missing_man.tmp"
tree_no_man=$(_tree_digest "$INST_LIB")
noman_out=$(HOME="$FAKE_HOME" "$INST_BIN" 2>&1)
assert_eq 6 $? "install.sh refuses reinstall when .authforge-install.manifest is missing"
assert_eq "$tree_no_man" "$(_tree_digest "$INST_LIB")" "existing installation preserved byte-for-byte when manifest missing"
assert_not_contains "$noman_out" "Installed AUTHFORGE" "no success message printed when manifest missing"
(HOME="$FAKE_HOME" "$UNINST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "uninstall.sh refuses when .authforge-install.manifest is missing"
mv "$SB/missing_man.tmp" "$INST_LIB/.authforge-install.manifest"

# (iii) Modified installed file
cp -p "$INST_LIB/README.md" "$SB/readme_orig.bak"
printf 'tampered line\n' >>"$INST_LIB/README.md"
tree_mod_file=$(_tree_digest "$INST_LIB")
mod_out=$(HOME="$FAKE_HOME" "$INST_BIN" 2>&1)
assert_eq 6 $? "install.sh refuses reinstall when an installed file (README.md) was modified"
assert_eq "$tree_mod_file" "$(_tree_digest "$INST_LIB")" "modified installation preserved byte-for-byte on rejected reinstall"
assert_not_contains "$mod_out" "Installed AUTHFORGE" "no success message printed when installed file modified"
mv "$SB/readme_orig.bak" "$INST_LIB/README.md"
chmod 644 "$INST_LIB/README.md"

# (iv) Missing listed file
mv "$INST_LIB/LICENSE" "$SB/license_orig.bak"
tree_missing_file=$(_tree_digest "$INST_LIB")
miss_out=$(HOME="$FAKE_HOME" "$INST_BIN" 2>&1)
assert_eq 6 $? "install.sh refuses reinstall when a manifested file (LICENSE) is missing"
assert_eq "$tree_missing_file" "$(_tree_digest "$INST_LIB")" "installation preserved byte-for-byte when listed file is missing"
assert_not_contains "$miss_out" "Installed AUTHFORGE" "no success message printed when listed file missing"
(HOME="$FAKE_HOME" "$UNINST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "uninstall.sh refuses when a manifested file (LICENSE) is missing"
mv "$SB/license_orig.bak" "$INST_LIB/LICENSE"
chmod 644 "$INST_LIB/LICENSE"

# (v) Duplicate manifest FILE entry
readme_line=$(grep -E '^FILE .* README\.md$' "$INST_LIB/.authforge-install.manifest")
printf '%s\n' "$readme_line" >>"$INST_LIB/.authforge-install.manifest"
chmod 644 "$INST_LIB/.authforge-install.manifest"
tree_dup_man=$(_tree_digest "$INST_LIB")
dup_out=$(HOME="$FAKE_HOME" "$INST_BIN" 2>&1)
assert_eq 6 $? "install.sh refuses reinstall when manifest contains a duplicate FILE entry"
assert_eq "$tree_dup_man" "$(_tree_digest "$INST_LIB")" "installation preserved byte-for-byte on duplicate manifest entry"
assert_not_contains "$dup_out" "Installed AUTHFORGE" "no success message printed on duplicate manifest entry"
(HOME="$FAKE_HOME" "$UNINST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "uninstall.sh refuses manifest containing a duplicate FILE entry"
cp -p "$SB/valid_manifest.bak" "$INST_LIB/.authforge-install.manifest"
chmod 644 "$INST_LIB/.authforge-install.manifest"

# (vi) Path traversal FILE entry (../outside-file) in manifest
printf 'outside secret\n' >"$FAKE_HOME/.local/share/outside-file"
outside_sha=$(sha256sum "$FAKE_HOME/.local/share/outside-file" | awk '{print $1}')
printf 'FILE 644 %s ../outside-file\n' "$outside_sha" >>"$INST_LIB/.authforge-install.manifest"
chmod 644 "$INST_LIB/.authforge-install.manifest"
trav_out=$(HOME="$FAKE_HOME" "$INST_BIN" 2>&1)
assert_eq 6 $? "install.sh rejects manifest with ../outside-file path traversal entry"
[[ -f "$FAKE_HOME/.local/share/outside-file" ]] && t_ok "../outside-file untouched after install.sh rejection" || t_fail "../outside-file lost"
assert_not_contains "$trav_out" "Installed AUTHFORGE" "no success message printed on path traversal entry"
(HOME="$FAKE_HOME" "$UNINST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "uninstall.sh rejects manifest with ../outside-file path traversal entry"
[[ -f "$FAKE_HOME/.local/share/outside-file" ]] && t_ok "../outside-file untouched after uninstall.sh rejection" || t_fail "../outside-file deleted by uninstall.sh"
rm -f "$FAKE_HOME/.local/share/outside-file"
cp -p "$SB/valid_manifest.bak" "$INST_LIB/.authforge-install.manifest"
chmod 644 "$INST_LIB/.authforge-install.manifest"

# (vii) Absolute FILE path entry in manifest
printf 'abs target\n' >"$SB/abs-target.txt"
abs_sha=$(sha256sum "$SB/abs-target.txt" | awk '{print $1}')
printf 'FILE 644 %s %s/abs-target.txt\n' "$abs_sha" "$SB" >>"$INST_LIB/.authforge-install.manifest"
chmod 644 "$INST_LIB/.authforge-install.manifest"
abs_out=$(HOME="$FAKE_HOME" "$INST_BIN" 2>&1)
assert_eq 6 $? "install.sh rejects manifest with absolute FILE path entry"
[[ -f "$SB/abs-target.txt" ]] && t_ok "absolute target untouched after install.sh rejection" || t_fail "absolute target lost"
assert_not_contains "$abs_out" "Installed AUTHFORGE" "no success message printed on absolute path entry"
(HOME="$FAKE_HOME" "$UNINST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "uninstall.sh rejects manifest with absolute FILE path entry"
[[ -f "$SB/abs-target.txt" ]] && t_ok "absolute target untouched after uninstall.sh rejection" || t_fail "absolute target deleted by uninstall.sh"
rm -f "$SB/abs-target.txt"
cp -p "$SB/valid_manifest.bak" "$INST_LIB/.authforge-install.manifest"
chmod 644 "$INST_LIB/.authforge-install.manifest"

# (viii) Symlink escape on FILE (manifested file replaced by symlink to external file with identical SHA-256)
cp -p "$INST_LIB/README.md" "$SB/outside-readme.md"
mv "$INST_LIB/README.md" "$SB/readme_real.bak"
ln -s "$SB/outside-readme.md" "$INST_LIB/README.md"
sym_out=$(HOME="$FAKE_HOME" "$INST_BIN" 2>&1)
assert_eq 6 $? "install.sh rejects symlink escape when manifested file is replaced by symlink"
[[ -f "$SB/outside-readme.md" && -L "$INST_LIB/README.md" ]] && t_ok "symlink escape rejected without deleting target" || t_fail "symlink target affected"
assert_not_contains "$sym_out" "Installed AUTHFORGE" "no success message printed on symlink escape"
(HOME="$FAKE_HOME" "$UNINST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "uninstall.sh rejects symlink escape when manifested file is replaced by symlink"
rm -f "$INST_LIB/README.md" "$SB/outside-readme.md"
mv "$SB/readme_real.bak" "$INST_LIB/README.md"
chmod 644 "$INST_LIB/README.md"
assert_eq "$valid_tree_sha" "$(_tree_digest "$INST_LIB")" "restored installation matches exact pre-matrix tree digest"

# =========================================================================
# 6c. V2 MANIFEST DIRECTORY-MODE REGRESSION SUITE (12 Mandatory Cases)
# =========================================================================
# V2-1: Correct directory mode (755): accepted
(HOME="$FAKE_HOME" "$INST_BIN" --dry-run >/dev/null 2>&1)
assert_eq 0 $? "V2-1: v2 manifest with matching directory modes (755) is accepted"

# V2-2: Directory mode changed after installation (755 -> 700): rejected by both install.sh and uninstall.sh
chmod 700 "$INST_LIB/core"
(HOME="$FAKE_HOME" "$INST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "V2-2a: install.sh rejects when directory mode changed after installation (core 755 -> 700)"
(HOME="$FAKE_HOME" "$UNINST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "V2-2b: uninstall.sh rejects when directory mode changed after installation (core 755 -> 700)"
assert_eq "$valid_tree_sha" "$(_tree_digest "$INST_LIB")" "V2-2c: files preserved byte-for-byte after directory mode mismatch"
chmod 755 "$INST_LIB/core"

# V2-3: Group/world-writable directory (775 / 777): rejected
chmod 775 "$INST_LIB/core"
(HOME="$FAKE_HOME" "$INST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "V2-3a: install.sh rejects group-writable (0775) directory"
(HOME="$FAKE_HOME" "$UNINST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "V2-3b: uninstall.sh rejects group-writable (0775) directory"
chmod 755 "$INST_LIB/core"

# V2-4: Invalid octal mode in DIR entry (e.g., 758): rejected
sed -i 's/^DIR core 755$/DIR core 758/' "$INST_LIB/.authforge-install.manifest"
(HOME="$FAKE_HOME" "$INST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "V2-4a: install.sh rejects invalid octal mode (758) in DIR entry"
(HOME="$FAKE_HOME" "$UNINST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "V2-4b: uninstall.sh rejects invalid octal mode (758) in DIR entry"
cp -p "$SB/valid_manifest.bak" "$INST_LIB/.authforge-install.manifest"

# V2-5: Missing mode field in v2 DIR entry (DIR core): rejected (no silent v1 reinterpretation)
sed -i 's/^DIR core 755$/DIR core/' "$INST_LIB/.authforge-install.manifest"
(HOME="$FAKE_HOME" "$INST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "V2-5a: install.sh rejects missing mode field in v2 DIR entry"
(HOME="$FAKE_HOME" "$UNINST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "V2-5b: uninstall.sh rejects missing mode field in v2 DIR entry"
cp -p "$SB/valid_manifest.bak" "$INST_LIB/.authforge-install.manifest"

# V2-6: Extra field in v2 DIR entry (DIR core 755 extra): rejected
sed -i 's/^DIR core 755$/DIR core 755 extra/' "$INST_LIB/.authforge-install.manifest"
(HOME="$FAKE_HOME" "$INST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "V2-6a: install.sh rejects extra field in v2 DIR entry"
(HOME="$FAKE_HOME" "$UNINST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "V2-6b: uninstall.sh rejects extra field in v2 DIR entry"
cp -p "$SB/valid_manifest.bak" "$INST_LIB/.authforge-install.manifest"

# V2-7: Duplicate directory entry: rejected
printf 'DIR core 755\n' >>"$INST_LIB/.authforge-install.manifest"
(HOME="$FAKE_HOME" "$INST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "V2-7a: install.sh rejects duplicate DIR entry in manifest"
(HOME="$FAKE_HOME" "$UNINST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "V2-7b: uninstall.sh rejects duplicate DIR entry in manifest"
cp -p "$SB/valid_manifest.bak" "$INST_LIB/.authforge-install.manifest"

# V2-8: Missing required directory entry: rejected
sed -i '/^DIR core 755$/d' "$INST_LIB/.authforge-install.manifest"
(HOME="$FAKE_HOME" "$INST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "V2-8a: install.sh rejects missing required DIR entry (core)"
(HOME="$FAKE_HOME" "$UNINST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "V2-8b: uninstall.sh rejects missing required DIR entry (core)"
cp -p "$SB/valid_manifest.bak" "$INST_LIB/.authforge-install.manifest"

# V2-9: Unexpected directory on disk: rejected
mkdir -p "$INST_LIB/unexpected_subdir"
(HOME="$FAKE_HOME" "$INST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "V2-9a: install.sh rejects unexpected directory on disk"
(HOME="$FAKE_HOME" "$UNINST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "V2-9b: uninstall.sh rejects unexpected directory on disk"
rmdir "$INST_LIB/unexpected_subdir"

# V2-10: Symlinked directory: rejected
mv "$INST_LIB/docs" "$SB/docs_real_dir"
ln -s "$SB/docs_real_dir" "$INST_LIB/docs"
(HOME="$FAKE_HOME" "$INST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "V2-10a: install.sh rejects symlinked manifested directory (docs)"
(HOME="$FAKE_HOME" "$UNINST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "V2-10b: uninstall.sh rejects symlinked manifested directory (docs)"
rm -f "$INST_LIB/docs"
mv "$SB/docs_real_dir" "$INST_LIB/docs"

# V2-11: Path traversal directory entry (DIR ../outside 755): rejected
printf 'DIR ../outside 755\n' >>"$INST_LIB/.authforge-install.manifest"
(HOME="$FAKE_HOME" "$INST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "V2-11a: install.sh rejects path traversal DIR entry (../outside)"
(HOME="$FAKE_HOME" "$UNINST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "V2-11b: uninstall.sh rejects path traversal DIR entry (../outside)"
cp -p "$SB/valid_manifest.bak" "$INST_LIB/.authforge-install.manifest"

# V2-12: Absolute directory path (DIR /tmp/abs 755): rejected
printf 'DIR /tmp/abs 755\n' >>"$INST_LIB/.authforge-install.manifest"
(HOME="$FAKE_HOME" "$INST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "V2-12a: install.sh rejects absolute DIR entry (/tmp/abs)"
(HOME="$FAKE_HOME" "$UNINST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "V2-12b: uninstall.sh rejects absolute DIR entry (/tmp/abs)"
cp -p "$SB/valid_manifest.bak" "$INST_LIB/.authforge-install.manifest"
assert_eq "$valid_tree_sha" "$(_tree_digest "$INST_LIB")" "V2 suite left $INST_LIB byte-for-byte intact"

# =========================================================================
# 6c-bis. SPECIAL DIRECTORY PERMISSION BITS & 4-DIGIT MODE REJECTION SUITE
# =========================================================================
# External sentinel file to verify unrelated files remain untouched across all rejected cases
printf 'UNRELATED_SENTINEL_DATA\n' >"$SB/unrelated_sentinel.txt"
sentinel_sha=$(sha256sum "$SB/unrelated_sentinel.txt" | awk '{print $1}')

# (A) Manifest-supplied special/4-digit modes (4755, 2755, 1755, 0755, 7755) when disk is 755
for bad_dmode in 4755 2755 1755 0755 7755; do
  sed -i "s/^DIR core 755$/DIR core $bad_dmode/" "$INST_LIB/.authforge-install.manifest"
  expect_tree=$(_tree_digest "$INST_LIB")
  inst_s_out=$(HOME="$FAKE_HOME" "$INST_BIN" 2>&1)
  assert_eq 6 $? "Special-A ($bad_dmode): install.sh rejects DIR core $bad_dmode in manifest"
  assert_not_contains "$inst_s_out" "Installed AUTHFORGE" "Special-A ($bad_dmode): install.sh prints no success message"
  uninst_s_out=$(HOME="$FAKE_HOME" "$UNINST_BIN" 2>&1)
  assert_eq 6 $? "Special-A ($bad_dmode): uninstall.sh rejects DIR core $bad_dmode in manifest"
  assert_not_contains "$uninst_s_out" "Removed AUTHFORGE" "Special-A ($bad_dmode): uninstall.sh prints no success message"
  assert_eq "$expect_tree" "$(_tree_digest "$INST_LIB")" "Special-A ($bad_dmode): existing installation preserved byte-for-byte"
  assert_eq "$sentinel_sha" "$(sha256sum "$SB/unrelated_sentinel.txt" | awk '{print $1}')" "Special-A ($bad_dmode): unrelated file intact"
  cp -p "$SB/valid_manifest.bak" "$INST_LIB/.authforge-install.manifest"
done

# (B) Actual on-disk directory changed to special mode (4755, 2755, 1755) while manifest has 755
for disk_smode in 4755 2755 1755; do
  chmod "$disk_smode" "$INST_LIB/core"
  inst_d_out=$(HOME="$FAKE_HOME" "$INST_BIN" 2>&1)
  assert_eq 6 $? "Special-B ($disk_smode): install.sh rejects on-disk directory mode $disk_smode"
  assert_not_contains "$inst_d_out" "Installed AUTHFORGE" "Special-B ($disk_smode): install.sh prints no success message"
  uninst_d_out=$(HOME="$FAKE_HOME" "$UNINST_BIN" 2>&1)
  assert_eq 6 $? "Special-B ($disk_smode): uninstall.sh rejects on-disk directory mode $disk_smode"
  assert_not_contains "$uninst_d_out" "Removed AUTHFORGE" "Special-B ($disk_smode): uninstall.sh prints no success message"
  assert_eq "$valid_tree_sha" "$(_tree_digest "$INST_LIB")" "Special-B ($disk_smode): existing installation files preserved byte-for-byte"
  chmod 00755 "$INST_LIB/core"
done

# (C) Manifest AND actual on-disk directory BOTH containing the same special bits (4755, 2755, 1755)
for both_smode in 4755 2755 1755; do
  sed -i "s/^DIR core 755$/DIR core $both_smode/" "$INST_LIB/.authforge-install.manifest"
  chmod "$both_smode" "$INST_LIB/core"
  expect_both_tree=$(_tree_digest "$INST_LIB")
  inst_b_out=$(HOME="$FAKE_HOME" "$INST_BIN" 2>&1)
  assert_eq 6 $? "Special-C ($both_smode): install.sh rejects matching special mode $both_smode on manifest and disk"
  assert_not_contains "$inst_b_out" "Installed AUTHFORGE" "Special-C ($both_smode): install.sh prints no success message"
  uninst_b_out=$(HOME="$FAKE_HOME" "$UNINST_BIN" 2>&1)
  assert_eq 6 $? "Special-C ($both_smode): uninstall.sh rejects matching special mode $both_smode on manifest and disk"
  assert_not_contains "$uninst_b_out" "Removed AUTHFORGE" "Special-C ($both_smode): uninstall.sh prints no success message"
  assert_eq "$expect_both_tree" "$(_tree_digest "$INST_LIB")" "Special-C ($both_smode): existing installation preserved byte-for-byte"
  chmod 00755 "$INST_LIB/core"
  cp -p "$SB/valid_manifest.bak" "$INST_LIB/.authforge-install.manifest"
done

# (D) Normal 3-digit directory modes 700, 750, and 755 continue to work when recorded and matching on disk
for norm_mode in 700 750 755; do
  sed -i "s/^DIR core 755$/DIR core $norm_mode/" "$INST_LIB/.authforge-install.manifest"
  chmod "0$norm_mode" "$INST_LIB/core"
  (HOME="$FAKE_HOME" "$INST_BIN" --dry-run >/dev/null 2>&1)
  assert_eq 0 $? "Normal mode $norm_mode: install.sh --dry-run accepts matching 3-digit mode $norm_mode"
  (HOME="$FAKE_HOME" "$UNINST_BIN" --dry-run >/dev/null 2>&1)
  assert_eq 0 $? "Normal mode $norm_mode: uninstall.sh --dry-run accepts matching 3-digit mode $norm_mode"
  chmod 0755 "$INST_LIB/core"
  cp -p "$SB/valid_manifest.bak" "$INST_LIB/.authforge-install.manifest"
done
assert_eq "$valid_tree_sha" "$(_tree_digest "$INST_LIB")" "Special-mode suite left $INST_LIB byte-for-byte intact"

# =========================================================================
# 6d. V1 COMPATIBILITY & CONTROLLED MIGRATION SUITE (7 Mandatory Cases)
# =========================================================================
V1_HOME="$SB/v1_home"
mkdir -p "$V1_HOME"
chmod 700 "$V1_HOME"
(HOME="$V1_HOME" XDG_DATA_HOME="" XDG_STATE_HOME="" "$INST_BIN" >/dev/null 2>&1)
assert_eq 0 $? "setup isolated installation for v1 migration tests"

V1_LIB="$V1_HOME/.local/share/authforge"
# Convert its manifest to authentic v1 schema (format=authforge-install-manifest-v1 and 2-token DIR <subdir>)
sed -E -e 's/^format=authforge-install-manifest-v2$/format=authforge-install-manifest-v1/' \
       -e 's/^DIR ([a-z_]+) [0-7]{3,4}$/DIR \1/' \
       "$V1_LIB/.authforge-install.manifest" >"$SB/v1_manifest.clean"
cp -p "$SB/v1_manifest.clean" "$V1_LIB/.authforge-install.manifest"
chmod 644 "$V1_LIB/.authforge-install.manifest"
v1_tree_sha=$(_tree_digest "$V1_LIB")

# V1-1: Valid v1 manifest passes dry-run verification under controlled migration policy
(HOME="$V1_HOME" "$INST_BIN" --dry-run >/dev/null 2>&1)
assert_eq 0 $? "V1-1: valid v1 manifest passes full pre-migration verification (--dry-run)"

# V1-2: Malformed v1 manifest (e.g. v2 3-token DIR inside v1 manifest): rejected without modifying files
sed -i 's/^DIR core$/DIR core 755/' "$V1_LIB/.authforge-install.manifest"
tree_v1_mal=$(_tree_digest "$V1_LIB")
(HOME="$V1_HOME" "$INST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "V1-2a: malformed v1 manifest is rejected by install.sh"
assert_eq "$tree_v1_mal" "$(_tree_digest "$V1_LIB")" "V1-2b: malformed v1 installation preserved byte-for-byte"
cp -p "$SB/v1_manifest.clean" "$V1_LIB/.authforge-install.manifest"

# V1-3: V1 manifest with modified file: rejected
cp -p "$V1_LIB/README.md" "$SB/v1_readme.bak"
printf 'v1 tamper\n' >>"$V1_LIB/README.md"
tree_v1_mod=$(_tree_digest "$V1_LIB")
(HOME="$V1_HOME" "$INST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "V1-3a: v1 manifest with modified file is rejected by install.sh"
assert_eq "$tree_v1_mod" "$(_tree_digest "$V1_LIB")" "V1-3b: v1 installation with modified file preserved byte-for-byte"
mv "$SB/v1_readme.bak" "$V1_LIB/README.md"
chmod 644 "$V1_LIB/README.md"

# V1-4: V1 manifest with unexpected file: rejected
printf 'v1 extra\n' >"$V1_LIB/keep-important.txt"
tree_v1_ext=$(_tree_digest "$V1_LIB")
(HOME="$V1_HOME" "$INST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "V1-4a: v1 manifest with unexpected file is rejected by install.sh"
assert_eq "$tree_v1_ext" "$(_tree_digest "$V1_LIB")" "V1-4b: v1 installation with unexpected file preserved byte-for-byte"
rm -f "$V1_LIB/keep-important.txt"

# V1-5: V1 manifest with unsafe permissions (0775) or special permission bits (4755, 2755, 1755) during migration: rejected
chmod 0775 "$V1_LIB/core"
(HOME="$V1_HOME" "$INST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "V1-5a: v1 manifest with group-writable directory (0775) is rejected"
chmod 00755 "$V1_LIB/core"

for v1_smode in 4755 2755 1755; do
  chmod "$v1_smode" "$V1_LIB/core"
  v1_s_out=$(HOME="$V1_HOME" "$INST_BIN" 2>&1)
  assert_eq 6 $? "V1-5b ($v1_smode): v1 migration rejects directory with special bits ($v1_smode)"
  assert_not_contains "$v1_s_out" "Installed AUTHFORGE" "V1-5b ($v1_smode): no success message on v1 special-bit rejection"
  (HOME="$V1_HOME" "$UNINST_BIN" >/dev/null 2>&1)
  assert_eq 6 $? "V1-5c ($v1_smode): uninstall.sh rejects v1 directory with special bits ($v1_smode)"
  assert_eq "$v1_tree_sha" "$(_tree_digest "$V1_LIB")" "V1-5d ($v1_smode): v1 installation preserved byte-for-byte"
  chmod 00755 "$V1_LIB/core"
done

# V1-6: Migration failure rolls back and leaves original v1 installation byte-for-byte unchanged
(HOME="$V1_HOME" AN_INSTALL_FAIL_AFTER_SWAP=1 "$INST_BIN" >/dev/null 2>&1)
assert_eq 1 $? "V1-6a: simulated post-swap failure during v1->v2 migration exits 1"
assert_eq "format=authforge-install-manifest-v1" "$(head -n 1 "$V1_LIB/.authforge-install.manifest")" "V1-6b: rollback restores original v1 manifest"
assert_eq "$v1_tree_sha" "$(_tree_digest "$V1_LIB")" "V1-6c: original v1 installation remains byte-for-byte unchanged after migration failure"

# V1-7: Successful controlled migration from v1 to v2 generates a valid v2 manifest
(HOME="$V1_HOME" "$INST_BIN" >/dev/null 2>&1)
assert_eq 0 $? "V1-7a: controlled migration from valid v1 installation succeeds"
assert_eq "format=authforge-install-manifest-v2" "$(head -n 1 "$V1_LIB/.authforge-install.manifest")" "V1-7b: migrated installation has format=authforge-install-manifest-v2"
assert_contains "$(<"$V1_LIB/.authforge-install.manifest")" "DIR core 755" "V1-7c: migrated v2 manifest records DIR core 755"
(HOME="$V1_HOME" "$UNINST_BIN" --dry-run >/dev/null 2>&1)
assert_eq 0 $? "V1-7d: migrated v2 installation passes uninstall.sh --dry-run verification"

# Also test unsupported manifest version (v99) on uninstall.sh and install.sh
cp -p "$V1_LIB/.authforge-install.manifest" "$SB/v2_mig.bak"
sed -i 's/^format=authforge-install-manifest-v2$/format=authforge-install-manifest-v99/' "$V1_LIB/.authforge-install.manifest"
tree_v99=$(_tree_digest "$V1_LIB")
(HOME="$V1_HOME" "$UNINST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "Uninstaller refuses unsupported manifest version (format=authforge-install-manifest-v99)"
(HOME="$V1_HOME" "$INST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "Installer refuses unsupported manifest version (format=authforge-install-manifest-v99)"
assert_eq "$tree_v99" "$(_tree_digest "$V1_LIB")" "Unsupported manifest version leaves installation byte-for-byte intact"
cp -p "$SB/v2_mig.bak" "$V1_LIB/.authforge-install.manifest"
(HOME="$V1_HOME" "$UNINST_BIN" --purge-data >/dev/null 2>&1)
assert_eq 0 $? "Clean up migrated v1_home installation via --purge-data"

# 7. Repeated / idempotent installation on verified valid installation preserves existing user data and custom config
printf '# custom comment\npolicy_min_length=14\n' >>"$INST_DATA/config/authforge.conf"
(HOME="$FAKE_HOME" XDG_DATA_HOME="" XDG_STATE_HOME="" "$INST_BIN" >/dev/null 2>&1)
assert_eq 0 $? "repeated (idempotent) installation on valid verified installation succeeds"
[[ -f "$INST_DATA/reports/$inst_sid/findings.dat" ]] && t_ok "idempotent reinstall preserves existing session reports" || t_fail "session lost on reinstall"
assert_contains "$(<"$INST_DATA/config/authforge.conf")" "policy_min_length=14" "idempotent reinstall preserves user config customizations"

# 8. Failed installation rollback test (simulated launcher creation failure after swap)
before_manifest=$(<"$INST_LIB/.authforge-install.manifest")
(HOME="$FAKE_HOME" AN_INSTALL_FAIL_AFTER_SWAP=1 "$INST_BIN" >/dev/null 2>&1)
assert_eq 1 $? "install.sh exits 1 when post-swap launcher step fails"
assert_eq "$before_manifest" "$(<"$INST_LIB/.authforge-install.manifest")" "failed reinstall rolls back and preserves previous working installation"

# 9. Read-only code tree simulation + config backup/restore in installed mode
chmod -R a-w "$INST_LIB"
ro_cfg_out=$(HOME="$FAKE_HOME" AN_DATA_DIR="" "$INST_LAUNCHER" --no-color config backup 2>&1)
assert_eq 0 $? "config backup succeeds when code tree (AN_ROOT) is read-only"
assert_contains "$ro_cfg_out" "$INST_DATA/backups/" "config backup writes into AN_DATA_DIR/backups"

sed -i 's/policy_min_length=14/policy_min_length=16/' "$INST_DATA/config/authforge.conf"
HOME="$FAKE_HOME" AN_DATA_DIR="" "$INST_LAUNCHER" --no-color config restore "$ro_cfg_out" >/dev/null 2>&1
assert_eq 0 $? "config restore succeeds when code tree (AN_ROOT) is read-only"
assert_contains "$(<"$INST_DATA/config/authforge.conf")" "policy_min_length=14" "config restore restores mutable config in AN_DATA_DIR/config"

# Reject symlinked file inside backup directory during config restore
ln -s /etc/passwd "$ro_cfg_out/evil.conf"
HOME="$FAKE_HOME" AN_DATA_DIR="" "$INST_LAUNCHER" --no-color config restore "$ro_cfg_out" >/dev/null 2>&1
assert_eq 6 $? "config restore rejects symlinked file inside backup directory (6)"
rm -f "$ro_cfg_out/evil.conf"
chmod -R u+w "$INST_LIB"

# 10. Safe launcher hardening (rejects group/world-writable target or code root)
chmod 777 "$INST_LIB/authforge.sh"
HOME="$FAKE_HOME" AN_DATA_DIR="" "$INST_LAUNCHER" --version >/dev/null 2>&1
assert_eq 4 $? "authforge-safe.sh refuses to execute world-writable (0777) authforge.sh"
chmod 755 "$INST_LIB/authforge.sh"

chmod 777 "$INST_LIB"
HOME="$FAKE_HOME" AN_DATA_DIR="" "$INST_LAUNCHER" --version >/dev/null 2>&1
assert_eq 4 $? "authforge-safe.sh refuses to execute from world-writable (0777) code root"
chmod 755 "$INST_LIB"

# 11. Uninstaller security checks: unrelated file, modified file, tampered manifest
printf 'unrelated\n' >"$INST_LIB/unrelated.txt"
(HOME="$FAKE_HOME" "$UNINST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "uninstall.sh refuses when an unmanifested file exists in code directory"
rm -f "$INST_LIB/unrelated.txt"

cp "$INST_LIB/README.md" "$SB/readme.bak"
printf 'modified\n' >>"$INST_LIB/README.md"
(HOME="$FAKE_HOME" "$UNINST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "uninstall.sh refuses when an installed file was modified after installation"
mv "$SB/readme.bak" "$INST_LIB/README.md"
chmod 644 "$INST_LIB/README.md"

cp "$INST_LIB/.authforge-install.manifest" "$SB/manifest.bak"
printf 'corrupt_line\n' >>"$INST_LIB/.authforge-install.manifest"
(HOME="$FAKE_HOME" "$UNINST_BIN" >/dev/null 2>&1)
assert_eq 6 $? "uninstall.sh refuses malformed installation manifest"
mv "$SB/manifest.bak" "$INST_LIB/.authforge-install.manifest"
chmod 644 "$INST_LIB/.authforge-install.manifest"

# 12. Normal uninstall preserves user data (reports, logs, evidence, backups, config)
(HOME="$FAKE_HOME" "$UNINST_BIN" >/dev/null 2>&1)
assert_eq 0 $? "normal uninstall succeeds on verified installation"
[[ ! -e "$INST_LIB" && ! -L "$INST_LAUNCHER" ]] &&
  t_ok "normal uninstall removes code directory and launcher symlink" ||
  t_fail "code directory or launcher symlink still exists after uninstall"
[[ -f "$INST_DATA/reports/$inst_sid/findings.dat" && -f "$INST_DATA/evidence/$inst_sid/manifest.sha256" ]] &&
  t_ok "normal uninstall preserves user runtime data and evidence in AN_DATA_DIR" ||
  t_fail "user data was lost during normal uninstall"

# 13. Reinstall and test --purge-data (refuses unknown file in datadir, succeeds when clean)
(HOME="$FAKE_HOME" "$INST_BIN" >/dev/null 2>&1)
assert_eq 0 $? "reinstall after uninstall succeeds"

printf 'important note\n' >"$INST_DATA/user_notes.txt"
(HOME="$FAKE_HOME" "$UNINST_BIN" --purge-data >/dev/null 2>&1)
assert_eq 6 $? "uninstall.sh --purge-data refuses when unknown file exists in datadir"
[[ -d "$INST_LIB" && -d "$INST_DATA" ]] && t_ok "aborted --purge-data leaves installation and data intact" || t_fail "aborted purge deleted files"
rm -f "$INST_DATA/user_notes.txt"

(HOME="$FAKE_HOME" "$UNINST_BIN" --purge-data >/dev/null 2>&1)
assert_eq 0 $? "uninstall.sh --purge-data succeeds on verified AUTHFORGE data directory"
[[ ! -e "$INST_LIB" && ! -L "$INST_LAUNCHER" && ! -e "$INST_DATA" ]] &&
  t_ok "--purge-data removes code, launcher, and validated data directory" ||
  t_fail "--purge-data left directories behind"

# =========================================================================
# 13b. PRE-CHMOD DIRECTORY VALIDATION & FAILURE-INJECTION REGRESSION SUITE
# =========================================================================
PC_BASE="$SB/prechmod_suite"
mkdir -p "$PC_BASE"
chmod 0700 "$PC_BASE"
printf 'PRECHMOD_SENTINEL_UNTOUCHED\n' >"$PC_BASE/sentinel.txt"
pc_sentinel_sha=$(sha256sum "$PC_BASE/sentinel.txt" | awk '{print $1}')

# 1. Pre-existing datadir and datadir/logs with special bits (4755, 2755, 1755)
# Must be rejected BEFORE chmod 0700 runs, leaving the original special mode on disk unchanged!
for smode in 4755 2755 1755; do
  pc_sub="$PC_BASE/data_case_$smode"
  mkdir -p "$pc_sub/data/logs" "$pc_sub/bin"
  chmod 0700 "$pc_sub" "$pc_sub/data"
  chmod 0755 "$pc_sub/bin"
  printf 'existing_log_entry\n' >"$pc_sub/data/logs/keep.log"
  keep_log_sha=$(sha256sum "$pc_sub/data/logs/keep.log" | awk '{print $1}')
  chmod "$smode" "$pc_sub/data/logs"

  pc_out=$("$INST_BIN" --libdir "$pc_sub/lib" --bindir "$pc_sub/bin" --datadir "$pc_sub/data" 2>&1)
  pc_rc=$?
  assert_eq 6 "$pc_rc" "Pre-chmod datadir/logs ($smode): install.sh exits 6 before chmod"
  assert_not_contains "$pc_out" "Installed AUTHFORGE" "Pre-chmod datadir/logs ($smode): no success message"
  assert_eq "$smode" "$(stat -c '%a' "$pc_sub/data/logs")" "Pre-chmod datadir/logs ($smode): original directory mode $smode remains UNCHANGED on disk"
  assert_eq "$keep_log_sha" "$(sha256sum "$pc_sub/data/logs/keep.log" | awk '{print $1}')" "Pre-chmod datadir/logs ($smode): existing file SHA-256 unchanged"
  [[ ! -e "$pc_sub/lib" ]] && t_ok "Pre-chmod datadir/logs ($smode): no partial installation left behind" || t_fail "partial lib created"
  chmod 00700 "$pc_sub/data/logs"
  rm -rf "$pc_sub"
done

# 2. Pre-existing user-local parent directory (lib_parent) and bindir with special bits (4755, 2755, 1755)
# Must be rejected BEFORE chmod 0755 runs, leaving the original special mode on disk unchanged!
for smode in 4755 2755 1755; do
  pc_p="$PC_BASE/parent_case_$smode"
  mkdir -p "$pc_p/share" "$pc_p/bin" "$pc_p/data"
  chmod 0700 "$pc_p" "$pc_p/data"
  chmod 0755 "$pc_p/bin"
  chmod "$smode" "$pc_p/share"

  pc_out=$("$INST_BIN" --libdir "$pc_p/share/authforge" --bindir "$pc_p/bin" --datadir "$pc_p/data" 2>&1)
  pc_rc=$?
  assert_eq 6 "$pc_rc" "Pre-chmod lib_parent ($smode): install.sh exits 6 before chmod"
  assert_not_contains "$pc_out" "Installed AUTHFORGE" "Pre-chmod lib_parent ($smode): no success message"
  assert_eq "$smode" "$(stat -c '%a' "$pc_p/share")" "Pre-chmod lib_parent ($smode): original mode $smode remains UNCHANGED on disk"
  [[ ! -e "$pc_p/share/authforge" ]] && t_ok "Pre-chmod lib_parent ($smode): no partial installation left behind" || t_fail "partial install created"
  chmod 00755 "$pc_p/share"

  chmod "$smode" "$pc_p/bin"
  pc_out2=$("$INST_BIN" --libdir "$pc_p/share/authforge" --bindir "$pc_p/bin" --datadir "$pc_p/data" 2>&1)
  pc_rc2=$?
  assert_eq 6 "$pc_rc2" "Pre-chmod bindir ($smode): install.sh exits 6 before chmod"
  assert_not_contains "$pc_out2" "Installed AUTHFORGE" "Pre-chmod bindir ($smode): no success message"
  assert_eq "$smode" "$(stat -c '%a' "$pc_p/bin")" "Pre-chmod bindir ($smode): original mode $smode remains UNCHANGED on disk"
  chmod 00755 "$pc_p/bin"
  rm -rf "$pc_p"
done

# 3. Pre-existing directories with normal safe modes (700, 750, 755) on parent, bindir, and datadir continue to work
for nmode in 700 750 755; do
  pc_norm="$PC_BASE/norm_case_$nmode"
  mkdir -p "$pc_norm/share" "$pc_norm/bin" "$pc_norm/data/logs"
  chmod "0$nmode" "$pc_norm/share" "$pc_norm/bin" "$pc_norm/data" "$pc_norm/data/logs"
  "$INST_BIN" --libdir "$pc_norm/share/authforge" --bindir "$pc_norm/bin" --datadir "$pc_norm/data" >/dev/null 2>&1
  assert_eq 0 $? "Pre-existing safe mode ($nmode): install.sh succeeds"
  assert_eq "$nmode" "$(stat -c '%a' "$pc_norm/share")" "Pre-existing lib_parent safe mode ($nmode) preserved"
  assert_eq "$nmode" "$(stat -c '%a' "$pc_norm/bin")" "Pre-existing bindir safe mode ($nmode) preserved"
  assert_eq "700" "$(stat -c '%a' "$pc_norm/data")" "Validated datadir ($nmode -> 700) enforced to 700"
  assert_eq "700" "$(stat -c '%a' "$pc_norm/data/logs")" "Validated datadir/logs ($nmode -> 700) enforced to 700"
  "$UNINST_BIN" --libdir "$pc_norm/share/authforge" --bindir "$pc_norm/bin" --datadir "$pc_norm/data" --purge-data >/dev/null 2>&1
  assert_eq 0 $? "Pre-existing safe mode ($nmode): uninstall.sh --purge-data succeeds"
  rm -rf "$pc_norm"
done

# 4. Existing installation directory with special bits on root ($libdir) or subdirectory ($libdir/core):
# Verify original special mode (4755, 2755, 1755) remains UNCHANGED on disk when rejected!
PC_INST="$PC_BASE/inst_check"
mkdir -p "$PC_INST"
chmod 0700 "$PC_INST"
"$INST_BIN" --libdir "$PC_INST/lib" --bindir "$PC_INST/bin" --datadir "$PC_INST/data" >/dev/null 2>&1
assert_eq 0 $? "Setup installation for pre-chmod existing-install mode preservation checks"
cp -p "$PC_INST/lib/.authforge-install.manifest" "$PC_BASE/pc_manifest.bak"
pc_inst_tree=$(_tree_digest "$PC_INST/lib")

for smode in 4755 2755 1755; do
  # Case 4a: Manifest has ordinary safe mode (755), actual directory has special bit
  chmod "$smode" "$PC_INST/lib/core"
  out_4a=$("$INST_BIN" --libdir "$PC_INST/lib" --bindir "$PC_INST/bin" --datadir "$PC_INST/data" 2>&1)
  assert_eq 6 $? "Case 4a ($smode): install.sh rejects when actual core dir has mode $smode"
  assert_not_contains "$out_4a" "Installed AUTHFORGE" "Case 4a ($smode): no success message"
  assert_eq "$smode" "$(stat -c '%a' "$PC_INST/lib/core")" "Case 4a ($smode): core dir mode $smode remains UNCHANGED"
  assert_eq "$pc_inst_tree" "$(_tree_digest "$PC_INST/lib")" "Case 4a ($smode): files and SHA-256 hashes unchanged"
  chmod 00755 "$PC_INST/lib/core"

  # Case 4b: Both manifest and actual directory contain the same special-bit mode
  sed -i "s/^DIR core 755$/DIR core $smode/" "$PC_INST/lib/.authforge-install.manifest"
  chmod "$smode" "$PC_INST/lib/core"
  both_tree=$(_tree_digest "$PC_INST/lib")
  out_4b=$("$INST_BIN" --libdir "$PC_INST/lib" --bindir "$PC_INST/bin" --datadir "$PC_INST/data" 2>&1)
  assert_eq 6 $? "Case 4b ($smode): install.sh rejects when manifest and disk both have $smode"
  assert_not_contains "$out_4b" "Installed AUTHFORGE" "Case 4b ($smode): no success message"
  assert_eq "$smode" "$(stat -c '%a' "$PC_INST/lib/core")" "Case 4b ($smode): core dir mode $smode remains UNCHANGED"
  assert_eq "$both_tree" "$(_tree_digest "$PC_INST/lib")" "Case 4b ($smode): files and SHA-256 hashes unchanged"
  chmod 00755 "$PC_INST/lib/core"
  cp -p "$PC_BASE/pc_manifest.bak" "$PC_INST/lib/.authforge-install.manifest"
done

# 5. Symlinked directory & missing directory inside datadir / libdir
rm -rf "$PC_INST/data/logs"
mkdir -p "$PC_BASE/ext_logs"
ln -s "$PC_BASE/ext_logs" "$PC_INST/data/logs"
"$INST_BIN" --libdir "$PC_INST/lib" --bindir "$PC_INST/bin" --datadir "$PC_INST/data" >/dev/null 2>&1
assert_eq 6 $? "Symlinked datadir/logs is rejected before chmod"
rm -f "$PC_INST/data/logs"
mkdir -p "$PC_INST/data/logs"
chmod 0700 "$PC_INST/data/logs"

mv "$PC_INST/lib/core" "$PC_BASE/core_moved"
"$INST_BIN" --libdir "$PC_INST/lib" --bindir "$PC_INST/bin" --datadir "$PC_INST/data" >/dev/null 2>&1
assert_eq 6 $? "Missing manifested directory (core) is rejected by install.sh"
"$UNINST_BIN" --libdir "$PC_INST/lib" --bindir "$PC_INST/bin" --datadir "$PC_INST/data" >/dev/null 2>&1
assert_eq 6 $? "Missing manifested directory (core) is rejected by uninstall.sh"
mv "$PC_BASE/core_moved" "$PC_INST/lib/core"

# 6. Failure-injection tests: failed stat and failed chmod must cause non-zero exit (never ignored with || true)
FAIL_SHIM_DIR="$PC_BASE/fail_shims"
mkdir -p "$FAIL_SHIM_DIR"
real_stat=$(command -v stat)
real_chmod=$(command -v chmod)

cat >"$FAIL_SHIM_DIR/stat" <<EOF
#!/usr/bin/env bash
for arg in "\$@"; do
  if [[ "\$arg" == *"/lib"* || "\$arg" == *"/data"* ]]; then
    exit 1
  fi
done
exec "$real_stat" "\$@"
EOF
chmod 0755 "$FAIL_SHIM_DIR/stat"

(PATH="$FAIL_SHIM_DIR:$PATH" "$INST_BIN" --libdir "$PC_INST/lib" --bindir "$PC_INST/bin" --datadir "$PC_INST/data" >/dev/null 2>&1)
assert_eq 6 $? "Failed stat on existing directory causes install.sh to fail closed (6)"
(PATH="$FAIL_SHIM_DIR:$PATH" "$UNINST_BIN" --libdir "$PC_INST/lib" --bindir "$PC_INST/bin" --datadir "$PC_INST/data" >/dev/null 2>&1)
assert_eq 6 $? "Failed stat on existing directory causes uninstall.sh to fail closed (6)"
assert_eq "$pc_inst_tree" "$(_tree_digest "$PC_INST/lib")" "Failed stat leaves existing installation untouched"
rm -f "$FAIL_SHIM_DIR/stat"

cat >"$FAIL_SHIM_DIR/chmod" <<EOF
#!/usr/bin/env bash
exit 1
EOF
chmod 0755 "$FAIL_SHIM_DIR/chmod"

(PATH="$FAIL_SHIM_DIR:$PATH" "$INST_BIN" --libdir "$PC_BASE/chmod_fail_lib" --bindir "$PC_BASE/chmod_fail_bin" --datadir "$PC_BASE/chmod_fail_data" >/dev/null 2>&1)
assert_eq 1 $? "Failed chmod causes install.sh to fail closed (1) without ignoring error"
[[ ! -e "$PC_BASE/chmod_fail_lib" ]] && t_ok "Failed chmod leaves no installed libdir behind" || t_fail "Failed chmod left libdir"
rm -rf "$FAIL_SHIM_DIR" "$PC_BASE/chmod_fail_bin" "$PC_BASE/chmod_fail_data"

assert_eq "$pc_sentinel_sha" "$(sha256sum "$PC_BASE/sentinel.txt" | awk '{print $1}')" "Unrelated sentinel file remains present and intact after all pre-chmod tests"
rm -rf "$PC_BASE"

# 14. Verify menu_render still renders [planned ...] badge when an item status is planned
future_badge=$(
  AN_MOD_STATUS["password"]="planned"
  menu_render
)
assert_contains "$future_badge" "[planned M0]" "menu_render preserves [planned ...] badge for unimplemented roadmap items"

t_summary
