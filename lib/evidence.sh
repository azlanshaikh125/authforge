#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034  # globals are shared across sourced files by design
# AUTHFORGE library: Evidence Management, Chain-of-Custody & Bundle Verification (M5-P1).
[[ -n "${_AN_LIB_EVIDENCE:-}" ]] && return 0
_AN_LIB_EVIDENCE=1

# Append a structured, secret-redacted chain-of-custody event to evidence/$sid/evidence.log.
# Fail-closed: returns nonzero ($EX_GENERAL / $EX_VALIDATION) if append or chmod fails.
# Schema (5 fields separated by \x1f):
#   timestamp \x1f event_type \x1f actor_uid \x1f artifact_relpath \x1f sha256_or_detail
evidence_log_event() { # <sid> <event_type> <artifact_relpath> <detail>
  local sid=${1:-$AN_SESSION_ID} etype=${2:-EVENT} rel=${3:-none} detail=${4:-}
  [[ -n $sid && $sid =~ ^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$ ]] || return "$EX_VALIDATION"
  local edir="$AN_DATA_DIR/evidence/$sid"
  [[ -d $edir && ! -L $edir ]] || return "$EX_VALIDATION"
  local elog="$edir/evidence.log"
  if [[ -L $elog ]] || { [[ -e $elog ]] && [[ ! -f $elog ]]; }; then
    log_error "evidence_log_event: unsafe or non-regular evidence.log: $elog"
    return "$EX_VALIDATION"
  fi

  local ts uid clean_etype clean_rel clean_detail rec
  ts=$(log_ts)
  uid=$(id -u)
  clean_etype=$(field_clean "$etype" | log_redact)
  clean_rel=$(field_clean "$rel" | log_redact)
  clean_detail=$(field_clean "$detail" | log_redact)
  printf -v rec '%s\x1f%s\x1f%s\x1f%s\x1f%s' "$ts" "$clean_etype" "$uid" "$clean_rel" "$clean_detail"

  if ! (umask 077; printf '%s\n' "$rec" >>"$elog") 2>/dev/null; then
    log_error "evidence_log_event: failed to append custody event to $elog"
    return "$EX_GENERAL"
  fi
  if ! chmod 600 "$elog" 2>/dev/null; then
    log_error "evidence_log_event: failed to set 0600 permissions on $elog"
    return "$EX_GENERAL"
  fi
  return 0
}

# Recompute evidence/$sid/manifest.sha256 over all session report and evidence artifacts
# using a same-directory temporary file ($edir/.manifest.tmp.XXXXXX) and atomic rename.
# Checks every write, sha256sum, chmod, and mv result and preserves the previous valid
# manifest if any step fails.
evidence_manifest_update() { # <sid>
  local sid=${1:-$AN_SESSION_ID}
  [[ -n $sid && $sid =~ ^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$ ]] || return "$EX_VALIDATION"
  local rdir="$AN_DATA_DIR/reports/$sid"
  local edir="$AN_DATA_DIR/evidence/$sid"
  [[ -d $rdir && -d $edir && ! -L $rdir && ! -L $edir ]] || return "$EX_VALIDATION"

  local mfile="$edir/manifest.sha256"
  if [[ -L $mfile ]] || { [[ -e $mfile ]] && [[ ! -f $mfile ]]; }; then
    log_error "evidence_manifest_update: unsafe manifest target: $mfile"
    return "$EX_VALIDATION"
  fi
  if [[ ! -f "$rdir/findings.dat" || -L "$rdir/findings.dat" ]]; then
    log_error "evidence_manifest_update: missing or unsafe findings.dat in $rdir"
    return "$EX_VALIDATION"
  fi

  local mv_bin
  mv_bin=$(_session_bin mv) || return "$EX_DEPENDENCY"

  local tmp_m
  tmp_m=$(mktemp "$edir/.manifest.tmp.XXXXXX" 2>/dev/null) || {
    log_error "evidence_manifest_update: cannot create temporary manifest in $edir"
    return "$EX_GENERAL"
  }
  if ! chmod 600 "$tmp_m" 2>/dev/null; then
    rm -f -- "$tmp_m"
    log_error "evidence_manifest_update: chmod 600 failed on $tmp_m"
    return "$EX_GENERAL"
  fi

  local f base rel sha_out sum
  local -a files_to_hash=()
  local had_nullglob=0 had_dotglob=0
  shopt -q nullglob && had_nullglob=1
  shopt -q dotglob && had_dotglob=1
  shopt -s nullglob dotglob

  for f in "$rdir"/*; do
    base=${f##*/}
    case $base in
      . | .. | .checks.lock | .checks.tmp.* | .lock-init.*) continue ;;
    esac
    if [[ -L $f || ! -f $f ]]; then
      ((had_nullglob == 0)) && shopt -u nullglob
      ((had_dotglob == 0)) && shopt -u dotglob
      rm -f -- "$tmp_m"
      log_error "evidence_manifest_update: unsafe non-regular entry in reports dir: $f"
      return "$EX_VALIDATION"
    fi
    files_to_hash+=("$f")
  done

  for f in "$edir"/*; do
    base=${f##*/}
    case $base in
      . | .. | manifest.sha256 | .manifest.tmp.*) continue ;;
    esac
    if [[ -L $f || ! -f $f ]]; then
      ((had_nullglob == 0)) && shopt -u nullglob
      ((had_dotglob == 0)) && shopt -u dotglob
      rm -f -- "$tmp_m"
      log_error "evidence_manifest_update: unsafe non-regular entry in evidence dir: $f"
      return "$EX_VALIDATION"
    fi
    files_to_hash+=("$f")
  done

  ((had_nullglob == 0)) && shopt -u nullglob
  ((had_dotglob == 0)) && shopt -u dotglob

  for f in "${files_to_hash[@]}"; do
    rel=${f#"$AN_DATA_DIR"/}
    if ! sha_out=$(sha256sum -- "$f" 2>/dev/null); then
      rm -f -- "$tmp_m"
      log_error "evidence_manifest_update: sha256sum failed on $f"
      return "$EX_GENERAL"
    fi
    sum=${sha_out%% *}
    if [[ ! $sum =~ ^[0-9a-fA-F]{64}$ ]]; then
      rm -f -- "$tmp_m"
      log_error "evidence_manifest_update: invalid sha256 digest for $f"
      return "$EX_GENERAL"
    fi
    if ! printf '%s  %s\n' "${sum,,}" "$rel" >>"$tmp_m" 2>/dev/null; then
      rm -f -- "$tmp_m"
      log_error "evidence_manifest_update: write failed on $tmp_m"
      return "$EX_GENERAL"
    fi
  done

  if ! chmod 600 "$tmp_m" 2>/dev/null; then
    rm -f -- "$tmp_m"
    log_error "evidence_manifest_update: post-write chmod 600 failed on $tmp_m"
    return "$EX_GENERAL"
  fi

  if [[ -L $mfile ]] || ! "$mv_bin" -f -- "$tmp_m" "$mfile" 2>/dev/null; then
    rm -f -- "$tmp_m"
    log_error "evidence_manifest_update: atomic rename failed for $mfile"
    return "$EX_GENERAL"
  fi
  return 0
}

# Verify every entry recorded in evidence/$sid/manifest.sha256, ensure all required
# artifacts are covered, and detect any unlisted extra files in reports/$sid/ or evidence/$sid/.
evidence_manifest_verify() { # <sid>
  local sid=$1
  [[ -n $sid && $sid =~ ^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$ ]] || return "$EX_VALIDATION"
  local rdir="$AN_DATA_DIR/reports/$sid"
  local edir="$AN_DATA_DIR/evidence/$sid"
  local mfile="$edir/manifest.sha256"
  if [[ ! -d $rdir || -L $rdir || ! -d $edir || -L $edir ]]; then
    printf '%s invalid or unsafe session directories for %s\n' "$(ui_status_badge FAIL)" "$sid"
    return "$EX_VALIDATION"
  fi
  if [[ -L $mfile || ! -f $mfile || ! -s $mfile ]]; then
    printf '%s integrity manifest missing for session %s\n' "$(ui_status_badge FAIL)" "$sid"
    return "$EX_VALIDATION"
  fi

  local fails=0 checked=0 line exp_hash rel full sha_out actual_hash
  declare -A seen_rel=()
  printf 'Integrity verification for session: %s\n' "$sid"
  ui_rule
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%$'\r'}
    [[ -n $line ]] || continue
    if [[ ! $line =~ ^([0-9a-fA-F]{64})[[:space:]]+(.+)$ ]]; then
      printf '  %s malformed manifest entry\n' "$(ui_status_badge FAIL)"
      fails=$((fails + 1))
      continue
    fi
    exp_hash=${BASH_REMATCH[1],,}
    rel=${BASH_REMATCH[2]}
    if [[ $rel == /* || $rel == *".."* || $rel == *"//"* ]]; then
      printf '  %s unsafe relative path in manifest: %s\n' "$(ui_status_badge FAIL)" "$rel"
      fails=$((fails + 1))
      continue
    fi
    if [[ $rel != "reports/$sid/"* && $rel != "evidence/$sid/"* ]]; then
      printf '  %s manifest entry outside session directories: %s\n' "$(ui_status_badge FAIL)" "$rel"
      fails=$((fails + 1))
      continue
    fi
    if [[ -n ${seen_rel[$rel]:-} ]]; then
      printf '  %s duplicate manifest entry: %s\n' "$(ui_status_badge FAIL)" "$rel"
      fails=$((fails + 1))
      continue
    fi
    seen_rel[$rel]=1
    full="$AN_DATA_DIR/$rel"
    checked=$((checked + 1))
    if ! validate_path_within "$full" "$AN_DATA_DIR" || [[ ! -f $full || -L $full ]]; then
      printf '  %s %s (missing or unsafe file)\n' "$(ui_status_badge FAIL)" "$rel"
      fails=$((fails + 1))
      continue
    fi
    if ! sha_out=$(sha256sum -- "$full" 2>/dev/null); then
      printf '  %s %s (sha256sum read failure)\n' "$(ui_status_badge FAIL)" "$rel"
      fails=$((fails + 1))
      continue
    fi
    actual_hash=${sha_out%% *}
    actual_hash=${actual_hash,,}
    if [[ $actual_hash == "$exp_hash" ]]; then
      printf '  %s %s (sha256=%s...)\n' "$(ui_status_badge PASS)" "$rel" "${actual_hash:0:16}"
    else
      printf '  %s %s (TAMPERED: expected %s..., got %s...)\n' \
        "$(ui_status_badge FAIL)" "$rel" "${exp_hash:0:16}" "${actual_hash:0:16}"
      fails=$((fails + 1))
    fi
  done <"$mfile"

  # 1. Required baseline artifact check: findings.dat must always be covered
  if [[ -z ${seen_rel["reports/$sid/findings.dat"]:-} ]]; then
    printf '  %s reports/%s/findings.dat missing from manifest\n' "$(ui_status_badge FAIL)" "$sid"
    fails=$((fails + 1))
  fi

  # 2. Scan reports/$sid/ and evidence/$sid/ for unlisted extra files or unsafe entries
  local f base
  local had_nullglob=0 had_dotglob=0
  shopt -q nullglob && had_nullglob=1
  shopt -q dotglob && had_dotglob=1
  shopt -s nullglob dotglob

  for f in "$rdir"/*; do
    base=${f##*/}
    case $base in
      . | ..) continue ;;
      .checks.lock)
        if [[ -L $f || ! -f $f ]]; then
          printf '  %s reports/%s/%s (unsafe lockfile entry)\n' "$(ui_status_badge FAIL)" "$sid" "$base"
          fails=$((fails + 1))
        fi
        continue ;;
    esac
    rel="reports/$sid/$base"
    if [[ -L $f || ! -f $f ]]; then
      printf '  %s %s (unsafe non-regular entry in reports directory)\n' "$(ui_status_badge FAIL)" "$rel"
      fails=$((fails + 1))
    elif [[ -z ${seen_rel[$rel]:-} ]]; then
      printf '  %s %s (unlisted extra file in reports directory)\n' "$(ui_status_badge FAIL)" "$rel"
      fails=$((fails + 1))
    fi
  done

  for f in "$edir"/*; do
    base=${f##*/}
    case $base in
      . | .. | manifest.sha256) continue ;;
    esac
    rel="evidence/$sid/$base"
    if [[ -L $f || ! -f $f ]]; then
      printf '  %s %s (unsafe non-regular entry in evidence directory)\n' "$(ui_status_badge FAIL)" "$rel"
      fails=$((fails + 1))
    elif [[ -z ${seen_rel[$rel]:-} ]]; then
      printf '  %s %s (unlisted extra file in evidence directory)\n' "$(ui_status_badge FAIL)" "$rel"
      fails=$((fails + 1))
    fi
  done

  ((had_nullglob == 0)) && shopt -u nullglob
  ((had_dotglob == 0)) && shopt -u dotglob

  ui_rule
  printf 'Integrity result: %d file(s) verified, %d failure(s)\n' "$checked" "$fails"
  if ((fails > 0 || checked == 0)); then return "$EX_VALIDATION"; fi
  return 0
}

# Override risk_manifest_update and risk_manifest_verify (from lib/risk.sh)
# so M0-M4 callers automatically cover checks.dat and compliance.* while
# preserving full backward compatibility with M0-M4 sessions.
risk_manifest_update() { evidence_manifest_update "$@"; }
risk_manifest_verify() { evidence_manifest_verify "$@"; }

# Export a self-contained, verifiable .tar.gz evidence bundle for a session.
# Feature-specific dependency check: requires tar in PATH (returns EX_DEPENDENCY=4 if missing).
# Fail-closed on custody-event write or manifest update failure.
evidence_export_bundle() { # <sid> <out_tar_gz>
  local sid=${1:-$AN_SESSION_ID} out_file=${2:-}
  [[ -n $sid && $sid =~ ^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$ ]] || an_die "$EX_VALIDATION" "invalid session id: $sid"
  [[ -n $out_file ]] || an_die "$EX_USAGE" "evidence bundle requires -o <output.tar.gz>"
  [[ ! -e $out_file && ! -L $out_file ]] || an_die "$EX_VALIDATION" "refusing to overwrite existing file: $out_file"

  if ! command -v tar >/dev/null 2>&1; then
    an_die "$EX_DEPENDENCY" "tar not installed; evidence bundle export requires tar"
  fi

  local rdir="$AN_DATA_DIR/reports/$sid"
  local edir="$AN_DATA_DIR/evidence/$sid"
  [[ -d $rdir && -d $edir && ! -L $rdir && ! -L $edir ]] || an_die "$EX_VALIDATION" "unknown session: $sid"
  [[ -f "$rdir/findings.dat" && ! -L "$rdir/findings.dat" ]] || an_die "$EX_VALIDATION" "missing findings.dat for session: $sid"

  if ! evidence_log_event "$sid" "BUNDLE_EXPORT" "evidence/$sid/manifest.sha256" "preparing evidence bundle"; then
    an_die "$EX_GENERAL" "failed to record chain-of-custody event for session: $sid"
  fi
  if ! evidence_manifest_update "$sid"; then
    an_die "$EX_GENERAL" "failed to update evidence manifest for session: $sid"
  fi
  evidence_manifest_verify "$sid" >/dev/null || an_die "$EX_VALIDATION" "session $sid failed pre-bundle integrity check"

  local stage_dir broot="$sid"
  stage_dir=$(mktemp -d "$AN_TMPDIR/bundle-stage.XXXXXX") || an_die "$EX_GENERAL" "cannot create bundle staging directory"
  chmod 700 "$stage_dir" || { rm -rf -- "$stage_dir"; an_die "$EX_GENERAL" "chmod failed on staging directory"; }
  mkdir -p "$stage_dir/$broot/reports/$sid" "$stage_dir/$broot/evidence/$sid" || {
    rm -rf -- "$stage_dir"
    an_die "$EX_GENERAL" "cannot create bundle subdirectories"
  }

  local f rel line
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%$'\r'}
    [[ $line =~ ^([0-9a-fA-F]{64})[[:space:]]+(.+)$ ]] || continue
    rel=${BASH_REMATCH[2]}
    f="$AN_DATA_DIR/$rel"
    [[ -f $f && ! -L $f ]] || { rm -rf -- "$stage_dir"; an_die "$EX_VALIDATION" "manifest file missing during bundle stage: $rel"; }
    cp -p -- "$f" "$stage_dir/$broot/$rel" || { rm -rf -- "$stage_dir"; an_die "$EX_GENERAL" "failed to stage $rel"; }
    chmod 600 "$stage_dir/$broot/$rel" || { rm -rf -- "$stage_dir"; an_die "$EX_GENERAL" "chmod failed on staged $rel"; }
  done <"$edir/manifest.sha256"

  cp -p -- "$edir/manifest.sha256" "$stage_dir/$broot/evidence/$sid/manifest.sha256" || {
    rm -rf -- "$stage_dir"
    an_die "$EX_GENERAL" "failed to stage manifest.sha256"
  }
  chmod 600 "$stage_dir/$broot/evidence/$sid/manifest.sha256" || {
    rm -rf -- "$stage_dir"
    an_die "$EX_GENERAL" "chmod failed on staged manifest.sha256"
  }

  (
    umask 077
    LC_ALL=C tar -C "$stage_dir" --owner=0 --group=0 --numeric-owner -czf "$out_file" "$broot"
  ) || {
    rm -rf -- "$stage_dir"
    rm -f -- "$out_file"
    an_die "$EX_GENERAL" "failed to create evidence bundle: $out_file"
  }
  if ! chmod 600 "$out_file" 2>/dev/null; then
    rm -rf -- "$stage_dir"
    rm -f -- "$out_file"
    an_die "$EX_GENERAL" "failed to set 0600 permissions on bundle: $out_file"
  fi
  rm -rf -- "$stage_dir"

  local sha_out bsum
  if ! sha_out=$(sha256sum -- "$out_file" 2>/dev/null); then
    rm -f -- "$out_file"
    an_die "$EX_GENERAL" "failed to hash created bundle: $out_file"
  fi
  bsum=${sha_out%% *}
  printf 'Wrote evidence bundle: %s\nSHA-256: %s\n' "$out_file" "$bsum"
  return 0
}

# Verify a standalone .tar.gz evidence bundle safely without trusting archive paths.
# Rejects unexpected archive paths and any unmanifested files.
evidence_verify_bundle() { # <bundle_tar_gz>
  local bfile=${1:-}
  [[ -n $bfile ]] || an_die "$EX_USAGE" "verify-bundle requires a bundle FILE argument"
  validate_regular_file "$bfile" || an_die "$EX_VALIDATION" "not a readable regular file: $bfile"

  if ! command -v tar >/dev/null 2>&1; then
    an_die "$EX_DEPENDENCY" "tar not installed; evidence bundle verification requires tar"
  fi

  local list_out
  if ! list_out=$(LC_ALL=C tar -ztvf "$bfile" 2>/dev/null); then
    printf '%s invalid or unreadable tar.gz bundle: %s\n' "$(ui_status_badge FAIL)" "$bfile"
    return "$EX_VALIDATION"
  fi

  # Reject empty archives, non-regular/non-dir entries (symlinks/hardlinks/devices),
  # leading "/", "../", "//", or unexpected archive paths outside:
  #   <sid>/
  #   <sid>/reports/
  #   <sid>/reports/<sid>/
  #   <sid>/reports/<sid>/<filename>
  #   <sid>/evidence/
  #   <sid>/evidence/<sid>/
  #   <sid>/evidence/<sid>/<filename>
  local bad_entry=0 sid_root="" has_manifest=0 tvline
  while IFS= read -r tvline || [[ -n $tvline ]]; do
    [[ -n $tvline ]] || continue
    local perm=${tvline%% *}
    local ttype=${perm:0:1}
    if [[ $ttype != "-" && $ttype != "d" ]]; then
      bad_entry=1
      break
    fi
    local entry_path=${tvline##* }
    if [[ $entry_path == /* || $entry_path == *".."* || $entry_path == *"//"* ]]; then
      bad_entry=1
      break
    fi
    local top=${entry_path%%/*}
    if [[ ! $top =~ ^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$ ]]; then
      bad_entry=1
      break
    fi
    if [[ -z $sid_root ]]; then
      sid_root=$top
    elif [[ $top != "$sid_root" ]]; then
      bad_entry=1
      break
    fi

    if [[ $ttype == "d" ]]; then
      case ${entry_path%/} in
        "$sid_root" | "$sid_root/reports" | "$sid_root/reports/$sid_root" | "$sid_root/evidence" | "$sid_root/evidence/$sid_root") ;;
        *)
          bad_entry=1
          break ;;
      esac
    else
      case $entry_path in
        "$sid_root/reports/$sid_root/"* | "$sid_root/evidence/$sid_root/"*)
          local leaf=${entry_path#"$sid_root/"*"/$sid_root/"}
          if [[ -z $leaf || $leaf == */* || $leaf == "." || $leaf == ".." || $leaf == ".checks.lock" ]]; then
            bad_entry=1
            break
          fi
          if [[ $entry_path == "$sid_root/evidence/$sid_root/manifest.sha256" ]]; then
            has_manifest=1
          fi ;;
        *)
          bad_entry=1
          break ;;
      esac
    fi
  done <<<"$list_out"

  if ((bad_entry != 0 || has_manifest == 0)) || [[ -z $sid_root ]]; then
    printf '%s bundle contains unsafe or unexpected archive paths: %s\n' "$(ui_status_badge FAIL)" "$bfile"
    return "$EX_VALIDATION"
  fi

  local xdir
  xdir=$(mktemp -d "$AN_TMPDIR/bundle-verify.XXXXXX") || return "$EX_GENERAL"
  chmod 700 "$xdir" || { rm -rf -- "$xdir"; return "$EX_GENERAL"; }
  if ! LC_ALL=C tar -C "$xdir" -xzf "$bfile" 2>/dev/null; then
    rm -rf -- "$xdir"
    printf '%s bundle extraction failed: %s\n' "$(ui_status_badge FAIL)" "$bfile"
    return "$EX_VALIDATION"
  fi

  # evidence_manifest_verify checks all manifest hashes AND rejects any unmanifested
  # extra files in both reports/<sid_root>/ and evidence/<sid_root>/.
  local saved_data=$AN_DATA_DIR rc=0
  AN_DATA_DIR="$xdir/$sid_root"
  evidence_manifest_verify "$sid_root" || rc=$?
  AN_DATA_DIR=$saved_data
  rm -rf -- "$xdir"
  return "$rc"
}
