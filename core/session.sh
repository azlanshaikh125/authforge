#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034  # globals are shared across sourced files by design
# AUTHFORGE core: session-based audit execution, strict directory containment,
# and kernel-flock check execution ledger (checks.dat).
[[ -n "${_AN_SESSION:-}" ]] && return 0
_AN_SESSION=1

AN_SESSION_ID=""
AN_SESSION_REPORT_DIR=""
AN_SESSION_EVIDENCE_DIR=""
AN_SESSION_FINDINGS=""
AN_SESSION_CHECKS=""

_AN_ACTIVE_CHECK_ID=""
_AN_ACTIVE_CHECK_TARGET=""
_AN_ACTIVE_CHECK_DETAIL=""
_AN_LAST_RECORDED_CID=""
_AN_LEDGER_WRITE_FAILED=0

# Resolve required core utilities even when legacy M4 test shims restrict PATH.
_session_bin() {
  local name=$1 p
  p=$(command -v "$name" 2>/dev/null || true)
  if [[ -n $p ]]; then
    printf '%s' "$p"
    return 0
  fi
  for p in "/usr/bin/$name" "/bin/$name"; do
    if [[ -x $p ]]; then
      printf '%s' "$p"
      return 0
    fi
  done
  return 1
}

# Strict segment-aware lexical validation of AN_DATA_DIR.
# Requires an ordinary absolute path, rejects root "/", rejects trailing "/",
# rejects repeated separators "//", and rejects "." or ".." segments anywhere.
_session_verify_droot_lexical() { # <droot>
  local droot=${1:-}
  [[ -n $droot && $droot == /* && $droot != "/" && $droot != */ ]] || return 1
  [[ $droot != *"//"* ]] || return 1
  case "${droot}/" in
    *"/./"* | *"/../"*) return 1 ;;
  esac
  return 0
}

# Verify that AN_SESSION_REPORT_DIR is the exact, non-symlink, mode-0700 direct
# child of AN_DATA_DIR/reports owned by the current EUID, with matching (dev,ino)
# parent links via "..".
# Trust boundary: ancestor directories above AN_DATA_DIR are assumed to be root-
# or same-UID-controlled per the Linux local execution model.
_session_verify_report_dirs() {
  local droot=$AN_DATA_DIR rparent="$AN_DATA_DIR/reports" sdir=$AN_SESSION_REPORT_DIR
  local sid=$AN_SESSION_ID uid dmeta rmeta smeta r_dotdot_devino d_devino s_dotdot_devino r_devino

  _session_verify_droot_lexical "$droot" || return 1
  [[ $sid =~ ^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$ ]] || return 1
  [[ $rparent == "${droot}/reports" ]] || return 1
  [[ $sdir == "${rparent}/${sid}" ]] || return 1

  [[ ! -L $droot && -d $droot ]] || return 1
  [[ ! -L $rparent && -d $rparent ]] || return 1
  [[ ! -L $sdir && -d $sdir ]] || return 1

  uid=$(id -u)
  dmeta=$(LC_ALL=C stat -c '%F|%u|%a|%d:%i' -- "$droot" 2>/dev/null) || return 1
  rmeta=$(LC_ALL=C stat -c '%F|%u|%a|%d:%i' -- "$rparent" 2>/dev/null) || return 1
  smeta=$(LC_ALL=C stat -c '%F|%u|%a|%d:%i' -- "$sdir" 2>/dev/null) || return 1

  local dtype duid dmode rtype ruid rmode stype suid smode
  IFS='|' read -r dtype duid dmode d_devino <<<"$dmeta"
  IFS='|' read -r rtype ruid rmode r_devino <<<"$rmeta"
  IFS='|' read -r stype suid smode _ <<<"$smeta"

  [[ $dtype == "directory" && $duid == "$uid" ]] || return 1
  (((8#$dmode & 8#022) == 0)) || return 1

  [[ $rtype == "directory" && $ruid == "$uid" && $rmode == "700" ]] || return 1
  [[ $stype == "directory" && $suid == "$uid" && $smode == "700" ]] || return 1

  r_dotdot_devino=$(LC_ALL=C stat -c '%d:%i' -- "$rparent/.." 2>/dev/null) || return 1
  s_dotdot_devino=$(LC_ALL=C stat -c '%d:%i' -- "$sdir/.." 2>/dev/null) || return 1
  [[ $r_dotdot_devino == "$d_devino" ]] || return 1
  [[ $s_dotdot_devino == "$r_devino" ]] || return 1
  return 0
}

_session_verify_evidence_dirs() {
  local droot=$AN_DATA_DIR eparent="$AN_DATA_DIR/evidence" edir=$AN_SESSION_EVIDENCE_DIR
  local sid=$AN_SESSION_ID uid dmeta emeta smeta e_dotdot_devino d_devino s_dotdot_devino e_devino

  _session_verify_droot_lexical "$droot" || return 1
  [[ $sid =~ ^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$ ]] || return 1
  [[ $eparent == "${droot}/evidence" ]] || return 1
  [[ $edir == "${eparent}/${sid}" ]] || return 1

  [[ ! -L $droot && -d $droot ]] || return 1
  [[ ! -L $eparent && -d $eparent ]] || return 1
  [[ ! -L $edir && -d $edir ]] || return 1

  uid=$(id -u)
  dmeta=$(LC_ALL=C stat -c '%F|%u|%a|%d:%i' -- "$droot" 2>/dev/null) || return 1
  emeta=$(LC_ALL=C stat -c '%F|%u|%a|%d:%i' -- "$eparent" 2>/dev/null) || return 1
  smeta=$(LC_ALL=C stat -c '%F|%u|%a|%d:%i' -- "$edir" 2>/dev/null) || return 1

  local dtype duid dmode etype euid emode stype suid smode
  IFS='|' read -r dtype duid dmode d_devino <<<"$dmeta"
  IFS='|' read -r etype euid emode e_devino <<<"$emeta"
  IFS='|' read -r stype suid smode _ <<<"$smeta"

  [[ $dtype == "directory" && $duid == "$uid" ]] || return 1
  (((8#$dmode & 8#022) == 0)) || return 1
  [[ $etype == "directory" && $euid == "$uid" && $emode == "700" ]] || return 1
  [[ $stype == "directory" && $suid == "$uid" && $smode == "700" ]] || return 1

  e_dotdot_devino=$(LC_ALL=C stat -c '%d:%i' -- "$eparent/.." 2>/dev/null) || return 1
  s_dotdot_devino=$(LC_ALL=C stat -c '%d:%i' -- "$edir/.." 2>/dev/null) || return 1
  [[ $e_dotdot_devino == "$d_devino" ]] || return 1
  [[ $s_dotdot_devino == "$e_devino" ]] || return 1
  return 0
}

session_init() {
  local old_umask rnd _d
  old_umask=$(umask)
  umask 077
  rnd=$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')
  AN_SESSION_ID="$(printf '%(%Y%m%d-%H%M%S)T' -1)-${rnd}"
  mkdir -p "$AN_DATA_DIR/logs" "$AN_DATA_DIR/reports/$AN_SESSION_ID" \
    "$AN_DATA_DIR/evidence/$AN_SESSION_ID" ||
    an_die "$EX_GENERAL" "cannot create session directories under $AN_DATA_DIR"
  for _d in "$AN_DATA_DIR/logs" "$AN_DATA_DIR/reports" "$AN_DATA_DIR/evidence" \
    "$AN_DATA_DIR/reports/$AN_SESSION_ID" "$AN_DATA_DIR/evidence/$AN_SESSION_ID"; do
    [[ ! -L $_d ]] || an_die "$EX_GENERAL" "refusing symlinked session directory: $_d"
    chmod 700 "$_d" 2>/dev/null || an_die "$EX_GENERAL" "cannot set 0700 on $_d"
  done
  AN_SESSION_REPORT_DIR="$AN_DATA_DIR/reports/$AN_SESSION_ID"
  AN_SESSION_EVIDENCE_DIR="$AN_DATA_DIR/evidence/$AN_SESSION_ID"
  AN_SESSION_FINDINGS="$AN_SESSION_REPORT_DIR/findings.dat"
  AN_SESSION_CHECKS="$AN_SESSION_REPORT_DIR/checks.dat"
  AN_LOG_FILE="$AN_DATA_DIR/logs/$AN_SESSION_ID.log"
  _AN_ACTIVE_CHECK_ID=""
  _AN_ACTIVE_CHECK_TARGET=""
  _AN_ACTIVE_CHECK_DETAIL=""
  _AN_LAST_RECORDED_CID=""
  _AN_LEDGER_WRITE_FAILED=0

  _session_verify_report_dirs || an_die "$EX_GENERAL" "session report directory failed containment check: $AN_SESSION_REPORT_DIR"
  _session_verify_evidence_dirs || an_die "$EX_GENERAL" "session evidence directory failed containment check: $AN_SESSION_EVIDENCE_DIR"

  : >"$AN_LOG_FILE"
  : >"$AN_SESSION_FINDINGS"
  : >"$AN_SESSION_CHECKS"
  chmod 600 "$AN_LOG_FILE" "$AN_SESSION_FINDINGS" "$AN_SESSION_CHECKS" 2>/dev/null ||
    an_die "$EX_GENERAL" "cannot set 0600 on session files"
  printf '%s\n' "$AN_SESSION_ID" >"$AN_DATA_DIR/reports/.latest"
  umask "$old_umask"
  log_info "session started id=$AN_SESSION_ID profile=${AN_PROFILE:-none} version=$AN_VERSION"
  return 0
}

# Atomically record or update a check execution record in checks.dat using
# kernel-managed flock and fail-closed /proc/<BASHPID>/fd/<lock_fd> verification.
# Schema (6 fields, \x1f-delimited):
#   check_id \x1f status \x1f exit_code \x1f target_type \x1f timestamp \x1f detail
session_record_check() { # <check_id> <status> <exit_code> <target_type> [detail]
  local cid=${1:-} st=${2:-} rc=${3:-0} ttype=${4:-none} detail=${5:-}
  [[ -n ${AN_SESSION_REPORT_DIR:-} ]] || return 0
  if ! _session_verify_report_dirs; then
    log_error "session_record_check: report directory failed containment verification"
    _AN_LEDGER_WRITE_FAILED=1
    return "$EX_GENERAL"
  fi
  [[ $cid =~ ^[a-z0-9_-]+:[a-z0-9_-]+$ ]] || {
    log_error "session_record_check: invalid check_id '$cid'"
    _AN_LEDGER_WRITE_FAILED=1
    return "$EX_VALIDATION"
  }
  case $st in
    COMPLETED | REFUSED | SKIPPED | ABORTED | ERROR) ;;
    *)
      log_error "session_record_check: invalid status '$st'"
      _AN_LEDGER_WRITE_FAILED=1
      return "$EX_VALIDATION" ;;
  esac
  [[ $rc =~ ^[0-9]+$ ]] || rc=1

  local flock_bin mv_bin ln_bin
  flock_bin=$(_session_bin flock) || { _AN_LEDGER_WRITE_FAILED=1; return "$EX_DEPENDENCY"; }
  mv_bin=$(_session_bin mv) || { _AN_LEDGER_WRITE_FAILED=1; return "$EX_DEPENDENCY"; }
  ln_bin=$(_session_bin ln) || { _AN_LEDGER_WRITE_FAILED=1; return "$EX_DEPENDENCY"; }

  local cfile="$AN_SESSION_REPORT_DIR/checks.dat"
  local lockfile="$AN_SESSION_REPORT_DIR/.checks.lock"
  local uid self_pid lock_fd init_tmp pre_lmeta fd_lmeta post_lmeta
  uid=$(id -u)
  self_pid=$BASHPID

  if [[ -L $lockfile ]]; then
    log_error "session_record_check: symlinked lockfile rejected: $lockfile"
    _AN_LEDGER_WRITE_FAILED=1
    return "$EX_GENERAL"
  fi
  if [[ ! -e $lockfile ]]; then
    init_tmp=$(mktemp "$AN_SESSION_REPORT_DIR/.lock-init.XXXXXX" 2>/dev/null) || {
      _AN_LEDGER_WRITE_FAILED=1
      return "$EX_GENERAL"
    }
    chmod 600 "$init_tmp" 2>/dev/null || {
      rm -f -- "$init_tmp"
      _AN_LEDGER_WRITE_FAILED=1
      return "$EX_GENERAL"
    }
    "$ln_bin" -- "$init_tmp" "$lockfile" 2>/dev/null || true
    rm -f -- "$init_tmp"
  fi
  if [[ -L $lockfile || ! -f $lockfile ]]; then
    log_error "session_record_check: lockfile is not a regular file: $lockfile"
    _AN_LEDGER_WRITE_FAILED=1
    return "$EX_GENERAL"
  fi

  pre_lmeta=$(LC_ALL=C stat -c '%F|%d|%i|%u|%a' -- "$lockfile" 2>/dev/null) || {
    _AN_LEDGER_WRITE_FAILED=1
    return "$EX_GENERAL"
  }
  local ltype ldev lino luid lmode
  IFS='|' read -r ltype ldev lino luid lmode <<<"$pre_lmeta"
  if [[ ($ltype != "regular file" && $ltype != "regular empty file") || $luid != "$uid" || $lmode != "600" ]]; then
    log_error "session_record_check: lockfile failed pre-open metadata check ($pre_lmeta)"
    _AN_LEDGER_WRITE_FAILED=1
    return "$EX_GENERAL"
  fi

  exec {lock_fd}<>"$lockfile" 2>/dev/null || {
    _AN_LEDGER_WRITE_FAILED=1
    return "$EX_GENERAL"
  }

  local fd_path="/proc/${self_pid}/fd/${lock_fd}"
  if [[ ! -e $fd_path ]]; then
    exec {lock_fd}>&-
    log_error "session_record_check: Linux /proc descriptor path unavailable: $fd_path"
    _AN_LEDGER_WRITE_FAILED=1
    return "$EX_GENERAL"
  fi
  fd_lmeta=$(LC_ALL=C stat -L -c '%F|%d|%i|%u|%a' -- "$fd_path" 2>/dev/null) || {
    exec {lock_fd}>&-
    _AN_LEDGER_WRITE_FAILED=1
    return "$EX_GENERAL"
  }
  post_lmeta=$(LC_ALL=C stat -c '%F|%d|%i|%u|%a' -- "$lockfile" 2>/dev/null) || {
    exec {lock_fd}>&-
    _AN_LEDGER_WRITE_FAILED=1
    return "$EX_GENERAL"
  }
  if [[ -L $lockfile || $pre_lmeta != "$fd_lmeta" || $fd_lmeta != "$post_lmeta" ]]; then
    exec {lock_fd}>&-
    log_error "session_record_check: descriptor identity mismatch on $lockfile"
    _AN_LEDGER_WRITE_FAILED=1
    return "$EX_GENERAL"
  fi

  local tmo=${AN_LOCK_TIMEOUT_SEC:-5}
  if ! "$flock_bin" -x -w "$tmo" "$lock_fd" 2>/dev/null; then
    exec {lock_fd}>&-
    log_error "session_record_check: failed to acquire exclusive flock on $lockfile"
    _AN_LEDGER_WRITE_FAILED=1
    return "$EX_GENERAL"
  fi

  # Re-verify that the locked fd still matches the current directory entry .checks.lock
  post_lmeta=$(LC_ALL=C stat -c '%F|%d|%i|%u|%a' -- "$lockfile" 2>/dev/null) || {
    exec {lock_fd}>&-
    _AN_LEDGER_WRITE_FAILED=1
    return "$EX_GENERAL"
  }
  if [[ -L $lockfile || $fd_lmeta != "$post_lmeta" ]]; then
    exec {lock_fd}>&-
    log_error "session_record_check: post-flock inode mismatch on $lockfile"
    _AN_LEDGER_WRITE_FAILED=1
    return "$EX_GENERAL"
  fi

  if [[ -L $cfile ]] || { [[ -e $cfile ]] && [[ ! -f $cfile ]]; }; then
    exec {lock_fd}>&-
    log_error "session_record_check: checks.dat is not a regular file"
    _AN_LEDGER_WRITE_FAILED=1
    return "$EX_GENERAL"
  fi

  local clean_ttype clean_detail ts tmpfile rec
  clean_ttype=$(field_clean "$ttype" | log_redact)
  clean_detail=$(field_clean "$detail" | log_redact)
  # Strip any untrusted target_linked or verifier_behavior_established keys
  clean_detail=$(printf '%s' "$clean_detail" | sed -E 's/(^|[;[[:space:]]+)(target_linked|verifier_behavior_established)=[^;[:space:]]*//g; s/^[;[[:space:]]+//; s/[;[[:space:]]+$//')
  ts=$(log_ts)

  tmpfile=$(mktemp "$AN_SESSION_REPORT_DIR/.checks.tmp.XXXXXX" 2>/dev/null) || {
    exec {lock_fd}>&-
    _AN_LEDGER_WRITE_FAILED=1
    return "$EX_GENERAL"
  }
  chmod 600 "$tmpfile" 2>/dev/null || {
    rm -f -- "$tmpfile"
    exec {lock_fd}>&-
    _AN_LEDGER_WRITE_FAILED=1
    return "$EX_GENERAL"
  }

  if [[ -f $cfile && -s $cfile ]]; then
    if ! LC_ALL=C awk -v cid="$cid" 'BEGIN { FS = sprintf("%c", 31) } NF == 6 && $1 != cid { print $0 }' "$cfile" >"$tmpfile" 2>/dev/null; then
      rm -f -- "$tmpfile"
      exec {lock_fd}>&-
      _AN_LEDGER_WRITE_FAILED=1
      return "$EX_GENERAL"
    fi
  fi

  printf -v rec '%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s' "$cid" "$st" "$rc" "$clean_ttype" "$ts" "$clean_detail"
  if ! printf '%s\n' "$rec" >>"$tmpfile" 2>/dev/null; then
    rm -f -- "$tmpfile"
    exec {lock_fd}>&-
    _AN_LEDGER_WRITE_FAILED=1
    return "$EX_GENERAL"
  fi

  if ! "$mv_bin" -f -- "$tmpfile" "$cfile" 2>/dev/null; then
    rm -f -- "$tmpfile"
    exec {lock_fd}>&-
    _AN_LEDGER_WRITE_FAILED=1
    return "$EX_GENERAL"
  fi

  _AN_LAST_RECORDED_CID=$cid
  exec {lock_fd}>&-
  return 0
}

# Wrapper that executes a check implementation and records its terminal status
# in checks.dat (both on normal return and via an_on_exit if an_die is called).
session_run_check() { # <check_id> <target_type> <detail> <fn> [args...]
  local cid=$1 ttype=$2 detail=$3 fn=$4
  shift 4
  _AN_ACTIVE_CHECK_ID=$cid
  _AN_ACTIVE_CHECK_TARGET=$ttype
  _AN_ACTIVE_CHECK_DETAIL=$detail
  _AN_LAST_RECORDED_CID=""

  local rc=0
  "$fn" "$@" || rc=$?

  local final_detail=${_AN_ACTIVE_CHECK_DETAIL:-$detail}
  local final_target=${_AN_ACTIVE_CHECK_TARGET:-$ttype}
  local st="COMPLETED"
  case $rc in
    0 | "$EX_FINDINGS") st="COMPLETED" ;;
    "$EX_USAGE" | "$EX_CONFIG" | "$EX_AUTHZ" | "$EX_VALIDATION") st="REFUSED" ;;
    "$EX_DEPENDENCY") st="SKIPPED" ;;
    "$EX_INTERRUPT") st="ABORTED" ;;
    *) st="ERROR" ;;
  esac

  if ! session_record_check "$cid" "$st" "$rc" "$final_target" "$final_detail"; then
    _AN_LEDGER_WRITE_FAILED=1
  fi
  _AN_ACTIVE_CHECK_ID=""
  _AN_ACTIVE_CHECK_TARGET=""
  _AN_ACTIVE_CHECK_DETAIL=""

  if ((_AN_LEDGER_WRITE_FAILED != 0 && rc == 0)); then
    return "$EX_GENERAL"
  fi
  return "$rc"
}

# Override an_on_exit (defined earlier in core/errors.sh) so that checks
# terminating early via an_die or signal still finalize their checks.dat entry
# and any ledger write failure prevents a zero exit code.
an_on_exit() {
  local rc=$?
  if [[ -n ${_AN_ACTIVE_CHECK_ID:-} && ${_AN_LAST_RECORDED_CID:-} != "$_AN_ACTIVE_CHECK_ID" ]]; then
    local st="ERROR"
    case $rc in
      0 | "$EX_FINDINGS") st="COMPLETED" ;;
      "$EX_USAGE" | "$EX_CONFIG" | "$EX_AUTHZ" | "$EX_VALIDATION") st="REFUSED" ;;
      "$EX_DEPENDENCY") st="SKIPPED" ;;
      "$EX_INTERRUPT") st="ABORTED" ;;
    esac
    if ! session_record_check "$_AN_ACTIVE_CHECK_ID" "$st" "$rc" \
      "${_AN_ACTIVE_CHECK_TARGET:-none}" "${_AN_ACTIVE_CHECK_DETAIL:-exit_trap}"; then
      _AN_LEDGER_WRITE_FAILED=1
    fi
    _AN_ACTIVE_CHECK_ID=""
  fi
  if ((_AN_LEDGER_WRITE_FAILED != 0 && rc == 0)); then
    rc=$EX_GENERAL
  fi
  _an_run_cleanup
  if [[ -t 1 ]]; then printf '\e[?25h' 2>/dev/null || true; fi
  exit "$rc"
}

session_latest() {
  if [[ -f "$AN_DATA_DIR/reports/.latest" ]]; then
    local lat
    lat=$(<"$AN_DATA_DIR/reports/.latest")
    if [[ -n $lat && -d "$AN_DATA_DIR/reports/$lat" ]]; then
      printf '%s\n' "$lat"
      return 0
    fi
  fi
  session_list | sort | tail -n 1
}

session_list() {
  local d
  shopt -s nullglob
  for d in "$AN_DATA_DIR"/reports/*/; do
    d=${d%/}
    printf '%s\n' "${d##*/}"
  done
  shopt -u nullglob
  return 0
}
