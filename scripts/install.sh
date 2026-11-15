#!/usr/bin/env bash
# shellcheck shell=bash
# AUTHFORGE M5-P2: Safe user-local (default) or custom-prefix installer.
# Separates immutable code (AN_ROOT) from mutable user runtime data (AN_DATA_DIR),
# validates destination, parent, and data paths against traversal/symlinks/unsafe modes,
# enforces strict validate-before-chmod ordering on every pre-existing directory,
# enforces strict 3-digit octal directory modes (rejecting 4-digit modes and setuid/setgid/sticky bits),
# verifies complete manifest inventory + directory modes + file SHA-256 digests before
# upgrading an existing libdir (supporting v2 native and controlled v1 -> v2 migration),
# stages atomically, and writes a verifiable v2 installation receipt (.authforge-install.manifest).
unset BASH_ENV ENV CDPATH
set -Eeuo pipefail
IFS=$' \t\n'

readonly EX_GENERAL=1
readonly EX_USAGE=2
readonly EX_DEPENDENCY=4
readonly EX_VALIDATION=6

readonly -a INST_REQUIRED_CMDS=(
  awk sed grep sort uniq tr head wc mktemp date od stat
  readlink realpath cat mkdir chmod cp rm mv ln flock id sha256sum
)

readonly -a INST_TOP_FILES=(
  authforge.sh Makefile LICENSE README.md CHANGELOG.md SECURITY.md CONTRIBUTING.md
)

readonly -a INST_SUBDIRS=(
  config core data docs fixtures lib modules plugins profiles scripts
)

readonly -a INST_DATA_SUBDIRS=(
  logs reports evidence backups config profiles
)

readonly -a INST_CORE_ANCHORS=(
  authforge.sh
  scripts/authforge-safe.sh
  scripts/install.sh
  scripts/uninstall.sh
  core/session.sh
  core/config.sh
  core/validate.sh
  data/compliance_mappings.dat
  lib/compliance.sh
  lib/evidence.sh
  modules/compliance.sh
  modules/evidence.sh
)

_inst_die() {
  local code=$1
  shift
  printf 'authforge-install: %s\n' "$*" >&2
  exit "$code"
}

_inst_usage() {
  cat <<'USAGE'
Usage: ./scripts/install.sh [options]

Install AUTHFORGE into an isolated code directory, launcher path, and mutable data directory.
By default, performs a rootless user-local installation under ~/.local:
  Code (AN_ROOT):       ~/.local/share/authforge
  Launcher symlink:     ~/.local/bin/authforge
  Data (AN_DATA_DIR):   ~/.local/state/authforge

Options:
  --prefix DIR          Set base prefix for code (DIR/share/authforge) and launcher (DIR/bin)
  --libdir DIR          Explicit code installation directory (AN_ROOT)
  --bindir DIR          Explicit launcher directory (installs DIR/authforge)
  --datadir DIR         Explicit mutable runtime data directory (AN_DATA_DIR)
  --dry-run             Validate paths and prerequisites without modifying the filesystem
  -h, --help            Show this help message
USAGE
}

# Strict segment-aware lexical path validation.
_inst_validate_abs_path() { # <path> <role:libdir|bindir|datadir|prefix|home|check>
  local p=${1:-} role=${2:-path}
  [[ -n $p && $p == /* && $p != "/" && $p != */ ]] || return 1
  [[ $p != *"//"* ]] || return 1
  [[ $p =~ ^[A-Za-z0-9._/-]+$ ]] || return 1
  case "${p}/" in
    *"/./"* | *"/../"*) return 1 ;;
  esac

  case $role in
    libdir | datadir)
      case $p in
        /bin | /sbin | /lib | /lib64 | /usr | /usr/bin | /usr/sbin | /usr/lib | /usr/local | /usr/local/bin | /usr/local/lib | /etc | /var | /tmp | /dev | /proc | /sys | /run | /boot | /root | /home | /opt)
          return 1 ;;
      esac
      if [[ -n ${HOME:-} && $p == "${HOME%/}" ]]; then
        return 1
      fi ;;
    bindir | prefix)
      case $p in
        /etc | /var | /tmp | /dev | /proc | /sys | /run | /boot | /root | /home)
          return 1 ;;
      esac
      if [[ -n ${HOME:-} && $p == "${HOME%/}" ]]; then
        return 1
      fi ;;
  esac
  return 0
}

# Strict relative path validation for manifest DIR and FILE entries.
_inst_validate_relpath() { # <rel>
  local r=${1:-}
  [[ -n $r && $r != /* && $r != */ && $r != "." && $r != ".." ]] || return 1
  [[ $r != *"//"* ]] || return 1
  [[ $r =~ ^[A-Za-z0-9._/-]+$ ]] || return 1
  case "/${r}/" in
    *"/./"* | *"/../"*) return 1 ;;
  esac
  return 0
}

# Strict directory mode validation (used for manifest DIR entries and on-disk stat %a modes).
# Accepts ONLY exactly 3 octal digits (e.g., 700, 750, 755) before arithmetic evaluation,
# rejecting 4-digit strings (0755, 1755, 2755, 4755), any special permission bits
# (setuid 4000, setgid 2000, sticky 1000), group/world write bits (022), and missing owner r+x (500).
_inst_validate_dir_mode() { # <mode_str>
  local m=${1:-}
  [[ $m =~ ^[0-7]{3}$ ]] || return 1
  (((8#$m & 8#7022) == 0 && (8#$m & 8#500) == 8#500)) || return 1
  return 0
}

# Validate an existing ordinary directory's ownership and mode BEFORE any chmod or write.
_inst_verify_existing_dir_node() { # <dir_path>
  local d=$1 uid meta ftype fuid fmode
  [[ -n $d && ! -L $d && -d $d ]] || return 1
  uid=$(id -u)
  meta=$(LC_ALL=C stat -c '%F|%u|%a' -- "$d" 2>/dev/null) || return 1
  IFS='|' read -r ftype fuid fmode <<<"$meta"
  [[ $ftype == "directory" && ($fuid == "$uid" || $fuid == "0") ]] || return 1
  _inst_validate_dir_mode "$fmode" || return 1
  return 0
}

# Ensure a single directory exists with safe validated permissions, distinguishing
# pre-existing directories (validate original mode BEFORE chmod) from newly created directories.
# If <enforce_exact_mode> is 1, applies chmod <target_mode> after pre-validation and confirms
# the resulting mode matches <target_mode>; if 0, preserves a pre-existing directory's valid safe mode.
_inst_ensure_dir_node() { # <dir_path> <target_mode:3-digit> <enforce_exact_mode:0|1>
  local d=$1 tmode=$2 enforce=${3:-1}
  _inst_validate_dir_mode "$tmode" || return 1
  local uid meta ftype fuid orig_mode post_meta post_type post_uid post_mode
  uid=$(id -u)

  if [[ -L $d ]]; then
    return 1
  elif [[ -e $d ]]; then
    # Pre-existing path: MUST be an ordinary directory and MUST pass mode validation BEFORE any chmod
    [[ -d $d ]] || return 1
    meta=$(LC_ALL=C stat -c '%F|%u|%a' -- "$d" 2>/dev/null) || return 1
    IFS='|' read -r ftype fuid orig_mode <<<"$meta"
    [[ $ftype == "directory" && ($fuid == "$uid" || $fuid == "0") ]] || return 1
    _inst_validate_dir_mode "$orig_mode" || return 1

    if ((enforce)); then
      if [[ $orig_mode != "$tmode" ]]; then
        chmod "0${tmode}" -- "$d" 2>/dev/null || return 1
      fi
      post_meta=$(LC_ALL=C stat -c '%F|%u|%a' -- "$d" 2>/dev/null) || return 1
      IFS='|' read -r post_type post_uid post_mode <<<"$post_meta"
      [[ $post_type == "directory" && ($post_uid == "$uid" || $post_uid == "0") ]] || return 1
      _inst_validate_dir_mode "$post_mode" || return 1
      [[ $post_mode == "$tmode" && $((8#$post_mode)) -eq $((8#$tmode)) ]] || return 1
    fi
  else
    # Newly created directory
    mkdir -- "$d" 2>/dev/null || return 1
    [[ ! -L $d && -d $d ]] || return 1
    chmod "0${tmode}" -- "$d" 2>/dev/null || return 1
    post_meta=$(LC_ALL=C stat -c '%F|%u|%a' -- "$d" 2>/dev/null) || return 1
    IFS='|' read -r post_type post_uid post_mode <<<"$post_meta"
    [[ $post_type == "directory" && $post_uid == "$uid" ]] || return 1
    _inst_validate_dir_mode "$post_mode" || return 1
    [[ $post_mode == "$tmode" && $((8#$post_mode)) -eq $((8#$tmode)) ]] || return 1
  fi
  return 0
}

# Walk every ancestor from / down to <target_dir>, validating existing components
# BEFORE any modification and creating only missing components with validated modes.
_inst_ensure_dir_chain() { # <target_dir> <leaf_mode:3-digit> <enforce_leaf_mode:0|1>
  local target=$1 leaf_mode=$2 enforce_leaf=${3:-0}
  _inst_validate_abs_path "$target" "check" || return 1
  _inst_validate_dir_mode "$leaf_mode" || return 1

  local uid cur="" part meta ftype fuid fmode
  uid=$(id -u)
  local IFS=/
  local -a parts=()
  read -r -a parts <<<"${target#/}"

  for part in "${parts[@]}"; do
    cur="${cur}/${part}"
    if [[ $cur == "$target" ]]; then
      _inst_ensure_dir_node "$cur" "$leaf_mode" "$enforce_leaf" || return 1
    else
      if [[ -L $cur ]]; then
        return 1
      elif [[ -e $cur ]]; then
        [[ -d $cur ]] || return 1
        meta=$(LC_ALL=C stat -c '%F|%u|%a' -- "$cur" 2>/dev/null) || return 1
        IFS='|' read -r ftype fuid fmode <<<"$meta"
        [[ $ftype == "directory" && ($fuid == "$uid" || $fuid == "0") ]] || return 1
        if [[ $fuid == "$uid" ]]; then
          _inst_validate_dir_mode "$fmode" || return 1
        fi
      else
        _inst_ensure_dir_node "$cur" "755" 1 || return 1
      fi
    fi
  done
  return 0
}

# Walk every existing ancestor component from / down to target and reject symlinks,
# non-directories, untrusted owners, or group/world-writable or special-bit leaf/user directories.
_inst_verify_parent_chain() { # <path>
  local target=$1
  _inst_validate_abs_path "$target" "check" || return 1

  local uid cur="" part meta ftype fuid fmode
  uid=$(id -u)
  local IFS=/
  local -a parts=()
  read -r -a parts <<<"${target#/}"

  for part in "${parts[@]}"; do
    cur="${cur}/${part}"
    if [[ -L $cur ]]; then
      printf 'authforge-install: symlink component rejected in path: %s\n' "$cur" >&2
      return 1
    fi
    if [[ -e $cur ]]; then
      if [[ ! -d $cur ]]; then
        printf 'authforge-install: non-directory component in path: %s\n' "$cur" >&2
        return 1
      fi
      meta=$(LC_ALL=C stat -c '%F|%u|%a' -- "$cur" 2>/dev/null) || return 1
      IFS='|' read -r ftype fuid fmode <<<"$meta"
      if [[ $ftype != "directory" ]]; then
        return 1
      fi
      if [[ $fuid != "$uid" && $fuid != "0" ]]; then
        printf 'authforge-install: untrusted owner (uid=%s) on path component: %s\n' "$fuid" "$cur" >&2
        return 1
      fi
      if [[ $cur == "$target" || $fuid == "$uid" ]]; then
        if ! _inst_validate_dir_mode "$fmode"; then
          printf 'authforge-install: unsafe or special-bit directory mode rejected (%s mode %s)\n' "$cur" "$fmode" >&2
          return 1
        fi
      fi
    fi
  done
  return 0
}

# Pre-validate an existing datadir and any existing subdirectories/files inside it
# BEFORE any mkdir or chmod runs, so unsafe/special-bit modes on pre-existing data
# subdirectories are rejected untouched rather than masked by chmod 0700.
_inst_verify_existing_datadir() { # <datadir>
  local ddir=$1
  if [[ ! -e $ddir && ! -L $ddir ]]; then
    return 0
  fi
  _inst_verify_existing_dir_node "$ddir" || return 1

  local sub dsub gk
  for sub in "${INST_DATA_SUBDIRS[@]}"; do
    dsub="$ddir/$sub"
    if [[ -e $dsub || -L $dsub ]]; then
      _inst_verify_existing_dir_node "$dsub" || return 1
    fi
  done

  for gk in "$ddir/logs/.gitkeep" "$ddir/reports/.gitkeep" "$ddir/evidence/.gitkeep" \
            "$ddir/config/authforge.conf" "$ddir/.authforge-data-marker"; do
    if [[ -L $gk ]] || { [[ -e $gk ]] && [[ ! -f $gk ]]; }; then
      return 1
    fi
  done
  return 0
}

_inst_check_prereqs() {
  if ((BASH_VERSINFO[0] < 5)); then
    _inst_die "$EX_DEPENDENCY" "Bash 5+ required (found ${BASH_VERSION:-unknown})"
  fi
  local c missing=()
  for c in "${INST_REQUIRED_CMDS[@]}"; do
    if ! command -v "$c" >/dev/null 2>&1; then
      missing+=("$c")
    fi
  done
  if ((${#missing[@]} > 0)); then
    _inst_die "$EX_DEPENDENCY" "missing required commands: ${missing[*]}"
  fi
  return 0
}

# Full manifest and directory-tree verification for an existing installation directory.
# If <libdir> does not exist at all, returns 0 (fresh install).
# Supports:
#   - format=authforge-install-manifest-v2 (native: DIR <relpath> <3-digit-octal-mode>, compares exact directory mode)
#   - format=authforge-install-manifest-v1 (controlled migration: DIR <relpath>, verifies full v1 schema,
#     directory ownership and strict 3-digit safe mode via _inst_validate_dir_mode, all file modes/hashes,
#     and zero unlisted files before allowing upgrade to v2)
# Never silently reinterprets v1 DIR entries as v2 or vice versa, and never masks special bits.
_inst_verify_existing_libdir() { # <libdir>
  local ldir=$1
  if [[ ! -e $ldir && ! -L $ldir ]]; then
    return 0
  fi
  [[ -d $ldir && ! -L $ldir ]] || return 1

  local uid lmeta ltype luid lmode
  uid=$(id -u)
  lmeta=$(LC_ALL=C stat -c '%F|%u|%a' -- "$ldir" 2>/dev/null) || return 1
  IFS='|' read -r ltype luid lmode <<<"$lmeta"
  if [[ $ltype != "directory" || ($luid != "$uid" && $luid != "0") ]] || ! _inst_validate_dir_mode "$lmode"; then
    return 1
  fi

  local mfile="$ldir/.authforge-install.manifest"
  [[ -f $mfile && ! -L $mfile ]] || return 1
  local mmeta mtype muid mmode
  mmeta=$(LC_ALL=C stat -c '%F|%u|%a' -- "$mfile" 2>/dev/null) || return 1
  IFS='|' read -r mtype muid mmode <<<"$mmeta"
  if [[ $mtype != "regular file" || ($muid != "$uid" && $muid != "0") || ! $mmode =~ ^[0-7]{3}$ || $((8#$mmode & 8#7022)) -ne 0 ]]; then
    return 1
  fi

  declare -A allowed_top_set=() allowed_dir_set=() seen_hdr=() man_dir_set=() man_dir_mode=() man_file_hash=() man_file_mode=()
  local tf sd
  for tf in "${INST_TOP_FILES[@]}"; do allowed_top_set[$tf]=1; done
  for sd in "${INST_SUBDIRS[@]}"; do allowed_dir_set[$sd]=1; done

  local m_format="" m_version="" m_installed_at="" m_installed_uid=""
  local m_libdir="" m_bindir="" m_launcher="" m_datadir=""
  local -a man_dirs=() man_files=()
  local line line_no=0

  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%$'\r'}
    ((line_no += 1))
    [[ -n $line ]] || return 1
    if ((line_no == 1)); then
      if [[ $line != "format=authforge-install-manifest-v2" && $line != "format=authforge-install-manifest-v1" ]]; then
        return 1
      fi
    fi
    case $line in
      format=*)
        [[ -z ${seen_hdr[format]:-} ]] || return 1
        seen_hdr[format]=1
        m_format=${line#format=} ;;
      version=*)
        [[ -z ${seen_hdr[version]:-} ]] || return 1
        seen_hdr[version]=1
        m_version=${line#version=} ;;
      installed_at=*)
        [[ -z ${seen_hdr[installed_at]:-} ]] || return 1
        seen_hdr[installed_at]=1
        m_installed_at=${line#installed_at=} ;;
      installed_uid=*)
        [[ -z ${seen_hdr[installed_uid]:-} ]] || return 1
        seen_hdr[installed_uid]=1
        m_installed_uid=${line#installed_uid=} ;;
      libdir=*)
        [[ -z ${seen_hdr[libdir]:-} ]] || return 1
        seen_hdr[libdir]=1
        m_libdir=${line#libdir=} ;;
      bindir=*)
        [[ -z ${seen_hdr[bindir]:-} ]] || return 1
        seen_hdr[bindir]=1
        m_bindir=${line#bindir=} ;;
      launcher=*)
        [[ -z ${seen_hdr[launcher]:-} ]] || return 1
        seen_hdr[launcher]=1
        m_launcher=${line#launcher=} ;;
      datadir=*)
        [[ -z ${seen_hdr[datadir]:-} ]] || return 1
        seen_hdr[datadir]=1
        m_datadir=${line#datadir=} ;;
      "DIR "*)
        local rest_dir=${line#DIR }
        local drel="" dmode="" dextra=""
        read -r drel dmode dextra <<<"$rest_dir"
        if [[ $m_format == "authforge-install-manifest-v2" ]]; then
          [[ -n $drel && -n $dmode && -z $dextra ]] || return 1
          _inst_validate_dir_mode "$dmode" || return 1
        elif [[ $m_format == "authforge-install-manifest-v1" ]]; then
          [[ -n $drel && -z $dmode && -z $dextra ]] || return 1
        else
          return 1
        fi
        _inst_validate_relpath "$drel" || return 1
        [[ -n ${allowed_dir_set[$drel]:-} ]] || return 1
        [[ -z ${man_dir_set[$drel]:-} ]] || return 1
        man_dirs+=("$drel")
        man_dir_set[$drel]=1
        if [[ $m_format == "authforge-install-manifest-v2" ]]; then
          man_dir_mode[$drel]=$dmode
        fi ;;
      "FILE "*)
        local rest=${line#FILE }
        local fmode="" fsha="" frel="" extra=""
        read -r fmode fsha frel extra <<<"$rest"
        [[ -n $fmode && -n $fsha && -n $frel && -z $extra ]] || return 1
        [[ $fmode =~ ^[0-7]{3}$ && $((8#$fmode & 8#7022)) -eq 0 ]] || return 1
        [[ $fsha =~ ^[0-9a-f]{64}$ ]] || return 1
        _inst_validate_relpath "$frel" || return 1
        if [[ $frel == */* ]]; then
          local fsub=${frel%%/*} fleaf=${frel#*/}
          [[ $fleaf != */* && -n ${allowed_dir_set[$fsub]:-} ]] || return 1
        else
          [[ -n ${allowed_top_set[$frel]:-} ]] || return 1
        fi
        [[ -z ${man_file_hash[$frel]:-} ]] || return 1
        man_files+=("$frel")
        man_file_hash[$frel]=$fsha
        man_file_mode[$frel]=$fmode ;;
      *)
        return 1 ;;
    esac
  done <"$mfile"

  [[ $m_format == "authforge-install-manifest-v2" || $m_format == "authforge-install-manifest-v1" ]] || return 1
  [[ $m_version == "0.1.0" ]] || return 1
  [[ $m_installed_at =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[+-][0-9]{4}$ ]] || return 1
  [[ $m_installed_uid =~ ^[0-9]+$ && ($m_installed_uid == "$uid" || $m_installed_uid == "0") ]] || return 1
  [[ $m_libdir == "$ldir" ]] || return 1
  _inst_validate_abs_path "$m_bindir" "bindir" || return 1
  [[ $m_launcher == "${m_bindir}/authforge" ]] || return 1
  _inst_validate_abs_path "$m_datadir" "datadir" || return 1
  if [[ $m_libdir == "$m_datadir" || $m_libdir == "$m_datadir/"* || $m_datadir == "$m_libdir/"* ]]; then
    return 1
  fi

  # Require all 10 runtime subdirectories and all core anchor files in manifest
  ((${#man_dirs[@]} == ${#INST_SUBDIRS[@]})) || return 1
  for sd in "${INST_SUBDIRS[@]}"; do
    [[ -n ${man_dir_set[$sd]:-} ]] || return 1
  done
  local anchor
  for anchor in "${INST_CORE_ANCHORS[@]}"; do
    [[ -n ${man_file_hash[$anchor]:-} ]] || return 1
  done

  # 1. Verify every manifested directory on disk (no symlinks, safe owner, 3-digit mode with no special bits, and exact mode match in v2)
  local drel full_d dmeta dtype duid dmode_actual
  for drel in "${man_dirs[@]}"; do
    full_d="$ldir/$drel"
    [[ -d $full_d && ! -L $full_d ]] || return 1
    dmeta=$(LC_ALL=C stat -c '%F|%u|%a' -- "$full_d" 2>/dev/null) || return 1
    IFS='|' read -r dtype duid dmode_actual <<<"$dmeta"
    [[ $dtype == "directory" && ($duid == "$uid" || $duid == "0") ]] || return 1
    _inst_validate_dir_mode "$dmode_actual" || return 1
    if [[ $m_format == "authforge-install-manifest-v2" ]]; then
      [[ $dmode_actual == "${man_dir_mode[$drel]}" && $((8#$dmode_actual)) -eq $((8#${man_dir_mode[$drel]})) ]] || return 1
    fi
  done

  # 2. Verify every manifested file on disk (no symlinks, safe owner/mode, exact mode & SHA-256)
  local frel full_f fmeta ftype fuid fmode_actual sha_out actual_sha
  for frel in "${man_files[@]}"; do
    full_f="$ldir/$frel"
    [[ -f $full_f && ! -L $full_f ]] || return 1
    fmeta=$(LC_ALL=C stat -c '%F|%u|%a' -- "$full_f" 2>/dev/null) || return 1
    IFS='|' read -r ftype fuid fmode_actual <<<"$fmeta"
    [[ $ftype == "regular file" && ($fuid == "$uid" || $fuid == "0") && $fmode_actual =~ ^[0-7]{3}$ && $((8#$fmode_actual & 8#7022)) -eq 0 ]] || return 1
    [[ $fmode_actual == "${man_file_mode[$frel]}" && $((8#$fmode_actual)) -eq $((8#${man_file_mode[$frel]})) ]] || return 1
    sha_out=$(sha256sum -- "$full_f" 2>/dev/null) || return 1
    actual_sha=${sha_out%% *}
    [[ ${actual_sha,,} == "${man_file_hash[$frel]}" ]] || return 1
  done

  # 3. Scan libdir exhaustively (dotglob + nullglob) without following symlinks to reject any extra/unlisted entry
  local item ibase sub sbase rel_item disk_file_count=0
  shopt -s nullglob dotglob
  for item in "$ldir"/*; do
    ibase=${item##*/}
    [[ $ibase == "." || $ibase == ".." || $ibase == ".authforge-install.manifest" ]] && continue
    if [[ -L $item ]]; then
      shopt -u nullglob dotglob
      return 1
    elif [[ -d $item ]]; then
      if [[ -z ${man_dir_set[$ibase]:-} ]]; then
        shopt -u nullglob dotglob
        return 1
      fi
      for sub in "$item"/*; do
        sbase=${sub##*/}
        [[ $sbase == "." || $sbase == ".." ]] && continue
        rel_item="${ibase}/${sbase}"
        if [[ -L $sub || ! -f $sub || -z ${man_file_hash[$rel_item]:-} ]]; then
          shopt -u nullglob dotglob
          return 1
        fi
        ((disk_file_count += 1))
      done
    elif [[ -f $item ]]; then
      if [[ -z ${man_file_hash[$ibase]:-} ]]; then
        shopt -u nullglob dotglob
        return 1
      fi
      ((disk_file_count += 1))
    else
      shopt -u nullglob dotglob
      return 1
    fi
  done
  shopt -u nullglob dotglob

  ((disk_file_count == ${#man_files[@]})) || return 1
  return 0
}

# Reject source trees containing symlinks or special directory permission bits inside runtime directories.
_inst_verify_source_tree() { # <src_root>
  local sroot=$1 f d smode
  [[ -f "$sroot/authforge.sh" && ! -L "$sroot/authforge.sh" ]] || return 1
  [[ -f "$sroot/data/compliance_mappings.dat" && ! -L "$sroot/data/compliance_mappings.dat" ]] || return 1
  smode=$(LC_ALL=C stat -c '%a' -- "$sroot" 2>/dev/null) || return 1
  _inst_validate_dir_mode "$smode" || return 1
  for d in "${INST_SUBDIRS[@]}"; do
    [[ -d "$sroot/$d" && ! -L "$sroot/$d" ]] || return 1
    smode=$(LC_ALL=C stat -c '%a' -- "$sroot/$d" 2>/dev/null) || return 1
    _inst_validate_dir_mode "$smode" || return 1
    shopt -s nullglob dotglob
    for f in "$sroot/$d"/*; do
      if [[ -L $f || ! -f $f ]]; then
        shopt -u nullglob dotglob
        return 1
      fi
    done
    shopt -u nullglob dotglob
  done
  return 0
}

main() {
  local prefix="" libdir="" bindir="" datadir="" dry_run=0
  while (($#)); do
    case $1 in
      --prefix)
        (($# >= 2)) || _inst_die "$EX_USAGE" "option --prefix requires an argument"
        prefix=$2; shift ;;
      --libdir)
        (($# >= 2)) || _inst_die "$EX_USAGE" "option --libdir requires an argument"
        libdir=$2; shift ;;
      --bindir)
        (($# >= 2)) || _inst_die "$EX_USAGE" "option --bindir requires an argument"
        bindir=$2; shift ;;
      --datadir)
        (($# >= 2)) || _inst_die "$EX_USAGE" "option --datadir requires an argument"
        datadir=$2; shift ;;
      --dry-run)
        dry_run=1 ;;
      -h | --help)
        _inst_usage; exit 0 ;;
      *)
        _inst_die "$EX_USAGE" "unknown option: $1" ;;
    esac
    shift
  done

  _inst_check_prereqs

  local self_path src_dir src_root
  self_path=$(readlink -f -- "${BASH_SOURCE[0]}") || _inst_die "$EX_GENERAL" "cannot resolve script path"
  src_dir=${self_path%/*}
  src_root=$(readlink -f -- "${src_dir}/..") || _inst_die "$EX_GENERAL" "cannot resolve source root"

  _inst_verify_source_tree "$src_root" || _inst_die "$EX_VALIDATION" "source tree failed integrity/symlink/permission check: $src_root"

  if [[ -n $prefix ]]; then
    _inst_validate_abs_path "$prefix" "prefix" || _inst_die "$EX_VALIDATION" "invalid --prefix path: $prefix"
    [[ -n $libdir ]] || libdir="${prefix}/share/authforge"
    [[ -n $bindir ]] || bindir="${prefix}/bin"
  fi

  if [[ -z $libdir || -z $bindir || -z $datadir ]]; then
    [[ -n ${HOME:-} ]] || _inst_die "$EX_VALIDATION" "HOME is not set; specify --libdir, --bindir, and --datadir explicitly"
    _inst_validate_abs_path "${HOME%/}" "home" || _inst_die "$EX_VALIDATION" "HOME is not a valid absolute path: $HOME"
    [[ -n $libdir ]] || libdir="${HOME%/}/.local/share/authforge"
    [[ -n $bindir ]] || bindir="${HOME%/}/.local/bin"
    [[ -n $datadir ]] || datadir="${HOME%/}/.local/state/authforge"
  fi

  _inst_validate_abs_path "$libdir" "libdir" || _inst_die "$EX_VALIDATION" "invalid --libdir path: $libdir"
  _inst_validate_abs_path "$bindir" "bindir" || _inst_die "$EX_VALIDATION" "invalid --bindir path: $bindir"
  _inst_validate_abs_path "$datadir" "datadir" || _inst_die "$EX_VALIDATION" "invalid --datadir path: $datadir"

  if [[ $libdir == "$datadir" || $libdir == "$datadir/"* || $datadir == "$libdir/"* ]]; then
    _inst_die "$EX_VALIDATION" "code directory ($libdir) and data directory ($datadir) must be disjoint"
  fi
  if [[ $libdir == "$bindir" || $datadir == "$bindir" ]]; then
    _inst_die "$EX_VALIDATION" "bindir ($bindir) must be distinct from libdir and datadir"
  fi
  if [[ $libdir == "$src_root" || $datadir == "$src_root" ]]; then
    _inst_die "$EX_VALIDATION" "refusing to install directly over source checkout ($src_root)"
  fi

  # Pre-validate all existing parent chains, existing libdir, and existing datadir
  # BEFORE any mkdir, chmod, or file write can occur.
  _inst_verify_parent_chain "$libdir" || _inst_die "$EX_VALIDATION" "unsafe parent chain for libdir: $libdir"
  _inst_verify_parent_chain "$bindir" || _inst_die "$EX_VALIDATION" "unsafe parent chain for bindir: $bindir"
  _inst_verify_parent_chain "$datadir" || _inst_die "$EX_VALIDATION" "unsafe parent chain for datadir: $datadir"

  if ! _inst_verify_existing_libdir "$libdir"; then
    _inst_die "$EX_VALIDATION" "refusing to overwrite directory that failed full AUTHFORGE manifest verification: $libdir"
  fi

  if ! _inst_verify_existing_datadir "$datadir"; then
    _inst_die "$EX_VALIDATION" "existing data directory or subdirectory failed permission/integrity check: $datadir"
  fi

  local launcher="${bindir}/authforge"
  if [[ -L $launcher ]]; then
    local existing_target
    existing_target=$(readlink -- "$launcher" 2>/dev/null || true)
    if [[ $existing_target != "${libdir}/scripts/authforge-safe.sh" ]]; then
      _inst_die "$EX_VALIDATION" "refusing to overwrite existing symlink pointing to unrelated target: $launcher -> $existing_target"
    fi
  elif [[ -e $launcher ]]; then
    _inst_die "$EX_VALIDATION" "refusing to overwrite existing non-symlink file at launcher path: $launcher"
  fi

  if ((dry_run)); then
    printf 'DRY-RUN OK: code=%s launcher=%s data=%s\n' "$libdir" "$launcher" "$datadir"
    exit 0
  fi

  local lib_parent=${libdir%/*}
  local old_umask
  old_umask=$(umask)
  umask 022

  # Ensure parent and launcher directories exist using strict validate-before-chmod ordering
  # (pre-existing directories with valid safe modes 700/750/755 are validated and preserved;
  # newly created directories are set to 0755 and re-verified).
  _inst_ensure_dir_chain "$lib_parent" "755" 0 || _inst_die "$EX_GENERAL" "failed to prepare or validate lib parent directory: $lib_parent"
  _inst_ensure_dir_chain "$bindir" "755" 0 || _inst_die "$EX_GENERAL" "failed to prepare or validate bindir: $bindir"

  _inst_verify_parent_chain "$lib_parent" || _inst_die "$EX_VALIDATION" "lib parent failed post-mkdir check: $lib_parent"
  _inst_verify_parent_chain "$bindir" || _inst_die "$EX_VALIDATION" "bindir failed post-mkdir check: $bindir"

  # 1. Initialize/verify mutable user data directory (0700) using validate-before-chmod ordering
  umask 077
  _inst_ensure_dir_chain "$datadir" "700" 1 || _inst_die "$EX_GENERAL" "failed to prepare or validate data directory: $datadir"
  local sub dsub
  for sub in "${INST_DATA_SUBDIRS[@]}"; do
    dsub="$datadir/$sub"
    _inst_ensure_dir_node "$dsub" "700" 1 || _inst_die "$EX_GENERAL" "failed to prepare or validate data subdirectory: $dsub"
  done
  _inst_verify_parent_chain "$datadir" || _inst_die "$EX_VALIDATION" "datadir failed post-mkdir check: $datadir"

  local gk
  for gk in "$datadir/logs/.gitkeep" "$datadir/reports/.gitkeep" "$datadir/evidence/.gitkeep"; do
    [[ ! -L $gk ]] || _inst_die "$EX_VALIDATION" "symlinked .gitkeep in data dir: $gk"
    if [[ ! -e $gk ]]; then
      : >"$gk" || _inst_die "$EX_GENERAL" "cannot create $gk"
      chmod 0600 "$gk" || _inst_die "$EX_GENERAL" "cannot set 0600 on $gk"
    fi
  done

  # Seed mutable config and profiles into datadir without overwriting existing user customizations
  if [[ ! -e "$datadir/config/authforge.conf" ]]; then
    [[ ! -L "$datadir/config/authforge.conf" ]] || _inst_die "$EX_VALIDATION" "symlinked config in data dir"
    cp -p -- "$src_root/config/authforge.conf" "$datadir/config/authforge.conf" || _inst_die "$EX_GENERAL" "cannot seed authforge.conf"
    chmod 0600 "$datadir/config/authforge.conf" || _inst_die "$EX_GENERAL" "cannot set 0600 on authforge.conf"
  fi
  local pf pbase
  for pf in "$src_root"/profiles/*.profile; do
    pbase=${pf##*/}
    if [[ ! -e "$datadir/profiles/$pbase" ]]; then
      [[ ! -L "$datadir/profiles/$pbase" ]] || _inst_die "$EX_VALIDATION" "symlinked profile in data dir"
      cp -p -- "$pf" "$datadir/profiles/$pbase" || _inst_die "$EX_GENERAL" "cannot seed profile $pbase"
      chmod 0600 "$datadir/profiles/$pbase" || _inst_die "$EX_GENERAL" "cannot set 0600 on profile $pbase"
    fi
  done

  local marker="$datadir/.authforge-data-marker"
  [[ ! -L $marker ]] || _inst_die "$EX_VALIDATION" "symlinked data marker: $marker"
  printf 'format=authforge-data-v1\ndatadir=%s\n' "$datadir" >"$marker" || _inst_die "$EX_GENERAL" "cannot write data marker"
  chmod 0600 "$marker" || _inst_die "$EX_GENERAL" "cannot set 0600 on data marker"

  # 2. Stage code installation in same parent directory as libdir
  umask 022
  local stage_dir stage_root_mode
  stage_dir=$(mktemp -d "${lib_parent}/.authforge-stage.XXXXXX") ||
    _inst_die "$EX_GENERAL" "cannot create staging directory in $lib_parent"
  if ! chmod 0755 "$stage_dir" 2>/dev/null; then
    rm -rf -- "$stage_dir"
    _inst_die "$EX_GENERAL" "cannot set 0755 on staging directory"
  fi
  if ! stage_root_mode=$(LC_ALL=C stat -c '%a' -- "$stage_dir" 2>/dev/null) ||
     ! _inst_validate_dir_mode "$stage_root_mode" || [[ $stage_root_mode != "755" ]]; then
    rm -rf -- "$stage_dir"
    _inst_die "$EX_VALIDATION" "staged root directory failed permission verification"
  fi

  local topf
  for topf in "${INST_TOP_FILES[@]}"; do
    if [[ -f "$src_root/$topf" && ! -L "$src_root/$topf" ]]; then
      cp -p -- "$src_root/$topf" "$stage_dir/$topf" || { rm -rf -- "$stage_dir"; _inst_die "$EX_GENERAL" "failed to copy $topf"; }
      if [[ $topf == "authforge.sh" ]]; then
        chmod 0755 "$stage_dir/$topf" || { rm -rf -- "$stage_dir"; _inst_die "$EX_GENERAL" "cannot chmod $topf"; }
      else
        chmod 0644 "$stage_dir/$topf" || { rm -rf -- "$stage_dir"; _inst_die "$EX_GENERAL" "cannot chmod $topf"; }
      fi
    fi
  done

  local subdir sf sbase dmode_staged
  for subdir in "${INST_SUBDIRS[@]}"; do
    mkdir -- "$stage_dir/$subdir" || { rm -rf -- "$stage_dir"; _inst_die "$EX_GENERAL" "cannot create staged directory $subdir"; }
    chmod 0755 "$stage_dir/$subdir" || { rm -rf -- "$stage_dir"; _inst_die "$EX_GENERAL" "cannot chmod staged directory $subdir"; }
    if ! dmode_staged=$(LC_ALL=C stat -c '%a' -- "$stage_dir/$subdir" 2>/dev/null) ||
       ! _inst_validate_dir_mode "$dmode_staged" || [[ $dmode_staged != "755" ]]; then
      rm -rf -- "$stage_dir"
      _inst_die "$EX_VALIDATION" "staged directory $subdir failed permission verification"
    fi
    shopt -s nullglob
    for sf in "$src_root/$subdir"/*; do
      [[ -f $sf && ! -L $sf ]] || continue
      sbase=${sf##*/}
      cp -p -- "$sf" "$stage_dir/$subdir/$sbase" || { rm -rf -- "$stage_dir"; _inst_die "$EX_GENERAL" "failed to copy $subdir/$sbase"; }
      if [[ $subdir == "scripts" && $sbase == *.sh ]]; then
        chmod 0755 "$stage_dir/$subdir/$sbase" || { rm -rf -- "$stage_dir"; _inst_die "$EX_GENERAL" "cannot chmod $subdir/$sbase"; }
      else
        chmod 0644 "$stage_dir/$subdir/$sbase" || { rm -rf -- "$stage_dir"; _inst_die "$EX_GENERAL" "cannot chmod $subdir/$sbase"; }
      fi
    done
    shopt -u nullglob
  done

  # 3. Generate v2 installation receipt (.authforge-install.manifest) inside stage_dir
  local mfile="$stage_dir/.authforge-install.manifest"
  local ts uid
  printf -v ts '%(%Y-%m-%dT%H:%M:%S%z)T' -1
  uid=$(id -u)
  {
    printf 'format=authforge-install-manifest-v2\n'
    printf 'version=0.1.0\n'
    printf 'installed_at=%s\n' "$ts"
    printf 'installed_uid=%s\n' "$uid"
    printf 'libdir=%s\n' "$libdir"
    printf 'bindir=%s\n' "$bindir"
    printf 'launcher=%s\n' "$launcher"
    printf 'datadir=%s\n' "$datadir"
  } >"$mfile"

  for subdir in "${INST_SUBDIRS[@]}"; do
    if ! dmode_staged=$(LC_ALL=C stat -c '%a' -- "$stage_dir/$subdir" 2>/dev/null) ||
       ! _inst_validate_dir_mode "$dmode_staged"; then
      rm -rf -- "$stage_dir"
      _inst_die "$EX_VALIDATION" "staged directory $subdir has invalid or special permission bits"
    fi
    printf 'DIR %s %s\n' "$subdir" "$dmode_staged" >>"$mfile"
  done

  local -a staged_files=()
  for topf in "${INST_TOP_FILES[@]}"; do
    [[ -f "$stage_dir/$topf" ]] && staged_files+=("$topf")
  done
  for subdir in "${INST_SUBDIRS[@]}"; do
    shopt -s nullglob
    for sf in "$stage_dir/$subdir"/*; do
      staged_files+=("${subdir}/${sf##*/}")
    done
    shopt -u nullglob
  done

  local rel fmode sha_out fsha
  while IFS= read -r rel; do
    [[ -n $rel ]] || continue
    if ! fmode=$(LC_ALL=C stat -c '%a' -- "$stage_dir/$rel" 2>/dev/null) ||
       [[ ! $fmode =~ ^[0-7]{3}$ || $((8#$fmode & 8#7022)) -ne 0 ]]; then
      rm -rf -- "$stage_dir"
      _inst_die "$EX_VALIDATION" "staged file $rel has invalid or special permission bits"
    fi
    sha_out=$(sha256sum -- "$stage_dir/$rel") || { rm -rf -- "$stage_dir"; _inst_die "$EX_GENERAL" "sha256sum failed on $rel"; }
    fsha=${sha_out%% *}
    printf 'FILE %s %s %s\n' "$fmode" "${fsha,,}" "$rel" >>"$mfile"
  done < <(printf '%s\n' "${staged_files[@]}" | LC_ALL=C sort)
  chmod 0644 "$mfile" || { rm -rf -- "$stage_dir"; _inst_die "$EX_GENERAL" "cannot chmod manifest"; }

  # 4. Atomic replacement of libdir and launcher with pre-swap verification and rollback on failure
  local backup_old=""
  if [[ -e $libdir || -L $libdir ]]; then
    if ! _inst_verify_existing_libdir "$libdir"; then
      rm -rf -- "$stage_dir"
      _inst_die "$EX_VALIDATION" "existing installation directory failed pre-swap verification: $libdir"
    fi
    backup_old="${lib_parent}/.authforge-old.$$"
    rm -rf -- "$backup_old" 2>/dev/null || true
    if ! mv -- "$libdir" "$backup_old"; then
      rm -rf -- "$stage_dir"
      _inst_die "$EX_GENERAL" "failed to move existing installation to rollback path"
    fi
  fi

  if ! mv -- "$stage_dir" "$libdir"; then
    rm -rf -- "$stage_dir"
    if [[ -n $backup_old && -d $backup_old ]]; then
      mv -- "$backup_old" "$libdir" 2>/dev/null || true
    fi
    _inst_die "$EX_GENERAL" "failed to move staged installation into $libdir"
  fi

  local tmp_link="${bindir}/.authforge-link.$$"
  rm -f -- "$tmp_link" 2>/dev/null || true
  local link_ok=1
  if [[ ${AN_INSTALL_FAIL_AFTER_SWAP:-0} == "1" ]]; then
    link_ok=0
  elif ! ln -s -- "${libdir}/scripts/authforge-safe.sh" "$tmp_link" 2>/dev/null; then
    link_ok=0
  elif ! mv -f -T -- "$tmp_link" "$launcher" 2>/dev/null; then
    rm -f -- "$tmp_link" 2>/dev/null || true
    link_ok=0
  fi

  if ((link_ok == 0)); then
    rm -rf -- "$libdir" 2>/dev/null || true
    if [[ -n $backup_old && -d $backup_old ]]; then
      mv -- "$backup_old" "$libdir" 2>/dev/null || true
    fi
    _inst_die "$EX_GENERAL" "failed to install launcher symlink at $launcher; rolled back installation"
  fi

  if [[ -n $backup_old && -d $backup_old ]]; then
    rm -rf -- "$backup_old" 2>/dev/null || true
  fi

  umask "$old_umask"
  printf 'Installed AUTHFORGE v0.1.0\n'
  printf '  Code (AN_ROOT):     %s\n' "$libdir"
  printf '  Launcher:           %s -> %s/scripts/authforge-safe.sh\n' "$launcher" "$libdir"
  printf '  Data (AN_DATA_DIR): %s\n' "$datadir"
  return 0
}

main "$@"
