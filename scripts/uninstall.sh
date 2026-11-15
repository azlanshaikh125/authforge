#!/usr/bin/env bash
# shellcheck shell=bash
# AUTHFORGE M5-P2: Safe manifest-verifying uninstaller.
# Verifies .authforge-install.manifest (supports v2 with exact 3-digit DIR <relpath> <octal-mode>
# verification and v1 with strict 2-token DIR <relpath> + 3-digit on-disk permission verification,
# rejecting 4-digit modes and setuid/setgid/sticky bits on both manifest and disk,
# file modes, SHA-256 digests, and absence of unmanifested/unexpected files) and removes
# only verified AUTHFORGE code files and directories using rm + rmdir (never unrestricted rm -rf).
# Preserves user runtime data (AN_DATA_DIR) by default unless --purge-data is passed.
unset BASH_ENV ENV CDPATH
set -Eeuo pipefail
IFS=$' \t\n'

readonly EX_GENERAL=1
readonly EX_USAGE=2
readonly EX_VALIDATION=6

readonly -a UNINST_TOP_FILES=(
  authforge.sh Makefile LICENSE README.md CHANGELOG.md SECURITY.md CONTRIBUTING.md
)

readonly -a UNINST_SUBDIRS=(
  config core data docs fixtures lib modules plugins profiles scripts
)

readonly -a UNINST_CORE_ANCHORS=(
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

_uninst_die() {
  local code=$1
  shift
  printf 'authforge-uninstall: %s\n' "$*" >&2
  exit "$code"
}

_uninst_usage() {
  cat <<'USAGE'
Usage: ./scripts/uninstall.sh [options]

Uninstall AUTHFORGE by verifying .authforge-install.manifest and removing only
verified installed code files and the launcher symlink.
By default, user runtime data (reports, logs, evidence, backups, config) is PRESERVED.

Options:
  --prefix DIR          Base prefix used during install (DIR/share/authforge, DIR/bin)
  --libdir DIR          Explicit code installation directory (default: ~/.local/share/authforge)
  --bindir DIR          Explicit launcher directory (default: ~/.local/bin)
  --datadir DIR         Explicit mutable data directory (default: ~/.local/state/authforge)
  --purge-data          Also remove the validated user data directory (AN_DATA_DIR)
  --dry-run             Verify manifest and print planned removals without deleting files
  -h, --help            Show this help message
USAGE
}

_uninst_validate_abs_path() { # <path> <role>
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

_uninst_validate_relpath() { # <rel>
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
_uninst_validate_dir_mode() { # <mode_str>
  local m=${1:-}
  [[ $m =~ ^[0-7]{3}$ ]] || return 1
  (((8#$m & 8#7022) == 0 && (8#$m & 8#500) == 8#500)) || return 1
  return 0
}

_uninst_verify_parent_chain() { # <path>
  local target=$1
  _uninst_validate_abs_path "$target" "check" || return 1
  local uid cur="" part meta ftype fuid fmode
  uid=$(id -u)
  local IFS=/
  local -a parts=()
  read -r -a parts <<<"${target#/}"
  for part in "${parts[@]}"; do
    cur="${cur}/${part}"
    if [[ -L $cur ]]; then
      return 1
    fi
    if [[ -e $cur ]]; then
      [[ -d $cur ]] || return 1
      meta=$(LC_ALL=C stat -c '%F|%u|%a' -- "$cur" 2>/dev/null) || return 1
      IFS='|' read -r ftype fuid fmode <<<"$meta"
      [[ $ftype == "directory" ]] || return 1
      [[ $fuid == "$uid" || $fuid == "0" ]] || return 1
      if [[ $cur == "$target" || $fuid == "$uid" ]]; then
        _uninst_validate_dir_mode "$fmode" || return 1
      fi
    fi
  done
  return 0
}

# Validate that datadir is a genuine AUTHFORGE data directory with no unknown top-level entries.
_uninst_verify_datadir_for_purge() { # <datadir> <expected_datadir>
  local ddir=$1 exp_ddir=$2
  [[ $ddir == "$exp_ddir" ]] || return 1
  _uninst_validate_abs_path "$ddir" "datadir" || return 1
  _uninst_verify_parent_chain "$ddir" || return 1
  [[ -d $ddir && ! -L $ddir ]] || return 1

  local uid meta ftype fuid fmode
  uid=$(id -u)
  meta=$(LC_ALL=C stat -c '%F|%u|%a' -- "$ddir" 2>/dev/null) || return 1
  IFS='|' read -r ftype fuid fmode <<<"$meta"
  [[ $ftype == "directory" && $fuid == "$uid" && $fmode == "700" ]] || return 1

  local marker="$ddir/.authforge-data-marker"
  [[ -f $marker && ! -L $marker ]] || return 1
  local m_fmt m_dir
  m_fmt=$(grep -E '^format=' "$marker" 2>/dev/null | head -n 1 || true)
  m_dir=$(grep -E '^datadir=' "$marker" 2>/dev/null | head -n 1 || true)
  [[ $m_fmt == "format=authforge-data-v1" && $m_dir == "datadir=$ddir" ]] || return 1

  local entry ebase sub sfile emode
  shopt -s nullglob dotglob
  for entry in "$ddir"/*; do
    ebase=${entry##*/}
    case $ebase in
      . | .. | .authforge-data-marker) continue ;;
      logs | reports | evidence | backups | config | profiles)
        [[ -d $entry && ! -L $entry ]] || { shopt -u nullglob dotglob; return 1; }
        emode=$(LC_ALL=C stat -c '%a' -- "$entry" 2>/dev/null) || { shopt -u nullglob dotglob; return 1; }
        _uninst_validate_dir_mode "$emode" || { shopt -u nullglob dotglob; return 1; }
        for sub in "$entry"/*; do
          [[ ${sub##*/} == "." || ${sub##*/} == ".." ]] && continue
          if [[ -L $sub ]]; then
            shopt -u nullglob dotglob
            return 1
          fi
          if [[ -d $sub ]]; then
            for sfile in "$sub"/*; do
              [[ ${sfile##*/} == "." || ${sfile##*/} == ".." ]] && continue
              if [[ -L $sfile || ! -f $sfile ]]; then
                shopt -u nullglob dotglob
                return 1
              fi
            done
          elif [[ ! -f $sub ]]; then
            shopt -u nullglob dotglob
            return 1
          fi
        done ;;
      *)
        shopt -u nullglob dotglob
        printf 'authforge-uninstall: refusing --purge-data due to unknown entry in datadir: %s\n' "$entry" >&2
        return 1 ;;
    esac
  done
  shopt -u nullglob dotglob
  return 0
}

_uninst_purge_datadir() { # <datadir>
  local ddir=$1 entry sub sfile
  shopt -s nullglob dotglob
  for entry in "$ddir"/{logs,reports,evidence,backups,config,profiles}; do
    [[ -d $entry && ! -L $entry ]] || continue
    for sub in "$entry"/*; do
      [[ ${sub##*/} == "." || ${sub##*/} == ".." ]] && continue
      if [[ -d $sub && ! -L $sub ]]; then
        for sfile in "$sub"/*; do
          [[ ${sfile##*/} == "." || ${sfile##*/} == ".." ]] && continue
          [[ -f $sfile && ! -L $sfile ]] && rm -f -- "$sfile"
        done
        rmdir -- "$sub"
      elif [[ -f $sub && ! -L $sub ]]; then
        rm -f -- "$sub"
      fi
    done
    rmdir -- "$entry"
  done
  shopt -u nullglob dotglob
  rm -f -- "$ddir/.authforge-data-marker"
  rmdir -- "$ddir"
  return 0
}

main() {
  local prefix="" libdir="" bindir="" datadir="" purge_data=0 dry_run=0
  while (($#)); do
    case $1 in
      --prefix)
        (($# >= 2)) || _uninst_die "$EX_USAGE" "option --prefix requires an argument"
        prefix=$2; shift ;;
      --libdir)
        (($# >= 2)) || _uninst_die "$EX_USAGE" "option --libdir requires an argument"
        libdir=$2; shift ;;
      --bindir)
        (($# >= 2)) || _uninst_die "$EX_USAGE" "option --bindir requires an argument"
        bindir=$2; shift ;;
      --datadir)
        (($# >= 2)) || _uninst_die "$EX_USAGE" "option --datadir requires an argument"
        datadir=$2; shift ;;
      --purge-data)
        purge_data=1 ;;
      --dry-run)
        dry_run=1 ;;
      -h | --help)
        _uninst_usage; exit 0 ;;
      *)
        _uninst_die "$EX_USAGE" "unknown option: $1" ;;
    esac
    shift
  done

  if [[ -n $prefix ]]; then
    _uninst_validate_abs_path "$prefix" "prefix" || _uninst_die "$EX_VALIDATION" "invalid --prefix path: $prefix"
    [[ -n $libdir ]] || libdir="${prefix}/share/authforge"
    [[ -n $bindir ]] || bindir="${prefix}/bin"
  fi

  if [[ -z $libdir || -z $bindir ]]; then
    [[ -n ${HOME:-} ]] || _uninst_die "$EX_VALIDATION" "HOME is not set; specify --libdir and --bindir explicitly"
    _uninst_validate_abs_path "${HOME%/}" "home" || _uninst_die "$EX_VALIDATION" "HOME is not a valid absolute path: $HOME"
    [[ -n $libdir ]] || libdir="${HOME%/}/.local/share/authforge"
    [[ -n $bindir ]] || bindir="${HOME%/}/.local/bin"
  fi

  _uninst_validate_abs_path "$libdir" "libdir" || _uninst_die "$EX_VALIDATION" "invalid --libdir path: $libdir"
  _uninst_validate_abs_path "$bindir" "bindir" || _uninst_die "$EX_VALIDATION" "invalid --bindir path: $bindir"
  _uninst_verify_parent_chain "$libdir" || _uninst_die "$EX_VALIDATION" "unsafe path or parent chain for libdir: $libdir"
  _uninst_verify_parent_chain "$bindir" || _uninst_die "$EX_VALIDATION" "unsafe path or parent chain for bindir: $bindir"

  if [[ ! -d $libdir || -L $libdir ]]; then
    _uninst_die "$EX_VALIDATION" "installation directory not found or is a symlink: $libdir"
  fi
  local lmeta ltype luid lmode
  lmeta=$(LC_ALL=C stat -c '%F|%u|%a' -- "$libdir" 2>/dev/null) || _uninst_die "$EX_VALIDATION" "cannot stat installation directory: $libdir"
  IFS='|' read -r ltype luid lmode <<<"$lmeta"
  if [[ $ltype != "directory" || ($luid != "$(id -u)" && $luid != "0") ]] || ! _uninst_validate_dir_mode "$lmode"; then
    _uninst_die "$EX_VALIDATION" "installation directory failed ownership or permission check: $libdir"
  fi

  local mfile="$libdir/.authforge-install.manifest"
  if [[ ! -f $mfile || -L $mfile ]]; then
    _uninst_die "$EX_VALIDATION" "missing or unsafe installation receipt: $mfile"
  fi
  local uid mmeta mtype muid mmode
  uid=$(id -u)
  mmeta=$(LC_ALL=C stat -c '%F|%u|%a' -- "$mfile" 2>/dev/null) || _uninst_die "$EX_VALIDATION" "cannot stat manifest"
  IFS='|' read -r mtype muid mmode <<<"$mmeta"
  if [[ $mtype != "regular file" || ($muid != "$uid" && $muid != "0") || ! $mmode =~ ^[0-7]{3}$ || $((8#$mmode & 8#7022)) -ne 0 ]]; then
    _uninst_die "$EX_VALIDATION" "installation receipt failed ownership/permission check: $mfile"
  fi

  declare -A allowed_top_set=() allowed_dir_set=() seen_hdr=() man_dir_set=() man_dir_mode=() man_file_hash=() man_file_mode=()
  local tf sd
  for tf in "${UNINST_TOP_FILES[@]}"; do allowed_top_set[$tf]=1; done
  for sd in "${UNINST_SUBDIRS[@]}"; do allowed_dir_set[$sd]=1; done

  local m_format="" m_version="" m_installed_at="" m_installed_uid=""
  local m_libdir="" m_bindir="" m_launcher="" m_datadir="" line line_no=0
  local -a man_files=() man_dirs=()

  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%$'\r'}
    ((line_no += 1))
    [[ -n $line ]] || _uninst_die "$EX_VALIDATION" "empty line in installation manifest"
    if ((line_no == 1)); then
      if [[ $line != "format=authforge-install-manifest-v2" && $line != "format=authforge-install-manifest-v1" ]]; then
        _uninst_die "$EX_VALIDATION" "unsupported or invalid manifest format on line 1: $line"
      fi
    fi
    case $line in
      format=*)
        [[ -z ${seen_hdr[format]:-} ]] || _uninst_die "$EX_VALIDATION" "duplicate format header"
        seen_hdr[format]=1; m_format=${line#format=} ;;
      version=*)
        [[ -z ${seen_hdr[version]:-} ]] || _uninst_die "$EX_VALIDATION" "duplicate version header"
        seen_hdr[version]=1; m_version=${line#version=} ;;
      installed_at=*)
        [[ -z ${seen_hdr[installed_at]:-} ]] || _uninst_die "$EX_VALIDATION" "duplicate installed_at header"
        seen_hdr[installed_at]=1; m_installed_at=${line#installed_at=} ;;
      installed_uid=*)
        [[ -z ${seen_hdr[installed_uid]:-} ]] || _uninst_die "$EX_VALIDATION" "duplicate installed_uid header"
        seen_hdr[installed_uid]=1; m_installed_uid=${line#installed_uid=} ;;
      libdir=*)
        [[ -z ${seen_hdr[libdir]:-} ]] || _uninst_die "$EX_VALIDATION" "duplicate libdir header"
        seen_hdr[libdir]=1; m_libdir=${line#libdir=} ;;
      bindir=*)
        [[ -z ${seen_hdr[bindir]:-} ]] || _uninst_die "$EX_VALIDATION" "duplicate bindir header"
        seen_hdr[bindir]=1; m_bindir=${line#bindir=} ;;
      launcher=*)
        [[ -z ${seen_hdr[launcher]:-} ]] || _uninst_die "$EX_VALIDATION" "duplicate launcher header"
        seen_hdr[launcher]=1; m_launcher=${line#launcher=} ;;
      datadir=*)
        [[ -z ${seen_hdr[datadir]:-} ]] || _uninst_die "$EX_VALIDATION" "duplicate datadir header"
        seen_hdr[datadir]=1; m_datadir=${line#datadir=} ;;
      "DIR "*)
        local rest_dir=${line#DIR }
        local drel="" dmode="" dextra=""
        read -r drel dmode dextra <<<"$rest_dir"
        if [[ $m_format == "authforge-install-manifest-v2" ]]; then
          [[ -n $drel && -n $dmode && -z $dextra ]] ||
            _uninst_die "$EX_VALIDATION" "malformed v2 DIR entry in manifest: $line"
          _uninst_validate_dir_mode "$dmode" ||
            _uninst_die "$EX_VALIDATION" "invalid or special-bit octal mode in DIR entry: $line"
        elif [[ $m_format == "authforge-install-manifest-v1" ]]; then
          [[ -n $drel && -z $dmode && -z $dextra ]] ||
            _uninst_die "$EX_VALIDATION" "malformed v1 DIR entry in manifest: $line"
        else
          _uninst_die "$EX_VALIDATION" "unsupported manifest format for DIR entry: $m_format"
        fi
        _uninst_validate_relpath "$drel" || _uninst_die "$EX_VALIDATION" "invalid DIR path in manifest: $drel"
        [[ -n ${allowed_dir_set[$drel]:-} ]] || _uninst_die "$EX_VALIDATION" "unexpected DIR in manifest: $drel"
        [[ -z ${man_dir_set[$drel]:-} ]] || _uninst_die "$EX_VALIDATION" "duplicate DIR in manifest: $drel"
        man_dirs+=("$drel")
        man_dir_set[$drel]=1
        if [[ $m_format == "authforge-install-manifest-v2" ]]; then
          man_dir_mode[$drel]=$dmode
        fi ;;
      "FILE "*)
        local rest=${line#FILE }
        local fmode="" fsha="" frel="" extra=""
        read -r fmode fsha frel extra <<<"$rest"
        [[ -n $fmode && -n $fsha && -n $frel && -z $extra ]] ||
          _uninst_die "$EX_VALIDATION" "malformed FILE entry in manifest: $line"
        [[ $fmode =~ ^[0-7]{3}$ && $((8#$fmode & 8#7022)) -eq 0 ]] ||
          _uninst_die "$EX_VALIDATION" "invalid FILE mode in manifest: $line"
        [[ $fsha =~ ^[0-9a-f]{64}$ ]] ||
          _uninst_die "$EX_VALIDATION" "invalid FILE sha256 in manifest: $line"
        _uninst_validate_relpath "$frel" || _uninst_die "$EX_VALIDATION" "invalid FILE path in manifest: $frel"
        if [[ $frel == */* ]]; then
          local fsub=${frel%%/*} fleaf=${frel#*/}
          [[ $fleaf != */* && -n ${allowed_dir_set[$fsub]:-} ]] ||
            _uninst_die "$EX_VALIDATION" "unexpected FILE path in manifest: $frel"
        else
          [[ -n ${allowed_top_set[$frel]:-} ]] ||
            _uninst_die "$EX_VALIDATION" "unexpected top-level FILE in manifest: $frel"
        fi
        [[ -z ${man_file_hash[$frel]:-} ]] || _uninst_die "$EX_VALIDATION" "duplicate FILE in manifest: $frel"
        man_files+=("$frel")
        man_file_hash[$frel]=$fsha
        man_file_mode[$frel]=$fmode ;;
      *)
        _uninst_die "$EX_VALIDATION" "unrecognized line in installation manifest: $line" ;;
    esac
  done <"$mfile"

  if [[ ($m_format != "authforge-install-manifest-v2" && $m_format != "authforge-install-manifest-v1") || $m_version != "0.1.0" || $m_libdir != "$libdir" ]]; then
    _uninst_die "$EX_VALIDATION" "installation manifest header mismatch in $mfile"
  fi
  if [[ ! $m_installed_at =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[+-][0-9]{4}$ ]] ||
     [[ ! $m_installed_uid =~ ^[0-9]+$ || ($m_installed_uid != "$uid" && $m_installed_uid != "0") ]]; then
    _uninst_die "$EX_VALIDATION" "invalid installed_at or installed_uid in manifest: $mfile"
  fi
  _uninst_validate_abs_path "$m_bindir" "bindir" || _uninst_die "$EX_VALIDATION" "invalid bindir in manifest: $m_bindir"
  [[ $m_launcher == "${m_bindir}/authforge" ]] || _uninst_die "$EX_VALIDATION" "invalid launcher in manifest: $m_launcher"
  [[ -n $datadir ]] || datadir=$m_datadir
  _uninst_validate_abs_path "$datadir" "datadir" || _uninst_die "$EX_VALIDATION" "invalid datadir in manifest: $datadir"
  if [[ $libdir == "$datadir" || $libdir == "$datadir/"* || $datadir == "$libdir/"* ]]; then
    _uninst_die "$EX_VALIDATION" "libdir and datadir in manifest must be disjoint"
  fi

  if ((${#man_dirs[@]} != ${#UNINST_SUBDIRS[@]})); then
    _uninst_die "$EX_VALIDATION" "incomplete DIR inventory in manifest"
  fi
  for sd in "${UNINST_SUBDIRS[@]}"; do
    [[ -n ${man_dir_set[$sd]:-} ]] || _uninst_die "$EX_VALIDATION" "missing required DIR in manifest: $sd"
  done
  local anchor
  for anchor in "${UNINST_CORE_ANCHORS[@]}"; do
    [[ -n ${man_file_hash[$anchor]:-} ]] || _uninst_die "$EX_VALIDATION" "missing core file in manifest: $anchor"
  done

  # 1. Verify every manifested directory exists, is a non-symlink directory, has safe 3-digit mode with no special bits, and matches v2 mode
  local drel full_d dmeta dtype duid dmode_actual
  for drel in "${man_dirs[@]}"; do
    full_d="$libdir/$drel"
    if [[ ! -d $full_d || -L $full_d ]]; then
      _uninst_die "$EX_VALIDATION" "manifested directory is missing or a symlink: $full_d"
    fi
    dmeta=$(LC_ALL=C stat -c '%F|%u|%a' -- "$full_d" 2>/dev/null) || _uninst_die "$EX_VALIDATION" "cannot stat $full_d"
    IFS='|' read -r dtype duid dmode_actual <<<"$dmeta"
    if [[ $dtype != "directory" || ($duid != "$uid" && $duid != "0") ]] || ! _uninst_validate_dir_mode "$dmode_actual"; then
      _uninst_die "$EX_VALIDATION" "manifested directory failed ownership/permission/special-bit check: $full_d"
    fi
    if [[ $m_format == "authforge-install-manifest-v2" ]]; then
      if [[ $dmode_actual != "${man_dir_mode[$drel]}" || $((8#$dmode_actual)) -ne $((8#${man_dir_mode[$drel]})) ]]; then
        _uninst_die "$EX_VALIDATION" "manifested directory mode was modified after installation: $full_d"
      fi
    fi
  done

  # 2. Verify every manifested file exists, is a regular non-symlink file, matches mode and SHA-256
  local frel full_f fmeta ftype fuid fmode_actual sha_out actual_sha
  for frel in "${man_files[@]}"; do
    full_f="$libdir/$frel"
    if [[ ! -f $full_f || -L $full_f ]]; then
      _uninst_die "$EX_VALIDATION" "manifested file is missing or a symlink: $full_f"
    fi
    fmeta=$(LC_ALL=C stat -c '%F|%u|%a' -- "$full_f" 2>/dev/null) || _uninst_die "$EX_VALIDATION" "cannot stat $full_f"
    IFS='|' read -r ftype fuid fmode_actual <<<"$fmeta"
    if [[ $ftype != "regular file" || ($fuid != "$uid" && $fuid != "0") || ! $fmode_actual =~ ^[0-7]{3}$ || $((8#$fmode_actual & 8#7022)) -ne 0 ]]; then
      _uninst_die "$EX_VALIDATION" "manifested file failed ownership/permission check: $full_f"
    fi
    if [[ $fmode_actual != "${man_file_mode[$frel]}" || $((8#$fmode_actual)) -ne $((8#${man_file_mode[$frel]})) ]]; then
      _uninst_die "$EX_VALIDATION" "manifested file mode was modified after installation: $full_f"
    fi
    sha_out=$(sha256sum -- "$full_f" 2>/dev/null) || _uninst_die "$EX_GENERAL" "cannot hash $full_f"
    actual_sha=${sha_out%% *}
    if [[ ${actual_sha,,} != "${man_file_hash[$frel]}" ]]; then
      _uninst_die "$EX_VALIDATION" "manifested file was modified after installation: $full_f"
    fi
  done

  # 3. Scan libdir for any unmanifested/unrelated files or subdirectories before removing anything
  local item ibase sub sbase rel_item disk_file_count=0
  shopt -s nullglob dotglob
  for item in "$libdir"/*; do
    ibase=${item##*/}
    [[ $ibase == "." || $ibase == ".." || $ibase == ".authforge-install.manifest" ]] && continue
    if [[ -L $item ]]; then
      shopt -u nullglob dotglob
      _uninst_die "$EX_VALIDATION" "refusing to uninstall: unexpected symlink in $libdir: $item"
    elif [[ -d $item ]]; then
      if [[ -z ${man_dir_set[$ibase]:-} ]]; then
        shopt -u nullglob dotglob
        _uninst_die "$EX_VALIDATION" "refusing to uninstall: unmanifested directory in $libdir: $item"
      fi
      for sub in "$item"/*; do
        sbase=${sub##*/}
        [[ $sbase == "." || $sbase == ".." ]] && continue
        rel_item="${ibase}/${sbase}"
        if [[ -L $sub || ! -f $sub || -z ${man_file_hash[$rel_item]:-} ]]; then
          shopt -u nullglob dotglob
          _uninst_die "$EX_VALIDATION" "refusing to uninstall: unmanifested or unsafe file in $libdir: $sub"
        fi
        ((disk_file_count += 1))
      done
    elif [[ -f $item ]]; then
      if [[ -z ${man_file_hash[$ibase]:-} ]]; then
        shopt -u nullglob dotglob
        _uninst_die "$EX_VALIDATION" "refusing to uninstall: unmanifested file in $libdir: $item"
      fi
      ((disk_file_count += 1))
    else
      shopt -u nullglob dotglob
      _uninst_die "$EX_VALIDATION" "refusing to uninstall: special file in $libdir: $item"
    fi
  done
  shopt -u nullglob dotglob

  if ((disk_file_count != ${#man_files[@]})); then
    _uninst_die "$EX_VALIDATION" "installed file count mismatch in $libdir"
  fi

  # 4. Verify launcher symlink before removal
  local launcher="${bindir}/authforge"
  if [[ -L $launcher ]]; then
    local ltarget
    ltarget=$(readlink -- "$launcher" 2>/dev/null || true)
    if [[ $ltarget != "${libdir}/scripts/authforge-safe.sh" ]]; then
      _uninst_die "$EX_VALIDATION" "launcher symlink points to unexpected target: $launcher -> $ltarget"
    fi
  elif [[ -e $launcher ]]; then
    _uninst_die "$EX_VALIDATION" "launcher path is not a symlink; refusing to remove: $launcher"
  fi

  # 5. If --purge-data is requested, verify datadir before deleting anything
  if ((purge_data)); then
    if ! _uninst_verify_datadir_for_purge "$datadir" "$m_datadir"; then
      _uninst_die "$EX_VALIDATION" "datadir failed verification for --purge-data: $datadir"
    fi
  fi

  if ((dry_run)); then
    printf 'DRY-RUN UNINSTALL OK: libdir=%s launcher=%s purge_data=%d\n' "$libdir" "$launcher" "$purge_data"
    exit 0
  fi

  # 6. Execute removals using explicit file rm + rmdir (never rm -rf)
  if [[ -L $launcher ]]; then
    rm -f -- "$launcher"
  fi
  for frel in "${man_files[@]}"; do
    rm -f -- "$libdir/$frel"
  done
  rm -f -- "$mfile"

  for drel in "${man_dirs[@]}"; do
    if [[ -d "$libdir/$drel" && ! -L "$libdir/$drel" ]]; then
      rmdir -- "$libdir/$drel"
    fi
  done
  rmdir -- "$libdir"

  printf 'Removed AUTHFORGE code installation: %s\n' "$libdir"
  printf 'Removed AUTHFORGE launcher: %s\n' "$launcher"
  if ((purge_data)); then
    _uninst_purge_datadir "$datadir"
    printf 'Purged AUTHFORGE user data directory: %s\n' "$datadir"
  else
    printf 'Preserved AUTHFORGE user data directory: %s\n' "$datadir"
  fi
  return 0
}

main "$@"
