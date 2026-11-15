#!/usr/bin/env bash
# shellcheck shell=bash
# AUTHFORGE core: configuration + profiles.
# Config files are PARSED, never sourced: only whitelisted keys with
# regex-validated values are accepted (no code execution via config).
[[ -n "${_AN_CONFIG:-}" ]] && return 0
_AN_CONFIG=1

declare -gA AN_CFG=()

declare -gA AN_CFG_DEFAULTS=(
  [log_level]=info
  [color]=auto
  [plugins_enabled]=0
  [common_passwords_file]=fixtures/common-passwords-sample.txt
  [policy_min_length]=12
  [policy_max_length]=128
  [policy_require_classes]=0
  [policy_block_common]=1
  [policy_min_entropy_bits]=40
  [hash_allow_legacy]=0
  [hash_min_bcrypt_cost]=12
  [hash_min_pbkdf2_iterations]=310000
  [hash_min_argon2_mib]=19
  [hash_min_argon2_time]=2
  [hash_min_shacrypt_rounds]=100000
  [wordlist_warn_dup_pct]=10
  [mfa_min_totp_digits]=6
  [mfa_max_totp_window]=1
  [mfa_max_attempts]=5
  [mfa_require_phishing_resistant]=0
  [mfa_min_recovery_entropy_bits]=64
  [session_min_entropy_bits]=128
  [session_max_idle_min]=30
  [session_max_absolute_min]=480
  [reset_min_entropy_bits]=128
  [reset_max_token_ttl_min]=30
  [reset_max_requests_per_hour]=5
  [max_online_requests]=100
  [max_online_rps]=1
  [allow_nonlocal_targets]=0
  [online_connect_timeout_sec]=3
  [online_max_time_sec]=8
)

declare -gA AN_CFG_RULES=(
  [log_level]='^(debug|info|warn|error)$'
  [color]='^(auto|always|never)$'
  [plugins_enabled]='^[01]$'
  [common_passwords_file]='^[A-Za-z0-9._/-]{1,256}$'
  [policy_min_length]='^[0-9]{1,3}$'
  [policy_max_length]='^[0-9]{1,4}$'
  [policy_require_classes]='^[0-4]$'
  [policy_block_common]='^[01]$'
  [policy_min_entropy_bits]='^[0-9]{1,3}$'
  [hash_allow_legacy]='^[01]$'
  [hash_min_bcrypt_cost]='^([4-9]|[12][0-9]|3[01])$'
  [hash_min_pbkdf2_iterations]='^[1-9][0-9]{2,7}$'
  [hash_min_argon2_mib]='^[1-9][0-9]{0,5}$'
  [hash_min_argon2_time]='^[1-9][0-9]{0,2}$'
  [hash_min_shacrypt_rounds]='^[1-9][0-9]{3,8}$'
  [wordlist_warn_dup_pct]='^([0-9]|[1-9][0-9]|100)$'
  [mfa_min_totp_digits]='^[6-8]$'
  [mfa_max_totp_window]='^[0-9]{1,2}$'
  [mfa_max_attempts]='^[1-9][0-9]{0,2}$'
  [mfa_require_phishing_resistant]='^[01]$'
  [mfa_min_recovery_entropy_bits]='^[1-9][0-9]{1,2}$'
  [session_min_entropy_bits]='^[1-9][0-9]{1,2}$'
  [session_max_idle_min]='^[1-9][0-9]{0,4}$'
  [session_max_absolute_min]='^[1-9][0-9]{0,5}$'
  [reset_min_entropy_bits]='^[1-9][0-9]{1,2}$'
  [reset_max_token_ttl_min]='^[1-9][0-9]{0,3}$'
  [reset_max_requests_per_hour]='^[1-9][0-9]{0,2}$'
  [max_online_requests]='^[0-9]{1,5}$'
  [max_online_rps]='^[1-9][0-9]{0,1}$'
  [allow_nonlocal_targets]='^[01]$'
  [online_connect_timeout_sec]='^[1-9][0-9]{0,1}$'
  [online_max_time_sec]='^[1-9][0-9]{0,2}$'
)

config_defaults() {
  local k
  for k in "${!AN_CFG_DEFAULTS[@]}"; do AN_CFG[$k]=${AN_CFG_DEFAULTS[$k]}; done
  return 0
}

# Parse one config/profile file. mode=apply writes into AN_CFG; mode=check only
# validates. Prints errors to stderr; returns 0 if the file is valid.
_config_parse_file() { # <file> <apply|check>
  local file=$1 mode=$2 line key val n=0 bad=0
  while IFS= read -r line || [[ -n $line ]]; do
    n=$((n + 1))
    line=${line%$'\r'}
    line=$(str_trim "$line")
    if [[ -z $line || $line == \#* ]]; then continue; fi
    if [[ ! $line =~ ^([a-z0-9_]+)=(.*)$ ]]; then
      printf '%s:%d: malformed line\n' "$file" "$n" >&2
      bad=$((bad + 1))
      continue
    fi
    key=${BASH_REMATCH[1]}
    val=$(str_trim "${BASH_REMATCH[2]}")
    if [[ -z ${AN_CFG_RULES[$key]+x} ]]; then
      printf '%s:%d: unknown key "%s"\n' "$file" "$n" "$key" >&2
      bad=$((bad + 1))
      continue
    fi
    if [[ ! $val =~ ${AN_CFG_RULES[$key]} ]]; then
      printf '%s:%d: invalid value for %s\n' "$file" "$n" "$key" >&2
      bad=$((bad + 1))
      continue
    fi
    if [[ $mode == apply ]]; then AN_CFG[$key]=$val; fi
  done <"$file"
  ((bad == 0))
}

# Cross-field consistency checks on the effective config.
config_validate_effective() {
  local bad=0
  if ((10#${AN_CFG[policy_min_length]} > 10#${AN_CFG[policy_max_length]})); then
    printf 'policy_min_length exceeds policy_max_length\n' >&2
    bad=1
  fi
  if ((10#${AN_CFG[policy_max_length]} > 1024)); then
    printf 'policy_max_length above supported ceiling (1024)\n' >&2
    bad=1
  fi
  if ((10#${AN_CFG[session_max_idle_min]} > 10#${AN_CFG[session_max_absolute_min]})); then
    printf 'session_max_idle_min exceeds session_max_absolute_min\n' >&2
    bad=1
  fi
  if ((10#${AN_CFG[online_connect_timeout_sec]} > 10#${AN_CFG[online_max_time_sec]})); then
    printf 'online_connect_timeout_sec exceeds online_max_time_sec\n' >&2
    bad=1
  fi
  ((bad == 0))
}

# Determine whether mutable configuration lives in AN_DATA_DIR (installed mode
# or read-only AN_ROOT) vs AN_ROOT (writable repository checkout mode).
_config_use_data_dir() {
  if [[ -f "$AN_ROOT/.authforge-install.manifest" || ! -w "$AN_ROOT/config" || ! -w "$AN_ROOT/profiles" || ! -O "$AN_ROOT" ]]; then
    return 0
  fi
  if [[ -n ${AN_DATA_DIR:-} && $AN_DATA_DIR != "$AN_ROOT" && -d "$AN_DATA_DIR/config" && -d "$AN_DATA_DIR/profiles" ]]; then
    return 0
  fi
  return 1
}

_config_ensure_mutable_dirs() { # <out_cdir_var> <out_pdir_var>
  local -n _cdir=$1 _pdir=$2
  if _config_use_data_dir; then
    _cdir="$AN_DATA_DIR/config"
    _pdir="$AN_DATA_DIR/profiles"
    local old_umask f base
    old_umask=$(umask)
    umask 077
    mkdir -p -- "$_cdir" "$_pdir" || { umask "$old_umask"; return 1; }
    if [[ -L $_cdir || -L $_pdir || ! -d $_cdir || ! -d $_pdir ]]; then
      umask "$old_umask"
      return 1
    fi
    chmod 700 "$_cdir" "$_pdir" 2>/dev/null || { umask "$old_umask"; return 1; }
    shopt -s nullglob
    for f in "$AN_ROOT"/config/*.conf; do
      [[ -f $f && ! -L $f ]] || continue
      base=${f##*/}
      if [[ ! -e "$_cdir/$base" ]]; then
        cp -p -- "$f" "$_cdir/$base" || { shopt -u nullglob; umask "$old_umask"; return 1; }
        chmod 600 "$_cdir/$base" 2>/dev/null || true
      fi
    done
    for f in "$AN_ROOT"/profiles/*.profile; do
      [[ -f $f && ! -L $f ]] || continue
      base=${f##*/}
      if [[ ! -e "$_pdir/$base" ]]; then
        cp -p -- "$f" "$_pdir/$base" || { shopt -u nullglob; umask "$old_umask"; return 1; }
        chmod 600 "$_pdir/$base" 2>/dev/null || true
      fi
    done
    shopt -u nullglob
    umask "$old_umask"
  else
    _cdir="$AN_ROOT/config"
    _pdir="$AN_ROOT/profiles"
    [[ -d $_cdir && ! -L $_cdir && -d $_pdir && ! -L $_pdir ]] || return 1
  fi
  return 0
}

# config_init <conf-file-or-empty> <profile-or-empty>
config_init() {
  local conf=${1:-} profile=${2:-}
  config_defaults
  local cdir="$AN_ROOT/config" pdir="$AN_ROOT/profiles"
  if _config_use_data_dir && [[ -d "$AN_DATA_DIR/config" && -d "$AN_DATA_DIR/profiles" ]]; then
    cdir="$AN_DATA_DIR/config"
    pdir="$AN_DATA_DIR/profiles"
  fi
  local default_conf="$cdir/authforge.conf"
  if [[ ! -f $default_conf ]]; then default_conf="$AN_ROOT/config/authforge.conf"; fi
  if [[ -z $conf && -f $default_conf ]]; then conf=$default_conf; fi
  if [[ -n $conf ]]; then
    validate_regular_file "$conf" || an_die "$EX_CONFIG" "config file not readable: $conf"
    _config_parse_file "$conf" apply || an_die "$EX_CONFIG" "invalid configuration: $conf"
  fi
  if [[ -n $profile ]]; then
    validate_ident "$profile" || an_die "$EX_CONFIG" "invalid profile name"
    local pf="$pdir/$profile.profile"
    if [[ ! -f $pf ]]; then pf="$AN_ROOT/profiles/$profile.profile"; fi
    validate_regular_file "$pf" || an_die "$EX_CONFIG" "unknown profile: $profile"
    _config_parse_file "$pf" apply || an_die "$EX_CONFIG" "invalid profile: $profile"
    AN_PROFILE=$profile
  fi
  config_validate_effective || an_die "$EX_CONFIG" "inconsistent configuration"
  return 0
}

config_get() { printf '%s' "${AN_CFG[$1]:-}"; }

config_show() {
  local k
  printf '# effective configuration (profile: %s)\n' "${AN_PROFILE:-none}"
  for k in $(printf '%s\n' "${!AN_CFG[@]}" | sort); do printf '%s=%s\n' "$k" "${AN_CFG[$k]}"; done
  return 0
}

# Backup / restore of config + profiles ------------------------------------
config_backup() {
  local ts rnd dest old_umask cdir pdir f
  _config_ensure_mutable_dirs cdir pdir || an_die "$EX_GENERAL" "cannot initialize configuration directories"
  printf -v ts '%(%Y%m%d-%H%M%S)T' -1
  old_umask=$(umask)
  umask 077 # parents and backup dir are private (mkdir -m only covers the leaf)
  mkdir -p -- "$AN_DATA_DIR/backups" || { umask "$old_umask"; an_die "$EX_GENERAL" "cannot create backups directory"; }
  [[ ! -L "$AN_DATA_DIR/backups" && -d "$AN_DATA_DIR/backups" ]] || { umask "$old_umask"; an_die "$EX_VALIDATION" "unsafe backups directory"; }
  chmod 700 "$AN_DATA_DIR/backups" 2>/dev/null || true
  # Unique per call: a restore takes a safety backup first and must never
  # overwrite the backup it is restoring from (regression-tested).
  while :; do
    rnd=$(od -An -N2 -tx1 /dev/urandom | tr -d ' \n')
    dest="$AN_DATA_DIR/backups/$ts-$rnd"
    [[ -e $dest || -L $dest ]] || break
  done
  mkdir -p -- "$dest" || { umask "$old_umask"; an_die "$EX_GENERAL" "cannot create backup destination"; }
  chmod 700 "$dest" 2>/dev/null || true
  shopt -s nullglob
  for f in "$cdir"/*.conf "$pdir"/*.profile; do
    if [[ -L $f || ! -f $f ]]; then
      shopt -u nullglob
      umask "$old_umask"
      rm -rf -- "$dest"
      an_die "$EX_VALIDATION" "refusing to back up symlink or non-regular config file: $f"
    fi
    cp -p -- "$f" "$dest"/ || { shopt -u nullglob; umask "$old_umask"; rm -rf -- "$dest"; an_die "$EX_GENERAL" "backup copy failed"; }
  done
  shopt -u nullglob
  umask "$old_umask"
  printf '%s\n' "$dest"
}

config_restore() { # <backup-dir>
  local src=$1 f
  [[ -n $src && ! -L $src ]] || {
    log_error "restore source is missing or a symlink: ${src:-}"
    return "$EX_VALIDATION"
  }
  validate_path_within "$src" "$AN_DATA_DIR/backups" || {
    log_error "restore source must be inside $AN_DATA_DIR/backups"
    return "$EX_VALIDATION"
  }
  [[ -d $src && ! -L $src ]] || { log_error "no such backup: $src"; return "$EX_VALIDATION"; }

  local cdir pdir
  if ! _config_ensure_mutable_dirs cdir pdir; then
    log_error "cannot prepare writable configuration directories for restore"
    return "$EX_GENERAL"
  fi
  if [[ ! -w $cdir || ! -w $pdir ]]; then
    log_error "configuration directories are not writable: $cdir, $pdir"
    return "$EX_GENERAL"
  fi

  shopt -s nullglob
  local files=("$src"/*.conf "$src"/*.profile)
  shopt -u nullglob
  ((${#files[@]} > 0)) || { log_error "backup contains no config files"; return "$EX_VALIDATION"; }

  local base dst_dir dst_file
  for f in "${files[@]}"; do
    if [[ -L $f || ! -f $f ]]; then
      log_error "backup file is a symlink or not a regular file: ${f##*/}"
      return "$EX_VALIDATION"
    fi
    base=${f##*/}
    case $base in
      *.conf) dst_dir=$cdir ;;
      *.profile) dst_dir=$pdir ;;
      *) return "$EX_VALIDATION" ;;
    esac
    dst_file="$dst_dir/$base"
    if [[ -L $dst_file ]] || { [[ -e $dst_file ]] && [[ ! -f $dst_file ]]; }; then
      log_error "refusing to overwrite symlink or non-regular target: $dst_file"
      return "$EX_VALIDATION"
    fi
    _config_parse_file "$f" check || { log_error "backup file invalid: $base"; return "$EX_CONFIG"; }
  done

  # Stage all restored files in same-directory temporary files before replacing any target
  local -a staged_tmps=() staged_dsts=()
  local tmp_f
  for f in "${files[@]}"; do
    base=${f##*/}
    case $base in
      *.conf) dst_dir=$cdir ;;
      *.profile) dst_dir=$pdir ;;
    esac
    dst_file="$dst_dir/$base"
    if ! tmp_f=$(mktemp "$dst_dir/.restore.tmp.XXXXXX" 2>/dev/null); then
      rm -f -- "${staged_tmps[@]}" 2>/dev/null || true
      log_error "cannot create temporary restore file in $dst_dir"
      return "$EX_GENERAL"
    fi
    if ! chmod 600 "$tmp_f" 2>/dev/null || ! cat -- "$f" >"$tmp_f" 2>/dev/null; then
      rm -f -- "$tmp_f" "${staged_tmps[@]}" 2>/dev/null || true
      log_error "failed to stage restored configuration in $dst_dir"
      return "$EX_GENERAL"
    fi
    staged_tmps+=("$tmp_f")
    staged_dsts+=("$dst_file")
  done

  if ! config_backup >/dev/null; then
    rm -f -- "${staged_tmps[@]}" 2>/dev/null || true
    log_error "safety backup failed prior to restore"
    return "$EX_GENERAL"
  fi

  local i
  for ((i = 0; i < ${#staged_tmps[@]}; i++)); do
    if [[ -L ${staged_dsts[$i]} ]] || ! mv -f -- "${staged_tmps[$i]}" "${staged_dsts[$i]}" 2>/dev/null; then
      rm -f -- "${staged_tmps[@]}" 2>/dev/null || true
      log_error "atomic rename failed during configuration restore: ${staged_dsts[$i]}"
      return "$EX_GENERAL"
    fi
  done
  return 0
}

config_validate_all() { # validates every active/shipped config & profile file
  local f bad=0 cdir="$AN_ROOT/config" pdir="$AN_ROOT/profiles" root_strip="$AN_ROOT"
  if _config_use_data_dir && [[ -d "$AN_DATA_DIR/config" && -d "$AN_DATA_DIR/profiles" ]]; then
    cdir="$AN_DATA_DIR/config"
    pdir="$AN_DATA_DIR/profiles"
    root_strip="$AN_DATA_DIR"
  fi
  shopt -s nullglob
  for f in "$cdir"/*.conf "$pdir"/*.profile; do
    if [[ -L $f || ! -f $f ]] || ! _config_parse_file "$f" check; then
      printf '%s %s\n' "$(ui_status_badge FAIL)" "${f#"$root_strip"/}"
      bad=1
    else
      printf '%s %s\n' "$(ui_status_badge PASS)" "${f#"$root_strip"/}"
    fi
  done
  shopt -u nullglob
  return "$bad"
}
