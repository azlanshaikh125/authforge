#!/usr/bin/env -S env -u BASH_ENV -u ENV bash
# shellcheck shell=bash
# AUTHFORGE safe environment-sanitizing launcher (M4-P3).
#
# USAGE:
#   ./scripts/authforge-safe.sh [authforge options and arguments...]
#   env -u BASH_ENV -u ENV -u LD_PRELOAD -u LD_LIBRARY_PATH ./scripts/authforge-safe.sh [args...]
#
# IMPORTANT SECURITY NOTES & LIMITATIONS:
# 1. Direct execution (`./scripts/authforge-safe.sh`) uses `/usr/bin/env -S env -u BASH_ENV -u ENV bash`
#    so `BASH_ENV` and `ENV` are removed before the launcher's own Bash interpreter starts.
# 2. Running `bash scripts/authforge-safe.sh` does NOT protect against `BASH_ENV` being processed
#    before the launcher starts, because the caller's `bash` binary evaluates `BASH_ENV` during its
#    own startup before reading `scripts/authforge-safe.sh` (bypassing the `#!` shebang). If invoking
#    via `bash`, always run: `env -u BASH_ENV -u ENV bash scripts/authforge-safe.sh [args...]`.
# 3. Environment variables intentionally removed before executing `authforge.sh`:
#    - Shell startup & execution hooks: BASH_ENV, ENV, PROMPT_COMMAND, PS4, SHELLOPTS, BASHOPTS, GLOBIGNORE
#    - Path & lookup overrides: CDPATH, FIGNORE, EXECIGNORE, HOSTFILE
#    - Dynamic linker variables: LD_PRELOAD, LD_LIBRARY_PATH, LD_AUDIT, LD_DEBUG, LD_PROFILE,
#      DYLD_INSERT_LIBRARIES, DYLD_LIBRARY_PATH
#    - Proxy & network/crypto overrides: HTTP_PROXY, HTTPS_PROXY, ALL_PROXY, FTP_PROXY, NO_PROXY,
#      http_proxy, https_proxy, all_proxy, ftp_proxy, no_proxy, CURL_HOME, OPENSSL_CONF,
#      OPENSSL_ENGINES, OPENSSL_MODULES
#    - Exported shell functions: any `BASH_FUNC_*` environment entries
# 4. Remaining limitation (`LD_PRELOAD` / `LD_LIBRARY_PATH`):
#    If `LD_PRELOAD`, `LD_LIBRARY_PATH`, or `LD_AUDIT` is set in the caller's environment before
#    `./scripts/authforge-safe.sh` is invoked, the OS dynamic linker (`ld-linux.so`) loads it into
#    the initial `env`/`bash` launcher process at `execve()` time before script commands execute.
#    Unsetting `LD_PRELOAD` here prevents child processes (`authforge.sh`, `curl`, `openssl`, `getent`,
#    `timeout`) from inheriting it (unless a preloaded library already hooked `execve`/`unsetenv`).
#    To prevent `LD_PRELOAD` from affecting the launcher process itself, unset it in the parent:
#    `env -u LD_PRELOAD -u LD_LIBRARY_PATH -u BASH_ENV -u ENV ./scripts/authforge-safe.sh`.

unset BASH_ENV ENV PROMPT_COMMAND PS4 GLOBIGNORE \
      CDPATH FIGNORE EXECIGNORE HOSTFILE \
      LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT LD_DEBUG LD_PROFILE \
      DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH \
      HTTP_PROXY HTTPS_PROXY ALL_PROXY FTP_PROXY NO_PROXY \
      http_proxy https_proxy all_proxy ftp_proxy no_proxy \
      CURL_HOME OPENSSL_CONF OPENSSL_ENGINES OPENSSL_MODULES 2>/dev/null || true

set -Eeuo pipefail
IFS=$' \t\n'

if [[ -z "${PATH:-}" ]]; then
  export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
fi
export NO_PROXY="*"
export no_proxy="*"

_SAFE_SELF=$(readlink -f -- "${BASH_SOURCE[0]}")
_SAFE_DIR=${_SAFE_SELF%/*}
_SAFE_ROOT=$(readlink -f -- "${_SAFE_DIR}/..")
_SAFE_TARGET="${_SAFE_ROOT}/authforge.sh"

_safe_verify_node() { # <path> <expected_type:regular file|directory>
  local p=$1 exp=$2 uid meta ftype fuid fmode
  [[ -n $p && ! -L $p ]] || return 1
  uid=$(id -u)
  meta=$(LC_ALL=C stat -c '%F|%u|%a' -- "$p" 2>/dev/null) || return 1
  IFS='|' read -r ftype fuid fmode <<<"$meta"
  [[ $ftype == "$exp" ]] || return 1
  [[ $fuid == "$uid" || $fuid == "0" ]] || return 1
  (((8#$fmode & 8#022) == 0)) || return 1
  return 0
}

if [[ ! -f "$_SAFE_TARGET" || -L "$_SAFE_TARGET" || ! -r "$_SAFE_TARGET" ]] ||
  ! _safe_verify_node "$_SAFE_ROOT" "directory" ||
  ! _safe_verify_node "$_SAFE_DIR" "directory" ||
  ! _safe_verify_node "$_SAFE_SELF" "regular file" ||
  ! _safe_verify_node "$_SAFE_TARGET" "regular file"; then
  printf 'authforge-safe: missing or unsafe target script or code root: %s\n' "$_SAFE_TARGET" >&2
  exit 4
fi
unset -f _safe_verify_node

# Collect any exported BASH_FUNC_* environment variable names so env -u strips them prior to exec.
declare -a _UNSET_ARGS=(
  -u BASH_ENV -u ENV -u PROMPT_COMMAND -u PS4 -u SHELLOPTS -u BASHOPTS -u GLOBIGNORE
  -u CDPATH -u FIGNORE -u EXECIGNORE -u HOSTFILE
  -u LD_PRELOAD -u LD_LIBRARY_PATH -u LD_AUDIT -u LD_DEBUG -u LD_PROFILE
  -u DYLD_INSERT_LIBRARIES -u DYLD_LIBRARY_PATH
  -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u FTP_PROXY
  -u http_proxy -u https_proxy -u all_proxy -u ftp_proxy
  -u CURL_HOME -u OPENSSL_CONF -u OPENSSL_ENGINES -u OPENSSL_MODULES
)

while IFS='=' read -r _k _; do
  if [[ $_k == BASH_FUNC_* ]]; then
    _UNSET_ARGS+=(-u "$_k")
  fi
done < <(env)

exec /usr/bin/env "${_UNSET_ARGS[@]}" NO_PROXY="*" no_proxy="*" /bin/bash --noprofile --norc "$_SAFE_TARGET" "$@"
