#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034  # globals are shared across sourced files by design
# AUTHFORGE core: terminal UI primitives (colors, banner, progress, menus).
# NOTE: every function returns 0 explicitly; callers run under `set -e`.
[[ -n "${_AN_UI:-}" ]] && return 0
_AN_UI=1

AN_COLS=80
AN_NO_COLOR=${AN_NO_COLOR:-0}
C_RESET='' C_BOLD='' C_DIM='' C_RED='' C_GREEN='' C_YELLOW='' C_BLUE='' C_MAGENTA='' C_CYAN=''

ui_cols_refresh() {
  local c=""
  if command -v tput >/dev/null 2>&1 && [[ -t 1 ]]; then c=$(tput cols 2>/dev/null || true); fi
  if [[ $c =~ ^[0-9]+$ ]]; then AN_COLS=$c; else AN_COLS=${COLUMNS:-80}; fi
  return 0
}

ui_init() {
  local use=0
  case ${AN_CFG[color]:-auto} in
    always) use=1 ;;
    never) use=0 ;;
    *) if [[ -t 2 && -z ${NO_COLOR:-} && ${TERM:-dumb} != dumb ]]; then use=1; fi ;;
  esac
  if ((AN_NO_COLOR)); then use=0; fi
  if ((use)); then
    C_RESET=$'\e[0m' C_BOLD=$'\e[1m' C_DIM=$'\e[2m' C_RED=$'\e[31m' C_GREEN=$'\e[32m'
    C_YELLOW=$'\e[33m' C_BLUE=$'\e[34m' C_MAGENTA=$'\e[35m' C_CYAN=$'\e[36m'
  fi
  ui_cols_refresh
  trap 'ui_cols_refresh' WINCH
  return 0
}

ui_is_utf8() {
  [[ ${LC_ALL:-${LC_CTYPE:-${LANG:-}}} == *[Uu][Tt][Ff]-8* || ${LC_ALL:-${LC_CTYPE:-${LANG:-}}} == *[Uu][Tt][Ff]8* ]]
}

ui_rule() {
  local w=$((AN_COLS > 78 ? 78 : AN_COLS))
  local ch='-'
  if ui_is_utf8; then ch='─'; fi
  printf '%s%s%s\n' "$C_DIM" "$(str_repeat "$ch" "$w")" "$C_RESET"
  return 0
}

ui_banner() {
  if ((AN_COLS >= 48)) && ui_is_utf8; then
    printf '%s' "$C_CYAN"
    cat <<'ART'
 ╔═╗╦ ╦╔╦╗╦ ╦╔╗╔╔═╗═╗ ╦╦ ╦╔═╗
 ╠═╣║ ║ ║ ╠═╣║║║║╣ ╔╩╦╝║ ║╚═╗
 ╩ ╩╚═╝ ╩ ╩ ╩╝╚╝╚═╝╩ ╚═╚═╝╚═╝
ART
    printf '%s' "$C_RESET"
    printf ' %s// %s%s  v%s\n' "$C_DIM" "$AN_TAGLINE" "$C_RESET" "$AN_VERSION"
  else
    printf '%s%s // %s%s v%s\n' "$C_BOLD" "$AN_NAME" "$AN_TAGLINE" "$C_RESET" "$AN_VERSION"
  fi
  return 0
}

ui_risk_badge() { # ui_risk_badge <SEVERITY>
  local c=$C_DIM
  case $1 in
    CRITICAL) c=$C_RED$C_BOLD ;;
    HIGH) c=$C_RED ;;
    MEDIUM) c=$C_YELLOW ;;
    LOW) c=$C_BLUE ;;
  esac
  printf '%s[%-8s]%s' "$c" "$1" "$C_RESET"
  return 0
}

ui_status_badge() { # PASS/FAIL/REVIEW/NOT TESTED/WARN
  local c=$C_DIM
  case $1 in
    PASS) c=$C_GREEN ;;
    FAIL) c=$C_RED ;;
    REVIEW | WARN) c=$C_YELLOW ;;
  esac
  printf '%s[%s]%s' "$c" "$1" "$C_RESET"
  return 0
}

# Progress bar on stderr; silent when not a TTY or in quiet mode.
ui_progress() { # ui_progress <current> <total> <label>
  local cur=$1 total=$2 label=${3:-}
  if ((total <= 0 || AN_QUIET)) || [[ ! -t 2 ]]; then return 0; fi
  local width=$((AN_COLS - 30))
  if ((width > 50)); then width=50; fi
  if ((width < 10)); then width=10; fi
  local filled=$((cur * width / total))
  printf '\r%s[%s%s]%s %3d%% %s\e[K' "$C_CYAN" \
    "$(str_repeat '#' "$filled")" "$(str_repeat '-' $((width - filled)))" "$C_RESET" \
    $((cur * 100 / total)) "$label" >&2
  if ((cur >= total)); then printf '\n' >&2; fi
  return 0
}

# Read a secret without echo. Uses the TTY when available, else stdin.
ui_read_secret() { # ui_read_secret <varname> <prompt>
  local -n _out=$1
  local prompt=$2
  if [[ -t 0 ]]; then
    IFS= read -rs -p "$prompt" _out || return 1
    printf '\n' >&2
  else
    IFS= read -r _out || return 1
  fi
  return 0
}

ui_pause() {
  if [[ -t 0 ]]; then
    read -r -p "Press Enter to continue..." _ || true
  fi
  return 0
}
