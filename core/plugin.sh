#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034  # globals are shared across sourced files by design
# AUTHFORGE core: module/plugin loader.
#
# Contract for modules/<id>.sh and plugins/<id>.sh (id = ^[a-z][a-z0-9_]{1,31}$):
#   mod_<id>_info   -> prints "menu_no|title|summary|status"   (menu_no 01-15 or -)
#   mod_<id>_main   -> CLI entry:  mod_<id>_main <args...>
#   mod_<id>_menu   -> optional interactive submenu
# Files are sourced only if: regular, not a symlink, owned by the current user
# or root, and not group/world-writable. plugins/ is opt-in (plugins_enabled=1).
[[ -n "${_AN_PLUGIN:-}" ]] && return 0
_AN_PLUGIN=1

declare -gA AN_MOD_TITLE=() AN_MOD_SUMMARY=() AN_MOD_STATUS=() AN_MOD_MENU=() AN_MOD_KIND=()

_plugin_file_safe() {
  local f=$1 mode owner
  [[ -f $f && ! -L $f ]] || return 1
  read -r mode owner < <(stat -c '%a %u' -- "$f") || return 1
  [[ $owner == "$(id -u)" || $owner == 0 ]] || return 2
  # last two octal digits are group/other; reject any write bit (2,3,6,7)
  local go=${mode: -2}
  [[ $go =~ [2367] ]] && return 3
  return 0
}

_plugin_register() { # <file> <kind>
  local f=$1 kind=$2 id
  id=${f##*/}
  id=${id%.sh}
  [[ $id =~ ^[a-z][a-z0-9_]{1,31}$ ]] || { log_warn "skipping ${f##*/}: invalid module id"; return 0; }
  local rc=0
  _plugin_file_safe "$f" || rc=$?
  if ((rc != 0)); then
    log_warn "refusing to load ${f##*/}: unsafe file (code $rc: symlink/owner/permissions)"
    return 0
  fi
  # shellcheck source=/dev/null
  source "$f"
  local fn
  for fn in "mod_${id}_info" "mod_${id}_main"; do
    if ! declare -F "$fn" >/dev/null; then
      log_warn "module $id rejected: missing function $fn"
      return 0
    fi
  done
  local info menu title summary status
  info=$("mod_${id}_info")
  IFS='|' read -r menu title summary status <<<"$info"
  AN_MOD_TITLE[$id]=$title
  AN_MOD_SUMMARY[$id]=$summary
  AN_MOD_STATUS[$id]=$status
  AN_MOD_KIND[$id]=$kind
  if [[ $menu =~ ^[0-9]{2}$ ]]; then AN_MOD_MENU[$menu]=$id; fi
  log_debug "registered $kind $id"
  return 0
}

plugin_load_all() {
  local f
  shopt -s nullglob
  for f in "$AN_ROOT"/modules/*.sh; do _plugin_register "$f" module; done
  if [[ ${AN_CFG[plugins_enabled]:-0} == 1 ]]; then
    for f in "$AN_ROOT"/plugins/*.sh; do _plugin_register "$f" plugin; done
  fi
  shopt -u nullglob
  return 0
}

plugin_list() {
  local id
  for id in $(printf '%s\n' "${!AN_MOD_TITLE[@]}" | sort); do
    printf '%-14s %-8s %-9s %s\n' "$id" "${AN_MOD_KIND[$id]}" "${AN_MOD_STATUS[$id]}" "${AN_MOD_TITLE[$id]}"
  done
  return 0
}
