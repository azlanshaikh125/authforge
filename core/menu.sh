#!/usr/bin/env bash
# shellcheck shell=bash
# AUTHFORGE core: multi-level TUI main menu. Honest status per entry:
# nothing is shown as "ready" unless it is implemented and tested.
[[ -n "${_AN_MENU:-}" ]] && return 0
_AN_MENU=1

readonly -a AN_MENU_ITEMS=(
  "01|Authentication Intelligence|M4"
  "02|Password Security Engine|M0"
  "03|Hash Intelligence Engine|M1"
  "04|Wordlist Analytics Engine|M1"
  "05|MFA Security Assessment|M3"
  "06|Authentication Protocol Audit|M4"
  "07|Session Security Analysis|M3"
  "08|Password Reset Security Audit|M3"
  "09|Web Authentication Assessment|M4"
  "10|Risk Intelligence Engine|M2"
  "11|Compliance Assessment|M5"
  "12|Evidence Management|M5"
  "13|Reporting & Analytics|M2"
  "14|System Diagnostics|M0"
  "15|Configuration Management|M0"
)

_menu_core_status() { # core-implemented entries
  case $1 in
    13 | 14 | 15) printf 'ready' ;;
    *) printf '' ;;
  esac
}

menu_render() {
  local item no title ms st badge id
  if [[ -t 1 ]]; then printf '\e[H\e[2J'; fi
  ui_banner
  printf '\n  session %s   profile %s\n' "$AN_SESSION_ID" "${AN_PROFILE:-default}"
  ui_rule
  for item in "${AN_MENU_ITEMS[@]}"; do
    IFS='|' read -r no title ms <<<"$item"
    id=${AN_MOD_MENU[$no]:-}
    st=""
    if [[ -n $id ]]; then st=${AN_MOD_STATUS[$id]}; else st=$(_menu_core_status "$no"); fi
    case $st in
      ready) badge="${C_GREEN}[ready]${C_RESET}" ;;
      partial) badge="${C_YELLOW}[partial]${C_RESET}" ;;
      *) badge="${C_DIM}[planned ${ms}]${C_RESET}" ;;
    esac
    printf '  [%s] %-34s %s\n' "$no" "$title" "$badge"
  done
  ui_rule
  printf '  [q] Quit\n\n'
  return 0
}

_menu_reporting() {
  local sid c
  while :; do
    ui_banner
    printf '\n  REPORTING & ANALYTICS\n'
    ui_rule
    printf '  Available sessions:\n'
    session_list | sed 's/^/    /'
    printf '\n  [1] Display terminal risk report\n'
    printf '  [2] Export JSON report\n'
    printf '  [3] Export CSV report\n'
    printf '  [4] Export Markdown report\n'
    printf '  [5] Export Plain-Text report\n'
    printf '  [6] Verify session report integrity (SHA-256)\n'
    printf '  [b] Back\n\n'
    read -r -p "Select: " c || return 0
    case $c in
      b | B | q | Q) return 0 ;;
      1 | 2 | 3 | 4 | 5 | 6) ;;
      *) printf 'Invalid selection.\n'; ui_pause; continue ;;
    esac
    read -r -p "Session id (blank = current): " sid || return 0
    if [[ -z $sid ]]; then sid=$AN_SESSION_ID; fi
    if [[ ! $sid =~ ^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$ ]]; then printf 'Invalid session id.\n'; ui_pause; continue; fi
    local ffile="$AN_DATA_DIR/reports/$sid/findings.dat"
    if [[ ! -f $ffile ]]; then printf 'Unknown session.\n'; ui_pause; continue; fi

    case $c in
      1) risk_report_terminal "$sid" "$ffile" ;;
      2)
        (umask 077; findings_export_json "$sid" "$ffile" >"$AN_DATA_DIR/reports/$sid/report.json")
        risk_manifest_update "$sid"
        printf 'Wrote %s\n' "$AN_DATA_DIR/reports/$sid/report.json" ;;
      3)
        (umask 077; findings_export_csv "$sid" "$ffile" >"$AN_DATA_DIR/reports/$sid/report.csv")
        risk_manifest_update "$sid"
        printf 'Wrote %s\n' "$AN_DATA_DIR/reports/$sid/report.csv" ;;
      4)
        (umask 077; findings_export_markdown "$sid" "$ffile" >"$AN_DATA_DIR/reports/$sid/report.md")
        risk_manifest_update "$sid"
        printf 'Wrote %s\n' "$AN_DATA_DIR/reports/$sid/report.md" ;;
      5)
        (umask 077; findings_export_txt "$sid" "$ffile" >"$AN_DATA_DIR/reports/$sid/report.txt")
        risk_manifest_update "$sid"
        printf 'Wrote %s\n' "$AN_DATA_DIR/reports/$sid/report.txt" ;;
      6) risk_manifest_verify "$sid" || true ;;
    esac
    ui_pause
  done
}

_menu_config() {
  local c d
  printf '  [1] Show effective configuration\n  [2] Validate shipped config/profiles\n  [3] Backup configuration\n  [b] Back\n'
  read -r -p "Select: " c || return 0
  case $c in
    1) config_show ;;
    2) config_validate_all || true ;;
    3) d=$(config_backup); printf 'Backup written to %s\n' "$d" ;;
  esac
  return 0
}

menu_main() {
  local c no id mrc
  while :; do
    menu_render
    read -r -p "Select [01-15, q]: " c || return 0
    case $c in
      q | Q | quit | exit) return 0 ;;
    esac
    if [[ ! $c =~ ^[0-9]{1,2}$ ]] || ((10#$c < 1 || 10#$c > ${#AN_MENU_ITEMS[@]})); then
      printf 'Invalid selection.\n'
      ui_pause
      continue
    fi
    printf -v no '%02d' "$((10#$c))"
    id=${AN_MOD_MENU[$no]:-}
    if [[ -n $id ]] && declare -F "mod_${id}_menu" >/dev/null; then
      mrc=0
      "mod_${id}_menu" || mrc=$?
      if ((mrc != 0)); then return "$mrc"; fi
    else
      case $no in
        13) _menu_reporting ;;
        14) deps_doctor || true; ui_pause ;;
        15) _menu_config; ui_pause ;;
        *) printf 'Not implemented yet (see docs/ROADMAP.md).\n'; ui_pause ;;
      esac
    fi
  done
}
