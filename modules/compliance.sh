#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034  # globals are shared across sourced files by design
# AUTHFORGE module: Compliance Assessment (menu 11) -- Milestone 5, Phase 1.
# Implemented: evaluate (alias: status), catalog (alias: list), gaps, export.

mod_compliance_info() { printf '11|Compliance Assessment|OWASP ASVS 5.0.0, NIST SP 800-63B-4 & CIS v8.1 control mapping|ready'; }

_comp_usage() {
  cat <<'USAGE'
Usage: authforge [global opts] compliance <subcommand> [options]

  evaluate [--session SID] [--framework ASVS|NIST|CIS|ALL]
                        Evaluate session evidence against the 40-control compliance catalog
  status [opts]         Alias for evaluate
  gaps [--session SID] [--framework ASVS|NIST|CIS|ALL]
                        Show only FAIL and NOT TESTED controls requiring remediation or coverage
  catalog [--framework ASVS|NIST|CIS|ALL]
                        List the pinned 40-control compliance catalog and scope bounds
  export [--session SID] [--framework ASVS|NIST|CIS|ALL] [--format json|csv|md|txt] [-o FILE]
                        Export compliance assessment report (refuses to overwrite existing FILE)
USAGE
}

_comp_resolve_session() { # <sid_arg> -> echoes validated sid
  local sid=${1:-}
  if [[ -z $sid ]]; then sid=$(session_latest); fi
  [[ -n $sid ]] || an_die "$EX_VALIDATION" "no sessions found"
  [[ $sid =~ ^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$ ]] || an_die "$EX_VALIDATION" "invalid session id: $sid"
  [[ -f "$AN_DATA_DIR/reports/$sid/findings.dat" ]] || an_die "$EX_VALIDATION" "unknown session: $sid"
  printf '%s' "$sid"
}

_comp_cmd_catalog() {
  local fw="ALL"
  while (($#)); do
    case $1 in
      --framework) fw=${2:-}; shift ;;
      *) an_die "$EX_USAGE" "compliance catalog: unknown option $1" ;;
    esac
    shift
  done
  case ${fw^^} in
    ALL | ASVS | NIST | CIS) ;;
    *) an_die "$EX_USAGE" "invalid --framework '$fw' (use ASVS|NIST|CIS|ALL)" ;;
  esac
  local cfile rc=0
  cfile=$(tmp_file)
  compliance_load_catalog "$cfile" "$fw" || rc=$?
  if ((rc != 0)); then
    rm -f -- "$cfile"
    an_die "$rc" "failed to load compliance catalog"
  fi
  local cnt
  cnt=$(wc -l <"$cfile" | tr -d ' ')
  printf 'AUTHFORGE Pinned Compliance Catalog (%s controls, filter=%s)\n' "$cnt" "${fw^^}"
  ui_rule
  local f ver cid sec lvl title sum req gates freg maxst lim xwalk
  while IFS=$'\x1f' read -r f ver cid sec lvl title sum req gates freg maxst lim xwalk; do
    [[ -n $cid ]] || continue
    printf '  %-10s %-14s [%-14s] %s (max=%s)\n' "$f $ver" "$cid" "$lvl" "$title" "$maxst"
    printf '      checks: %s | crosswalk: %s\n' "$req" "${xwalk:-n/a}"
  done <"$cfile"
  ui_rule
  rm -f -- "$cfile"
  return 0
}

_comp_cmd_evaluate() {
  local gaps_only=$1
  shift
  local sid="" fw="ALL"
  while (($#)); do
    case $1 in
      --session) sid=${2:-}; shift ;;
      --framework) fw=${2:-}; shift ;;
      *) an_die "$EX_USAGE" "compliance: unknown option $1" ;;
    esac
    shift
  done
  case ${fw^^} in
    ALL | ASVS | NIST | CIS) ;;
    *) an_die "$EX_USAGE" "invalid --framework '$fw' (use ASVS|NIST|CIS|ALL)" ;;
  esac
  sid=$(_comp_resolve_session "$sid")
  compliance_report_terminal "$sid" "$fw" "$gaps_only"
}

_comp_cmd_export() {
  local sid="" fw="ALL" fmt="json" out=""
  while (($#)); do
    case $1 in
      --session) sid=${2:-}; shift ;;
      --framework) fw=${2:-}; shift ;;
      --format) fmt=${2:-}; shift ;;
      -o | --output) out=${2:-}; shift ;;
      *) an_die "$EX_USAGE" "compliance export: unknown option $1" ;;
    esac
    shift
  done
  case ${fw^^} in
    ALL | ASVS | NIST | CIS) ;;
    *) an_die "$EX_USAGE" "invalid --framework '$fw' (use ASVS|NIST|CIS|ALL)" ;;
  esac
  case $fmt in
    json | csv | md | markdown | txt) ;;
    *) an_die "$EX_USAGE" "unsupported export format '$fmt' (use json|csv|md|txt)" ;;
  esac
  sid=$(_comp_resolve_session "$sid")

  if [[ -n $out ]]; then
    [[ ! -e $out && ! -L $out ]] || an_die "$EX_VALIDATION" "refusing to overwrite existing file: $out"
    (
      umask 077
      case $fmt in
        json) compliance_export_json "$sid" "$fw" >"$out" ;;
        csv) compliance_export_csv "$sid" "$fw" >"$out" ;;
        md | markdown) compliance_export_markdown "$sid" "$fw" >"$out" ;;
        txt) compliance_export_txt "$sid" "$fw" >"$out" ;;
      esac
    )
    evidence_manifest_update "$sid" || an_die "$EX_GENERAL" "failed to update evidence manifest"
    printf 'Wrote %s\n' "$out"
  else
    case $fmt in
      json) compliance_export_json "$sid" "$fw" ;;
      csv) compliance_export_csv "$sid" "$fw" ;;
      md | markdown) compliance_export_markdown "$sid" "$fw" ;;
      txt) compliance_export_txt "$sid" "$fw" ;;
    esac
    evidence_manifest_update "$sid" || an_die "$EX_GENERAL" "failed to update evidence manifest"
  fi
  return 0
}

mod_compliance_main() {
  local sub=${1:-evaluate}
  if (($# > 0)); then shift; fi
  AN_MODULE=compliance
  case $sub in
    evaluate | status) _comp_cmd_evaluate 0 "$@" ;;
    gaps) _comp_cmd_evaluate 1 "$@" ;;
    catalog | list) _comp_cmd_catalog "$@" ;;
    export) _comp_cmd_export "$@" ;;
    help | -h | --help) _comp_usage ;;
    *) an_die "$EX_USAGE" "compliance: unknown subcommand '$sub'" ;;
  esac
}

mod_compliance_menu() {
  AN_MODULE=compliance
  local c sid fw
  while :; do
    ui_banner
    printf '\n  COMPLIANCE ASSESSMENT ENGINE (OWASP ASVS 5.0.0 / NIST SP 800-63B-4 / CIS v8.1)\n'
    ui_rule
    printf '  [1] Evaluate session compliance posture (all 40 controls)\n'
    printf '  [2] Show compliance gaps only (FAIL / NOT TESTED)\n'
    printf '  [3] Inspect pinned 40-control compliance catalog\n'
    printf '  [4] Export compliance report (JSON/CSV/MD/TXT)\n'
    printf '  [b] Back\n\n'
    read -r -p "Select: " c || return 0
    case $c in
      1)
        read -r -p "Session id (blank = latest): " sid || return 0
        read -r -p "Framework [ALL/ASVS/NIST/CIS] (blank = ALL): " fw || return 0
        (_comp_cmd_evaluate 0 ${sid:+--session "$sid"} --framework "${fw:-ALL}") || true
        ui_pause ;;
      2)
        read -r -p "Session id (blank = latest): " sid || return 0
        (_comp_cmd_evaluate 1 ${sid:+--session "$sid"}) || true
        ui_pause ;;
      3)
        (_comp_cmd_catalog) || true
        ui_pause ;;
      4)
        read -r -p "Session id (blank = latest): " sid || return 0
        sid=$(_comp_resolve_session "$sid") || { ui_pause; continue; }
        (umask 077; compliance_export_json "$sid" ALL >"$AN_DATA_DIR/reports/$sid/compliance.json")
        evidence_manifest_update "$sid" || true
        printf 'Wrote %s\n' "$AN_DATA_DIR/reports/$sid/compliance.json"
        ui_pause ;;
      b | B | q | Q) return 0 ;;
      *) printf 'Invalid selection.\n'; ui_pause ;;
    esac
  done
}
