#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034  # globals are shared across sourced files by design
# AUTHFORGE module: Evidence Management (menu 12) -- Milestone 5, Phase 1.
# Implemented: list (alias: status), manifest, verify, bundle, verify-bundle, log.

mod_evidence_info() { printf '12|Evidence Management|SHA-256 evidence manifests, chain-of-custody logs & verifiable bundles|ready'; }

_ev_usage() {
  cat <<'USAGE'
Usage: authforge [global opts] evidence <subcommand> [options]

  list [--session SID]          Show session artifacts, check ledger, and manifest summary
  status [--session SID]        Alias for list
  manifest [--session SID]      Recompute and display SHA-256 manifest for a session
  verify [--session SID]        Verify SHA-256 integrity of all session artifacts
  log [--session SID]           Display structured chain-of-custody log (evidence.log)
  bundle [--session SID] -o FILE.tar.gz
                                Package verified session artifacts into a standalone tar.gz bundle
  verify-bundle FILE.tar.gz     Verify integrity of a standalone tar.gz evidence bundle
USAGE
}

_ev_resolve_session() {
  local sid=${1:-}
  if [[ -z $sid ]]; then sid=$(session_latest); fi
  [[ -n $sid ]] || an_die "$EX_VALIDATION" "no sessions found"
  [[ $sid =~ ^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$ ]] || an_die "$EX_VALIDATION" "invalid session id: $sid"
  [[ -f "$AN_DATA_DIR/reports/$sid/findings.dat" ]] || an_die "$EX_VALIDATION" "unknown session: $sid"
  printf '%s' "$sid"
}

_ev_parse_sid_opt() {
  local sid=""
  while (($#)); do
    case $1 in
      --session) sid=${2:-}; shift ;;
      *) an_die "$EX_USAGE" "evidence: unknown option $1" ;;
    esac
    shift
  done
  _ev_resolve_session "$sid"
}

_ev_cmd_list() {
  local sid
  sid=$(_ev_parse_sid_opt "$@")
  local rdir="$AN_DATA_DIR/reports/$sid"
  local edir="$AN_DATA_DIR/evidence/$sid"
  local fcnt=0 ccnt=0
  [[ -f "$rdir/findings.dat" ]] && fcnt=$(wc -l <"$rdir/findings.dat" | tr -d ' ')
  [[ -f "$rdir/checks.dat" ]] && ccnt=$(wc -l <"$rdir/checks.dat" | tr -d ' ')

  printf 'Evidence & Check Ledger Summary for session: %s\n' "$sid"
  ui_rule
  printf '  %-24s %s\n' "Report directory" "$rdir"
  printf '  %-24s %s\n' "Evidence directory" "$edir"
  printf '  %-24s %s\n' "Recorded findings" "$fcnt"
  printf '  %-24s %s\n' "Recorded check runs" "$ccnt"
  if [[ -s "$rdir/checks.dat" ]]; then
    printf '\n  Executed Checks Ledger (checks.dat):\n'
    local cid st rc ttype ts det
    while IFS=$'\x1f' read -r cid st rc ttype ts det; do
      [[ -n $cid ]] || continue
      printf '    %-26s %-10s rc=%-3s target=%-20s %s\n' "$cid" "[$st]" "$rc" "$ttype" "$det"
    done <"$rdir/checks.dat"
  fi
  ui_rule
  return 0
}

_ev_cmd_manifest() {
  local sid
  sid=$(_ev_parse_sid_opt "$@")
  evidence_manifest_update "$sid" || an_die "$EX_GENERAL" "failed to update evidence manifest for session: $sid"
  local mfile="$AN_DATA_DIR/evidence/$sid/manifest.sha256"
  printf 'SHA-256 Evidence Manifest (%s):\n' "$sid"
  ui_rule
  if [[ -s $mfile ]]; then
    sed 's/^/  /' "$mfile"
  else
    printf '  (empty manifest)\n'
  fi
  ui_rule
  return 0
}

_ev_cmd_verify() {
  local sid
  sid=$(_ev_parse_sid_opt "$@")
  local rc=0
  evidence_manifest_verify "$sid" || rc=$?
  return "$rc"
}

_ev_cmd_log() {
  local sid
  sid=$(_ev_parse_sid_opt "$@")
  local elog="$AN_DATA_DIR/evidence/$sid/evidence.log"
  printf 'Chain-of-Custody Log for session: %s\n' "$sid"
  ui_rule
  if [[ ! -s $elog ]]; then
    printf '  No chain-of-custody events recorded yet.\n'
  else
    local ts etype uid rel det
    while IFS=$'\x1f' read -r ts etype uid rel det; do
      [[ -n $ts ]] || continue
      printf '  %s  [%-14s] uid=%s  target=%s  %s\n' "$ts" "$etype" "$uid" "$rel" "$det"
    done <"$elog"
  fi
  ui_rule
  return 0
}

_ev_cmd_bundle() {
  local sid="" out=""
  while (($#)); do
    case $1 in
      --session) sid=${2:-}; shift ;;
      -o | --output) out=${2:-}; shift ;;
      *) an_die "$EX_USAGE" "evidence bundle: unknown option $1" ;;
    esac
    shift
  done
  sid=$(_ev_resolve_session "$sid")
  evidence_export_bundle "$sid" "$out"
}

mod_evidence_main() {
  local sub=${1:-list}
  if (($# > 0)); then shift; fi
  AN_MODULE=evidence
  case $sub in
    list | status) _ev_cmd_list "$@" ;;
    manifest) _ev_cmd_manifest "$@" ;;
    verify) _ev_cmd_verify "$@" ;;
    log) _ev_cmd_log "$@" ;;
    bundle) _ev_cmd_bundle "$@" ;;
    verify-bundle) evidence_verify_bundle "$@" ;;
    help | -h | --help) _ev_usage ;;
    *) an_die "$EX_USAGE" "evidence: unknown subcommand '$sub'" ;;
  esac
}

mod_evidence_menu() {
  AN_MODULE=evidence
  local c sid out
  while :; do
    ui_banner
    printf '\n  EVIDENCE MANAGEMENT & CHAIN OF CUSTODY\n'
    ui_rule
    printf '  [1] List session evidence & check execution ledger\n'
    printf '  [2] Recompute & display SHA-256 manifest\n'
    printf '  [3] Verify session SHA-256 integrity\n'
    printf '  [4] Export verifiable evidence bundle (.tar.gz)\n'
    printf '  [5] Verify an external evidence bundle (.tar.gz)\n'
    printf '  [b] Back\n\n'
    read -r -p "Select: " c || return 0
    case $c in
      1)
        read -r -p "Session id (blank = latest): " sid || return 0
        (_ev_cmd_list ${sid:+--session "$sid"}) || true
        ui_pause ;;
      2)
        read -r -p "Session id (blank = latest): " sid || return 0
        (_ev_cmd_manifest ${sid:+--session "$sid"}) || true
        ui_pause ;;
      3)
        read -r -p "Session id (blank = latest): " sid || return 0
        (_ev_cmd_verify ${sid:+--session "$sid"}) || true
        ui_pause ;;
      4)
        read -r -p "Session id (blank = latest): " sid || return 0
        read -r -p "Output bundle path (.tar.gz): " out || return 0
        (_ev_cmd_bundle ${sid:+--session "$sid"} -o "$out") || true
        ui_pause ;;
      5)
        read -r -p "Bundle file path (.tar.gz): " out || return 0
        (evidence_verify_bundle "$out") || true
        ui_pause ;;
      b | B | q | Q) return 0 ;;
      *) printf 'Invalid selection.\n'; ui_pause ;;
    esac
  done
}
