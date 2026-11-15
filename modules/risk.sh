#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034  # globals are shared across sourced files by design
# AUTHFORGE module: Risk Intelligence Engine (menu 10) -- Milestone 2.
# Implemented: evaluate (analyze/score), prioritize, correlate, report,
# suppress, unsuppress, suppressions, manifest, verify.

mod_risk_info() { printf '10|Risk Intelligence Engine|CVSS-inspired risk scoring, correlation, deduplication and multi-format reporting|ready'; }

_risk_usage() {
  cat <<'USAGE'
Usage: authforge [global opts] risk <subcommand> [options]

  evaluate [--session SID]              Evaluate session findings, correlate, deduplicate, and print terminal report
  prioritize [--session SID]            Print prioritized remediation queue (P1..P5) ordered by risk score
  correlate [--session SID]             Identify compound risk chains and duplicate finding clusters
  report [--session SID] [--format terminal|json|csv|md|txt] [-o FILE]
                                        Generate or export assessment report in the specified format
  suppress FINDING_ID --reason TEXT [--status false_positive|risk_accepted] [--session SID]
                                        Suppress a finding with mandatory audited justification
  unsuppress FINDING_ID [--session SID] Remove a finding suppression
  suppressions [--session SID]          List active finding suppressions for a session
  manifest [--session SID]              Update and display the SHA-256 integrity manifest for a session
  verify [--session SID]                Verify session findings and exported reports against SHA-256 manifest
USAGE
}

_risk_parse_sid() { # <outvar> <args...>
  local -n _s_out=$1
  shift
  local s=""
  while (($#)); do
    case $1 in
      --session) s=${2:-}; shift ;;
      *) an_die "$EX_USAGE" "risk: unknown option $1" ;;
    esac
    shift
  done
  risk_resolve_session _s_out "$s"
  return 0
}

_risk_cmd_evaluate() {
  local sid=""
  _risk_parse_sid sid "$@"
  risk_report_terminal "$sid" "$AN_DATA_DIR/reports/$sid/findings.dat"
  return 0
}

_risk_cmd_prioritize() {
  local sid=""
  _risk_parse_sid sid "$@"
  local ffile="$AN_DATA_DIR/reports/$sid/findings.dat"
  local enriched
  enriched=$(tmp_file)
  risk_evaluate_file "$ffile" "$enriched"
  printf 'Prioritized remediation queue for session: %s  (posture: %d/100, rating: %s)\n' \
    "$sid" "$RISK_POSTURE_INDEX" "$RISK_OVERALL_RATING"
  ui_rule
  if [[ ! -s $enriched ]]; then
    printf '  No findings recorded.\n'
  else
    printf '  %-14s %-6s %-10s %-10s %-10s %-18s %s\n' \
      "PRIORITY" "SCORE" "SEVERITY" "LIKELIHOOD" "IMPACT" "ID" "TITLE / REMEDIATION"
    ui_rule
    local pri score id ts mod sev conf lik imp basis status occ title detail rem evid sreason
    while IFS=$'\x1f' read -r pri score id ts mod sev conf lik imp basis status occ title detail rem evid sreason; do
      if [[ $status != "active" ]]; then continue; fi
      printf '  %-14s %-6s %-10s %-10s %-10s %-18s %s (x%s)\n' \
        "$pri" "$score" "$sev" "$lik" "$imp" "$id" "$title" "$occ"
      printf '      -> %s\n' "$rem"
    done <"$enriched"
  fi
  ui_rule
  rm -f -- "$enriched"
  return 0
}

_risk_cmd_correlate() {
  local sid=""
  _risk_parse_sid sid "$@"
  local ffile="$AN_DATA_DIR/reports/$sid/findings.dat"
  local enriched
  enriched=$(tmp_file)
  risk_evaluate_file "$ffile" "$enriched"

  printf 'Correlation & deduplication analysis for session: %s\n' "$sid"
  ui_rule
  printf '  %-28s %d total -> %d unique (%d duplicate group(s), %d redundant)\n' \
    "Deduplication summary" "$RISK_TOTAL_RAW" "$RISK_UNIQUE_COUNT" "$RISK_DUP_GROUPS" "$RISK_DUP_EXTRA"
  printf '  %-28s %d compound risk chain(s)\n' "Correlated risk chains" "$RISK_CORR_COUNT"
  ui_rule

  if ((RISK_CORR_COUNT > 0)); then
    local c cid csev cconf ctitle cdetail crem
    for c in "${RISK_CORRELATIONS[@]}"; do
      IFS=$'\x1f' read -r cid csev cconf ctitle cdetail crem <<<"$c"
      printf '  %s %s %s (confidence=%s)\n' "$(ui_risk_badge "$csev")" "$cid" "$ctitle" "$cconf"
      printf '      %s\n' "$cdetail"
      printf '      remediation: %s\n' "$crem"
    done
    ui_rule
  fi

  if ((RISK_DUP_GROUPS > 0)); then
    printf 'Duplicate clusters collapsed:\n'
    local pri score id ts mod sev conf lik imp basis status occ title detail rem evid sreason
    while IFS=$'\x1f' read -r pri score id ts mod sev conf lik imp basis status occ title detail rem evid sreason; do
      if ((occ > 1)); then
        printf '  %s (%s) occurrences=%s title="%s"\n' "$id" "$mod" "$occ" "$title"
      fi
    done <"$enriched"
    ui_rule
  fi
  rm -f -- "$enriched"
  return 0
}

_risk_cmd_report() {
  local sid="" fmt="terminal" out=""
  while (($#)); do
    case $1 in
      --session) sid=${2:-}; shift ;;
      --format) fmt=${2:-}; shift ;;
      -o | --output) out=${2:-}; shift ;;
      *) an_die "$EX_USAGE" "risk report: unknown option $1" ;;
    esac
    shift
  done
  risk_resolve_session sid "$sid"
  local ffile="$AN_DATA_DIR/reports/$sid/findings.dat"

  case $fmt in
    terminal | json | csv | md | markdown | txt) ;;
    *) an_die "$EX_USAGE" "unsupported report format '$fmt' (use terminal|json|csv|md|txt)" ;;
  esac

  if [[ -n $out ]]; then
    [[ ! -e $out ]] || an_die "$EX_VALIDATION" "refusing to overwrite existing file: $out"
    (
      umask 077
      case $fmt in
        terminal | txt) findings_export_txt "$sid" "$ffile" >"$out" ;;
        json) findings_export_json "$sid" "$ffile" >"$out" ;;
        csv) findings_export_csv "$sid" "$ffile" >"$out" ;;
        md | markdown) findings_export_markdown "$sid" "$ffile" >"$out" ;;
      esac
    )
    risk_manifest_update "$sid"
    printf 'Wrote %s\n' "$out"
  else
    case $fmt in
      terminal) risk_report_terminal "$sid" "$ffile" ;;
      txt) findings_export_txt "$sid" "$ffile" ;;
      json) findings_export_json "$sid" "$ffile" ;;
      csv) findings_export_csv "$sid" "$ffile" ;;
      md | markdown) findings_export_markdown "$sid" "$ffile" ;;
    esac
    risk_manifest_update "$sid"
  fi
  return 0
}

_risk_cmd_suppress() {
  local fid=${1:-} sid="" st="false_positive" reason=""
  [[ -n $fid && $fid != -* ]] || an_die "$EX_USAGE" "suppress requires a FINDING_ID and --reason TEXT"
  shift
  while (($#)); do
    case $1 in
      --session) sid=${2:-}; shift ;;
      --status) st=${2:-}; shift ;;
      --reason) reason=${2:-}; shift ;;
      *) an_die "$EX_USAGE" "suppress: unknown option $1" ;;
    esac
    shift
  done
  [[ -n $reason ]] || an_die "$EX_USAGE" "suppress requires --reason TEXT"
  risk_resolve_session sid "$sid"
  risk_suppress_add "$sid" "$fid" "$st" "$reason"
  printf 'Recorded suppression for %s in session %s (%s)\n' "$fid" "$sid" "$st"
  return 0
}

_risk_cmd_unsuppress() {
  local fid=${1:-} sid=""
  [[ -n $fid && $fid != -* ]] || an_die "$EX_USAGE" "unsuppress requires a FINDING_ID"
  shift
  _risk_parse_sid sid "$@"
  risk_suppress_remove "$sid" "$fid"
  printf 'Removed suppression for %s in session %s\n' "$fid" "$sid"
  return 0
}

_risk_cmd_suppressions() {
  local sid=""
  _risk_parse_sid sid "$@"
  risk_suppress_list "$sid"
  return 0
}

_risk_cmd_manifest() {
  local sid=""
  _risk_parse_sid sid "$@"
  risk_manifest_update "$sid"
  local mfile="$AN_DATA_DIR/evidence/$sid/manifest.sha256"
  printf 'SHA-256 integrity manifest for session %s (%s):\n' "$sid" "$mfile"
  ui_rule
  cat "$mfile"
  ui_rule
  return 0
}

_risk_cmd_verify() {
  local sid=""
  _risk_parse_sid sid "$@"
  local rc=0
  risk_manifest_verify "$sid" || rc=$?
  return "$rc"
}

mod_risk_main() {
  local sub=${1:-}
  shift || true
  AN_MODULE=risk
  case $sub in
    evaluate | analyze | score) _risk_cmd_evaluate "$@" ;;
    prioritize) _risk_cmd_prioritize "$@" ;;
    correlate) _risk_cmd_correlate "$@" ;;
    report) _risk_cmd_report "$@" ;;
    suppress) _risk_cmd_suppress "$@" ;;
    unsuppress) _risk_cmd_unsuppress "$@" ;;
    suppressions) _risk_cmd_suppressions "$@" ;;
    manifest) _risk_cmd_manifest "$@" ;;
    verify) _risk_cmd_verify "$@" ;;
    "" | help | -h | --help) _risk_usage ;;
    *) an_die "$EX_USAGE" "risk: unknown subcommand '$sub'" ;;
  esac
}

mod_risk_menu() {
  AN_MODULE=risk
  local c sid fid reason fmt out
  while :; do
    ui_banner
    printf '\n  RISK INTELLIGENCE ENGINE\n'
    ui_rule
    printf '  [1] Evaluate session risk & display terminal report\n'
    printf '  [2] View prioritized remediation queue (P1..P5)\n'
    printf '  [3] Run correlation & duplicate analysis\n'
    printf '  [4] Export report (JSON / CSV / Markdown / TXT)\n'
    printf '  [5] Suppress a finding (false-positive / risk-accepted)\n'
    printf '  [6] Verify session evidence & report integrity (SHA-256)\n'
    printf '  [b] Back\n\n'
    read -r -p "Select: " c || return 0
    case $c in
      1)
        read -r -p "Session ID (blank = latest): " sid || return 0
        if [[ -n $sid ]]; then (_risk_cmd_evaluate --session "$sid") || true; else (_risk_cmd_evaluate) || true; fi
        ui_pause ;;
      2)
        read -r -p "Session ID (blank = latest): " sid || return 0
        if [[ -n $sid ]]; then (_risk_cmd_prioritize --session "$sid") || true; else (_risk_cmd_prioritize) || true; fi
        ui_pause ;;
      3)
        read -r -p "Session ID (blank = latest): " sid || return 0
        if [[ -n $sid ]]; then (_risk_cmd_correlate --session "$sid") || true; else (_risk_cmd_correlate) || true; fi
        ui_pause ;;
      4)
        read -r -p "Session ID (blank = latest): " sid || return 0
        read -r -p "Format (json|csv|md|txt): " fmt || return 0
        read -r -p "Output file path: " out || return 0
        if [[ -n $sid ]]; then
          (_risk_cmd_report --session "$sid" --format "$fmt" -o "$out") || true
        else
          (_risk_cmd_report --format "$fmt" -o "$out") || true
        fi
        ui_pause ;;
      5)
        read -r -p "Session ID (blank = latest): " sid || return 0
        read -r -p "Finding ID (e.g. AN-password-001): " fid || return 0
        read -r -p "Justification reason: " reason || return 0
        if [[ -n $sid ]]; then
          (_risk_cmd_suppress "$fid" --session "$sid" --reason "$reason") || true
        else
          (_risk_cmd_suppress "$fid" --reason "$reason") || true
        fi
        ui_pause ;;
      6)
        read -r -p "Session ID (blank = latest): " sid || return 0
        if [[ -n $sid ]]; then (_risk_cmd_verify --session "$sid") || true; else (_risk_cmd_verify) || true; fi
        ui_pause ;;
      b | B | q | Q) return 0 ;;
      *) printf 'Invalid selection.\n' ;;
    esac
  done
}
