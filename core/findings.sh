#!/usr/bin/env bash
# shellcheck shell=bash
# AUTHFORGE core: finding data model + multi-format export (JSON, CSV, Markdown, TXT).
#
# Evidence rule (spec section 4): a finding may only be marked basis=verified
# when it carries non-empty evidence. Everything else is a heuristic
# observation. Records are stored with the ASCII unit separator (0x1f) as the
# field delimiter so empty fields survive `read`.
[[ -n "${_AN_FINDINGS:-}" ]] && return 0
_AN_FINDINGS=1

readonly AN_FS=$'\x1f'
AN_FINDING_SEQ=0

# findings_add <severity> <confidence> <basis> <title> <detail> <remediation> [evidence]
findings_add() {
  local sev=$1 conf=$2 basis=$3 title=$4 detail=$5 rem=$6 evid=${7:-}
  in_array "$sev" "${AN_SEVERITIES[@]}" || { log_error "bad severity: $sev"; return "$EX_VALIDATION"; }
  in_array "$conf" "${AN_CONFIDENCES[@]}" || { log_error "bad confidence: $conf"; return "$EX_VALIDATION"; }
  case $basis in verified | heuristic) ;; *) log_error "bad basis: $basis"; return "$EX_VALIDATION" ;; esac
  if [[ $basis == verified && -z $evid ]]; then
    log_error "refusing to record a 'verified' finding without evidence: $title"
    return "$EX_VALIDATION"
  fi
  [[ -n $AN_SESSION_FINDINGS ]] || { log_error "no active session"; return "$EX_GENERAL"; }

  AN_FINDING_SEQ=$((AN_FINDING_SEQ + 1))
  local id
  id=$(printf 'AN-%s-%03d' "${AN_MODULE:-core}" "$AN_FINDING_SEQ")
  local f_title f_detail f_rem f_evid
  f_title=$(field_clean "$title" | log_redact)
  f_detail=$(field_clean "$detail" | log_redact)
  f_rem=$(field_clean "$rem" | log_redact)
  f_evid=$(field_clean "$evid" | log_redact)
  printf '%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\n' \
    "$id" "$(log_ts)" "${AN_MODULE:-core}" "$sev" "$conf" "$basis" \
    "$f_title" "$f_detail" "$f_rem" "$f_evid" >>"$AN_SESSION_FINDINGS"
  log_info "finding recorded id=$id severity=$sev confidence=$conf basis=$basis"
  return 0
}

_sev_rank() {
  local i
  for i in "${!AN_SEVERITIES[@]}"; do
    if [[ ${AN_SEVERITIES[$i]} == "$1" ]]; then printf '%d' "$i"; return 0; fi
  done
  printf -- '-1'
}

# Highest severity rank present in a findings file (-1 if none).
# Respects suppressions.dat if present alongside findings.dat.
findings_max_rank() { # <file>
  local f=${1:-$AN_SESSION_FINDINGS} max=-1 r
  local id ts mod sev rest
  [[ -s $f ]] || { printf -- '-1'; return 0; }
  local sfile="${f%/*}/suppressions.dat"
  while IFS=$AN_FS read -r id ts mod sev rest; do
    if [[ -s $sfile ]] && grep -q "^${id}"$'\x1f' "$sfile" 2>/dev/null; then
      continue
    fi
    r=$(_sev_rank "$sev")
    if ((r > max)); then max=$r; fi
  done <"$f"
  printf '%d' "$max"
}

findings_print() { # <file> : human-readable list
  local f=${1:-$AN_SESSION_FINDINGS}
  local id ts mod sev conf basis title detail rem evid n=0
  [[ -s $f ]] || { printf 'No findings recorded.\n'; return 0; }
  while IFS=$AN_FS read -r id ts mod sev conf basis title detail rem evid; do
    n=$((n + 1))
    printf '%s %s %s\n' "$(ui_risk_badge "$sev")" "$id" "$title"
    printf '    confidence=%s basis=%s\n' "$conf" "$basis"
    printf '    %s\n' "$detail"
    if [[ -n $evid ]]; then printf '    evidence: %s\n' "$evid"; fi
    printf '    remediation: %s\n' "$rem"
  done <"$f"
  return 0
}

# JSON export (enriched with M2 risk intelligence while preserving M0/M1 schema).
# Usage: findings_export_json <session-id> <findings-file>
findings_export_json() {
  local sid=$1 f=$2
  local enriched
  enriched=$(tmp_file)
  risk_evaluate_file "$f" "$enriched"

  local -A raw_count=()
  local s id ts mod sev conf basis title detail rem evid
  for s in "${AN_SEVERITIES[@]}"; do raw_count[$s]=0; done
  if [[ -s $f ]]; then
    while IFS=$AN_FS read -r id ts mod sev conf basis title detail rem evid; do
      [[ -n ${raw_count[$sev]+x} ]] && raw_count[$sev]=$((${raw_count[$sev]:-0} + 1))
    done <"$f"
  fi

  local corr_body="" cfirst=1 c cid csev cconf ctitle cdetail crem
  for c in "${RISK_CORRELATIONS[@]}"; do
    IFS=$'\x1f' read -r cid csev cconf ctitle cdetail crem <<<"$c"
    if ((cfirst)); then cfirst=0; else corr_body+=","; fi
    corr_body+=$'\n    {'
    corr_body+="\"id\":\"$(json_escape "$cid")\",\"severity\":\"$csev\",\"confidence\":\"$cconf\","
    corr_body+="\"title\":\"$(json_escape "$ctitle")\",\"detail\":\"$(json_escape "$cdetail")\","
    corr_body+="\"remediation\":\"$(json_escape "$crem")\"}"
  done

  local body="" first=1
  local pri score lik imp status occ sreason
  if [[ -s $enriched ]]; then
    while IFS=$'\x1f' read -r pri score id ts mod sev conf lik imp basis status occ title detail rem evid sreason; do
      if ((first)); then first=0; else body+=","; fi
      body+=$'\n    {'
      body+="\"id\":\"$(json_escape "$id")\",\"timestamp\":\"$(json_escape "$ts")\","
      body+="\"module\":\"$(json_escape "$mod")\",\"severity\":\"$sev\",\"confidence\":\"$conf\","
      body+="\"likelihood\":\"$lik\",\"impact\":\"$imp\",\"score\":$score,\"priority\":\"$pri\","
      body+="\"basis\":\"$basis\",\"status\":\"$(json_escape "$status")\",\"occurrences\":$occ,"
      body+="\"title\":\"$(json_escape "$title")\",\"detail\":\"$(json_escape "$detail")\","
      body+="\"remediation\":\"$(json_escape "$rem")\",\"evidence\":\"$(json_escape "$evid")\"}"
    done <"$enriched"
  fi
  rm -f -- "$enriched"

  printf '{\n  "metadata": {"tool":"%s","version":"%s","session":"%s","generated":"%s"},\n' \
    "$AN_NAME" "$AN_VERSION" "$(json_escape "$sid")" "$(log_ts)"
  printf '  "summary": {'
  local sep=""
  for s in CRITICAL HIGH MEDIUM LOW INFO; do
    printf '%s"%s":%d' "$sep" "$s" "${raw_count[$s]}"
    sep=","
  done
  printf '},\n'
  printf '  "risk_summary": {"overall_rating":"%s","posture_index":%d,"max_score":%s,"avg_score":%s,"total_raw":%d,"unique_findings":%d,"active_findings":%d,"suppressed_findings":%d,"duplicate_groups":%d,"duplicate_extra":%d,"correlations":%d},\n' \
    "$RISK_OVERALL_RATING" "$RISK_POSTURE_INDEX" "$RISK_MAX_SCORE" "$RISK_AVG_SCORE" \
    "$RISK_TOTAL_RAW" "$RISK_UNIQUE_COUNT" "$RISK_ACTIVE_COUNT" "$RISK_SUPPRESSED_COUNT" \
    "$RISK_DUP_GROUPS" "$RISK_DUP_EXTRA" "$RISK_CORR_COUNT"
  printf '  "correlations": [%s\n  ],\n' "$corr_body"
  printf '  "findings": [%s\n  ]\n}\n' "$body"
  return 0
}

# RFC 4180 CSV export of prioritized, deduplicated findings.
findings_export_csv() { # <session-id> <findings-file>
  local sid=$1 f=$2
  local enriched
  enriched=$(tmp_file)
  risk_evaluate_file "$f" "$enriched"
  printf 'session,priority,score,id,timestamp,module,severity,confidence,likelihood,impact,basis,status,occurrences,title,detail,remediation,evidence\n'
  if [[ -s $enriched ]]; then
    local pri score id ts mod sev conf lik imp basis status occ title detail rem evid sreason
# shellcheck disable=SC2034  # sreason: trailing field consumed but unused
    while IFS=$'\x1f' read -r pri score id ts mod sev conf lik imp basis status occ title detail rem evid sreason; do
      printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$(csv_escape "$sid")" "$(csv_escape "$pri")" "$(csv_escape "$score")" \
        "$(csv_escape "$id")" "$(csv_escape "$ts")" "$(csv_escape "$mod")" \
        "$(csv_escape "$sev")" "$(csv_escape "$conf")" "$(csv_escape "$lik")" \
        "$(csv_escape "$imp")" "$(csv_escape "$basis")" "$(csv_escape "$status")" \
        "$(csv_escape "$occ")" "$(csv_escape "$title")" "$(csv_escape "$detail")" \
        "$(csv_escape "$rem")" "$(csv_escape "$evid")"
    done <"$enriched"
  fi
  rm -f -- "$enriched"
  return 0
}

# Markdown executive & technical security report export.
findings_export_markdown() { # <session-id> <findings-file>
  local sid=$1 f=$2
  local enriched
  enriched=$(tmp_file)
  risk_evaluate_file "$f" "$enriched"

  cat <<EOF
# $AN_NAME Security Assessment Report

- **Session ID**: \`$sid\`
- **Tool Version**: \`$AN_NAME $AN_VERSION\`
- **Generated**: \`$(log_ts)\`
- **Overall Risk Rating**: **$RISK_OVERALL_RATING**
- **Security Posture Index**: **$RISK_POSTURE_INDEX / 100** (Peak Score: **$RISK_MAX_SCORE / 10.0**, Mean Score: **$RISK_AVG_SCORE / 10.0**)

## Executive Risk Summary

| Metric | Count |
| :--- | ---: |
| Total Raw Findings | $RISK_TOTAL_RAW |
| Unique Findings (Deduplicated) | $RISK_UNIQUE_COUNT |
| Active Findings | $RISK_ACTIVE_COUNT |
| Suppressed / Risk-Accepted | $RISK_SUPPRESSED_COUNT |
| Duplicate Groups Collapsed | $RISK_DUP_GROUPS ($RISK_DUP_EXTRA redundant) |
| Correlated Attack Chains | $RISK_CORR_COUNT |

## Active Severity & Priority Distribution

| Severity | Active Count | Priority Tier | Active Count |
| :--- | ---: | :--- | ---: |
| CRITICAL | ${RISK_SEV_COUNTS[CRITICAL]} | P1-IMMEDIATE | ${RISK_PRI_COUNTS[P1-IMMEDIATE]} |
| HIGH | ${RISK_SEV_COUNTS[HIGH]} | P2-HIGH | ${RISK_PRI_COUNTS[P2-HIGH]} |
| MEDIUM | ${RISK_SEV_COUNTS[MEDIUM]} | P3-MEDIUM | ${RISK_PRI_COUNTS[P3-MEDIUM]} |
| LOW | ${RISK_SEV_COUNTS[LOW]} | P4-LOW | ${RISK_PRI_COUNTS[P4-LOW]} |
| INFO | ${RISK_SEV_COUNTS[INFO]} | P5-INFO | ${RISK_PRI_COUNTS[P5-INFO]} |
EOF

  if ((RISK_CORR_COUNT > 0)); then
    printf '\n## Correlated Attack Chains\n\n'
    printf '| ID | Severity | Confidence | Correlation Title | Detail | Recommended Remediation |\n'
    printf '| :--- | :--- | :--- | :--- | :--- | :--- |\n'
    local c cid csev cconf ctitle cdetail crem
    for c in "${RISK_CORRELATIONS[@]}"; do
      IFS=$'\x1f' read -r cid csev cconf ctitle cdetail crem <<<"$c"
      # shellcheck disable=SC2016
      printf '| `%s` | **%s** | %s | %s | %s | %s |\n' \
        "$(md_escape "$cid")" "$(md_escape "$csev")" "$(md_escape "$cconf")" \
        "$(md_escape "$ctitle")" "$(md_escape "$cdetail")" "$(md_escape "$crem")"
    done
  fi

  printf '\n## Prioritized Findings & Remediation Plan\n\n'
  if [[ ! -s $enriched ]]; then
    printf 'No findings were recorded in this session.\n'
  else
    printf '| Priority | Score | ID | Module | Severity | Confidence | Likelihood | Impact | Basis | Status | Occurrences | Title | Remediation | Evidence |\n'
    printf '| :--- | ---: | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | ---: | :--- | :--- | :--- |\n'
    local pri score id ts mod sev conf lik imp basis status occ title detail rem evid
    while IFS=$'\x1f' read -r pri score id ts mod sev conf lik imp basis status occ title detail rem evid _; do
      # shellcheck disable=SC2016
      printf '| %s | %s | `%s` | %s | **%s** | %s | %s | %s | %s | %s | %s | %s | %s | `%s` |\n' \
        "$(md_escape "$pri")" "$score" "$(md_escape "$id")" "$(md_escape "$mod")" \
        "$(md_escape "$sev")" "$(md_escape "$conf")" "$(md_escape "$lik")" "$(md_escape "$imp")" \
        "$(md_escape "$basis")" "$(md_escape "$status")" "$occ" \
        "$(md_escape "$title")" "$(md_escape "$rem")" "$(md_escape "${evid:-n/a}")"
    done <"$enriched"
  fi
  rm -f -- "$enriched"
  return 0
}

# Plain-text printable report export (no ANSI escape sequences).
findings_export_txt() { # <session-id> <findings-file>
  local sid=$1 f=$2
  local old_nc=$AN_NO_COLOR
  local old_r=$C_RESET old_b=$C_BOLD old_d=$C_DIM old_red=$C_RED old_g=$C_GREEN old_y=$C_YELLOW old_bl=$C_BLUE old_m=$C_MAGENTA old_c=$C_CYAN
  AN_NO_COLOR=1
  C_RESET='' C_BOLD='' C_DIM='' C_RED='' C_GREEN='' C_YELLOW='' C_BLUE='' C_MAGENTA='' C_CYAN=''
  risk_report_terminal "$sid" "$f"
  AN_NO_COLOR=$old_nc
  C_RESET=$old_r C_BOLD=$old_b C_DIM=$old_d C_RED=$old_red C_GREEN=$old_g C_YELLOW=$old_y C_BLUE=$old_bl C_MAGENTA=$old_m C_CYAN=$old_c
  return 0
}
