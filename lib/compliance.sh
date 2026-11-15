#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034  # globals are shared across sourced files by design
# AUTHFORGE library: Compliance Assessment Engine (Milestone 5, Phase 1).
# Loads external 13-column TSV catalog (data/compliance_mappings.dat: 40 controls
# across OWASP ASVS 5.0.0, NIST SP 800-63B-4, and CIS Controls v8.1) and evaluates
# session check ledgers (checks.dat) and findings (findings.dat) conservatively.
[[ -n "${_AN_LIB_COMPLIANCE:-}" ]] && return 0
_AN_LIB_COMPLIANCE=1

declare -gA COMP_SUMMARY_COUNTS=(
  [TOTAL]=0 [PASS]=0 [PARTIAL]=0 [FAIL]=0 ["NOT TESTED"]=0 ["N/A"]=0
)
declare -gA COMP_FW_TOTAL=([ASVS]=0 [NIST]=0 [CIS]=0)
declare -gA COMP_FW_PASS=([ASVS]=0 [NIST]=0 [CIS]=0)
declare -gA COMP_FW_PARTIAL=([ASVS]=0 [NIST]=0 [CIS]=0)
declare -gA COMP_FW_FAIL=([ASVS]=0 [NIST]=0 [CIS]=0)
declare -gA COMP_FW_NOT_TESTED=([ASVS]=0 [NIST]=0 [CIS]=0)
declare -gA COMP_FW_NA=([ASVS]=0 [NIST]=0 [CIS]=0)

# Parse and validate the external 13-column TSV catalog (data/compliance_mappings.dat)
# into out_file (13 fields separated by \x1f).
# Uses awk split($0, f, "\t") == 13 so empty optional fields (columns 9 and 13)
# never shift fields and literal "|" characters inside column 10 (finding_regex) are preserved.
compliance_load_catalog() { # <out_file> [framework_filter]
  local out_file=$1 fw_filter=${2:-ALL}
  fw_filter=${fw_filter^^}
  case $fw_filter in
    ALL | ASVS | NIST | CIS) ;;
    *) return "$EX_USAGE" ;;
  esac

  local cat_src=${AN_COMPLIANCE_CATALOG:-$AN_ROOT/data/compliance_mappings.dat}
  validate_regular_file "$cat_src" || {
    log_error "compliance catalog is missing or not a regular file: $cat_src"
    return "$EX_CONFIG"
  }
  local cmode
  cmode=$(LC_ALL=C stat -c '%a' -- "$cat_src" 2>/dev/null) || return "$EX_CONFIG"
  if (((8#$cmode & 8#022) != 0)); then
    log_error "compliance catalog is group- or world-writable (mode $cmode): $cat_src"
    return "$EX_CONFIG"
  fi

  if ! LC_ALL=C awk -v fw_want="$fw_filter" '
    BEGIN {
      US = sprintf("%c", 31)
      bad = 0
      total_rows = 0
    }
    {
      sub(/\r$/, "")
      if (length($0) == 0 || substr($0, 1, 1) == "#") next
      n = split($0, f, "\t")
      if (n != 13) { bad = 1; exit 1 }
      fw = f[1]; ver = f[2]; cid = f[3]; sec = f[4]; lvl = f[5]; title = f[6]
      sum = f[7]; req = f[8]; gates = f[9]; freg = f[10]; maxst = f[11]; lim = f[12]; xwalk = f[13]
      if (fw != "ASVS" && fw != "NIST" && fw != "CIS") { bad = 1; exit 1 }
      if (cid == "" || title == "" || req == "" || maxst != "PARTIAL") { bad = 1; exit 1 }
      if (seen_cid[fw ":" cid]++) { bad = 1; exit 1 }
      total_rows++
      fw_rows[fw]++
      if (fw_want != "ALL" && fw != fw_want) next
      printf "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n", \
        fw, US, ver, US, cid, US, sec, US, lvl, US, title, US, \
        sum, US, req, US, gates, US, freg, US, maxst, US, lim, US, xwalk
    }
    END {
      if (bad) exit 1
      if (total_rows != 40 || fw_rows["ASVS"] != 25 || fw_rows["NIST"] != 11 || fw_rows["CIS"] != 4) exit 1
    }' "$cat_src" >"$out_file"; then
    rm -f -- "$out_file"
    log_error "invalid or corrupted compliance catalog: $cat_src"
    return "$EX_CONFIG"
  fi
  return 0
}

# Evaluate a session's checks.dat, findings.dat, and suppressions.dat against
# the 40-control catalog.
# Output record schema in out_file (13 fields separated by \x1f):
#   1:framework  2:version  3:control_id  4:section  5:level  6:status
#   7:max_status  8:title  9:executed_checks  10:matched_finding_ids
#   11:reason_detail  12:scope_limit  13:legacy_crosswalk
compliance_evaluate_session() { # <sid> <out_file> [framework_filter]
  local sid=${1:-$AN_SESSION_ID} out_file=$2 fw_filter=${3:-ALL}
  [[ -n $sid && $sid =~ ^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$ ]] || return "$EX_VALIDATION"
  local rdir="$AN_DATA_DIR/reports/$sid"
  local ffile="$rdir/findings.dat"
  local cfile="$rdir/checks.dat"
  local sfile="$rdir/suppressions.dat"
  [[ -f $ffile && ! -L $ffile ]] || return "$EX_VALIDATION"

  local cat_file sum_file load_rc=0
  cat_file=$(tmp_file)
  sum_file=$(tmp_file)
  compliance_load_catalog "$cat_file" "$fw_filter" || load_rc=$?
  if ((load_rc != 0)); then
    rm -f -- "$cat_file" "$sum_file"
    return "$load_rc"
  fi

  : >"$out_file"
  LC_ALL=C awk \
    -v ffile="$ffile" -v cfile="$cfile" -v sfile="$sfile" -v sum_out="$sum_file" '
    BEGIN {
      US = sprintf("%c", 31)

      # 1. Load suppressions.dat (4 fields: fid \x1f status \x1f reason \x1f ts)
      while ((getline line < sfile) > 0) {
        sub(/\r$/, "", line)
        if (split(line, sf, US) >= 2 && sf[1] != "") {
          suppressed[sf[1]] = sf[2]
        }
      }
      close(sfile)

      # 2. Load checks.dat (6 fields: check_id \x1f status \x1f exit_code \x1f target_type \x1f ts \x1f detail)
      # Production rule: ignore any untrusted target_linked or verifier_behavior_established tokens.
      has_checks_file = 0
      while ((getline line < cfile) > 0) {
        sub(/\r$/, "", line)
        if (split(line, cf, US) == 6 && cf[1] != "") {
          has_checks_file = 1
          cid = cf[1]
          chk_status[cid] = cf[2]
          chk_rc[cid] = cf[3] + 0
          chk_target[cid] = cf[4]
          det = cf[6]
          gsub(/(^|[;[[:space:]]+)(target_linked|verifier_behavior_established)=[^;[:space:]]*/, "", det)
          chk_detail[cid] = det
        }
      }
      close(cfile)

      # 3. Load findings.dat (10 fields: id \x1f ts \x1f mod \x1f sev \x1f conf \x1f basis \x1f title \x1f detail \x1f rem \x1f evid)
      f_cnt = 0
      while ((getline line < ffile) > 0) {
        sub(/\r$/, "", line)
        if (split(line, ff, US) == 10 && ff[1] ~ /^AN-[a-z0-9_]+-[0-9]+$/) {
          fid = ff[1]
          if (fid in suppressed) continue
          f_cnt++
          f_id[f_cnt] = fid
          f_mod[f_cnt] = ff[3]
          f_sev[f_cnt] = ff[4]
          f_conf[f_cnt] = ff[5]
          f_basis[f_cnt] = ff[6]
          f_title[f_cnt] = ff[7]
          f_evid[f_cnt] = ff[10]
          mod_has_findings[ff[3]] = 1
        }
      }
      close(ffile)
    }

    # Helper: determine whether a required check cid was validly executed with usable evidence
    function check_validly_completed(cid, gates,    st, det) {
      st = (cid in chk_status) ? chk_status[cid] : ""
      det = (cid in chk_detail) ? chk_detail[cid] : ""
      if (st != "COMPLETED") {
        # Legacy M0-M4 fallback ONLY when checks.dat is absent/empty and an active finding proves the module ran
        if (!has_checks_file) {
          if (cid ~ /^password:/ && mod_has_findings["password"]) return 1
          if (cid ~ /^hash:/ && mod_has_findings["hash"]) return 1
          if (cid ~ /^mfa:/ && mod_has_findings["mfa"]) return 1
          if (cid ~ /^session-audit:/ && mod_has_findings["session_sec"]) return 1
          if (cid ~ /^pwreset:/ && mod_has_findings["pwreset"]) return 1
          if (cid ~ /^proto-audit:/ && mod_has_findings["proto_audit"]) return 1
          if (cid ~ /^auth-intel:/ && mod_has_findings["auth_intel"]) return 1
          if (cid ~ /^web-auth:/ && mod_has_findings["web_auth"]) return 1
        }
        return 0
      }
      # Check probe-specific validity gates so failed/empty probes stay NOT TESTED
      if (cid == "proto-audit:tls") {
        if (det ~ /tls_handshake_ok=0/) return 0
      } else if (cid == "proto-audit:http-auth" || cid == "auth-intel:scan" || cid == "web-auth:headers") {
        if (det ~ /http_probe_ok=0/) return 0
      } else if (cid == "auth-intel:oidc-check") {
        if (det ~ /http_probe_ok=0/ || det ~ /oidc_found=0/) return 0
      } else if (cid == "web-auth:cookies") {
        if (det ~ /http_probe_ok=0/ || det ~ /cookies_seen=0/) return 0
      } else if (cid == "web-auth:rate-limit-check") {
        if (det ~ /http_probe_ok=0/ || det ~ /ratelimit_probes=0/) return 0
      }
      return 1
    }

    {
      sub(/\r$/, "")
      if (split($0, c, US) != 13) next
      fw = c[1]; ver = c[2]; cid = c[3]; sec = c[4]; lvl = c[5]; title = c[6]
      sum = c[7]; req_csv = c[8]; gates = c[9]; freg = c[10]; maxst = c[11]; lim = c[12]; xwalk = c[13]

      nreq = split(req_csv, req_arr, ",")
      exec_list = ""
      refused_list = ""
      valid_exec_cnt = 0
      for (i = 1; i <= nreq; i++) {
        rcid = req_arr[i]
        if (check_validly_completed(rcid, gates)) {
          valid_exec_cnt++
          exec_list = exec_list (exec_list == "" ? "" : ",") rcid
        } else if (rcid in chk_status) {
          refused_list = refused_list (refused_list == "" ? "" : ",") rcid "(" chk_status[rcid] ")"
        }
      }

      # Match active findings against finding_regex (only when not conservative_partial_only)
      matched_fids = ""
      fail_hit = 0
      if (gates != "conservative_partial_only" && freg != "") {
        for (j = 1; j <= f_cnt; j++) {
          if (f_title[j] ~ freg) {
            if (f_sev[j] == "CRITICAL" || f_sev[j] == "HIGH" || f_sev[j] == "MEDIUM" || f_basis[j] == "verified" || cid == "v5.0.0-6.2.5" || cid == "v5.0.0-6.2.9" || cid == "v5.0.0-3.4.3" || cid == "v5.0.0-6.3.1") {
              fail_hit = 1
              matched_fids = matched_fids (matched_fids == "" ? "" : ",") f_id[j]
            }
          }
        }
      }

      if (valid_exec_cnt == 0 && !fail_hit) {
        st = "NOT TESTED"
        if (refused_list != "") {
          reason = "Mapped check(s) did not complete with usable evidence: " refused_list "."
        } else {
          reason = "No mapped check executed in this session (requires: " req_csv ")."
        }
      } else if (fail_hit) {
        st = "FAIL"
        reason = "Control requirement failed based on session finding(s): " matched_fids "."
      } else {
        # Capped at max_status (PARTIAL across all 40 controls in M5-P1)
        st = maxst
        if (gates == "conservative_partial_only") {
          reason = "Mapped check(s) completed (" exec_list "); capped at PARTIAL because offline artifacts/descriptors do not establish target CSP verifier behavior or AAL context."
        } else {
          reason = "Mapped check(s) completed (" exec_list ") with no disqualifying control findings; capped at PARTIAL due to offline/single-probe verification scope."
        }
      }

      tot_c[st]++
      tot_all++
      fw_tot[fw]++
      fw_c[fw, st]++

      printf "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n", \
        fw, US, ver, US, cid, US, sec, US, lvl, US, st, US, \
        maxst, US, title, US, (exec_list == "" ? "none" : exec_list), US, \
        (matched_fids == "" ? "none" : matched_fids), US, reason, US, lim, US, xwalk
    }
    END {
      printf "%d|%d|%d|%d|%d|%d\n", \
        tot_all+0, tot_c["PASS"]+0, tot_c["PARTIAL"]+0, tot_c["FAIL"]+0, tot_c["NOT TESTED"]+0, tot_c["N/A"]+0 > sum_out
      for (f in fw_tot) {
        printf "%s|%d|%d|%d|%d|%d|%d\n", \
          f, fw_tot[f]+0, fw_c[f, "PASS"]+0, fw_c[f, "PARTIAL"]+0, fw_c[f, "FAIL"]+0, fw_c[f, "NOT TESTED"]+0, fw_c[f, "N/A"]+0 >> sum_out
      }
    }' "$cat_file" >"$out_file"

  COMP_SUMMARY_COUNTS=([TOTAL]=0 [PASS]=0 [PARTIAL]=0 [FAIL]=0 ["NOT TESTED"]=0 ["N/A"]=0)
  COMP_FW_TOTAL=([ASVS]=0 [NIST]=0 [CIS]=0)
  COMP_FW_PASS=([ASVS]=0 [NIST]=0 [CIS]=0)
  COMP_FW_PARTIAL=([ASVS]=0 [NIST]=0 [CIS]=0)
  COMP_FW_FAIL=([ASVS]=0 [NIST]=0 [CIS]=0)
  COMP_FW_NOT_TESTED=([ASVS]=0 [NIST]=0 [CIS]=0)
  COMP_FW_NA=([ASVS]=0 [NIST]=0 [CIS]=0)

  if [[ -s $sum_file ]]; then
    local lno=0 a b c d e f g
    while IFS='|' read -r a b c d e f g; do
      lno=$((lno + 1))
      if ((lno == 1)); then
        COMP_SUMMARY_COUNTS=(
          [TOTAL]=$a [PASS]=$b [PARTIAL]=$c [FAIL]=$d ["NOT TESTED"]=$e ["N/A"]=$f
        )
      elif [[ -n $a ]]; then
        COMP_FW_TOTAL[$a]=$b
        COMP_FW_PASS[$a]=$c
        COMP_FW_PARTIAL[$a]=$d
        COMP_FW_FAIL[$a]=$e
        COMP_FW_NOT_TESTED[$a]=$f
        COMP_FW_NA[$a]=$g
      fi
    done <"$sum_file"
  fi

  rm -f -- "$cat_file" "$sum_file"
  return 0
}

_comp_status_badge() {
  case $1 in
    PASS) ui_status_badge PASS ;;
    FAIL) ui_status_badge FAIL ;;
    PARTIAL) printf '%s[PARTIAL]%s' "$C_YELLOW" "$C_RESET" ;;
    "NOT TESTED") ui_status_badge "NOT TESTED" ;;
    "N/A") printf '%s[N/A]%s' "$C_DIM" "$C_RESET" ;;
    *) printf '[%s]' "$1" ;;
  esac
}

compliance_report_terminal() { # <sid> [framework_filter] [gaps_only]
  local sid=${1:-$AN_SESSION_ID} fw_filter=${2:-ALL} gaps_only=${3:-0}
  local eval_file rc=0
  eval_file=$(tmp_file)
  compliance_evaluate_session "$sid" "$eval_file" "$fw_filter" || rc=$?
  if ((rc != 0)); then
    rm -f -- "$eval_file"
    return "$rc"
  fi

  printf 'AUTHFORGE COMPLIANCE ASSESSMENT REPORT\n'
  ui_rule
  printf '  %-24s %s\n' "Session ID" "$sid"
  printf '  %-24s %s\n' "Framework filter" "${fw_filter^^}"
  printf '  %-24s total=%d  PASS=%d  PARTIAL=%d  FAIL=%d  NOT_TESTED=%d  N/A=%d\n' \
    "Control summary" \
    "${COMP_SUMMARY_COUNTS[TOTAL]}" "${COMP_SUMMARY_COUNTS[PASS]}" \
    "${COMP_SUMMARY_COUNTS[PARTIAL]}" "${COMP_SUMMARY_COUNTS[FAIL]}" \
    "${COMP_SUMMARY_COUNTS[NOT TESTED]}" "${COMP_SUMMARY_COUNTS[N/A]}"
  local fw
  for fw in ASVS NIST CIS; do
    if ((COMP_FW_TOTAL[$fw] > 0)); then
      printf '  %-24s total=%-2d PASS=%-2d PARTIAL=%-2d FAIL=%-2d NOT_TESTED=%-2d N/A=%-2d\n' \
        "Framework: $fw" \
        "${COMP_FW_TOTAL[$fw]}" "${COMP_FW_PASS[$fw]}" "${COMP_FW_PARTIAL[$fw]}" \
        "${COMP_FW_FAIL[$fw]}" "${COMP_FW_NOT_TESTED[$fw]}" "${COMP_FW_NA[$fw]}"
    fi
  done
  printf '  %-24s %s\n' "Methodology note" "Offline/lab checks cap passing controls at PARTIAL (max_status=PARTIAL)"
  ui_rule

  local ver cid sec lvl st maxst title execs fids reason lim xwalk shown=0
  while IFS=$'\x1f' read -r fw ver cid sec lvl st maxst title execs fids reason lim xwalk; do
    [[ -n $cid ]] || continue
    if ((gaps_only)) && [[ $st != "FAIL" && $st != "NOT TESTED" ]]; then
      continue
    fi
    shown=$((shown + 1))
    printf '  %s %-8s %-14s [%s] %s\n' "$(_comp_status_badge "$st")" "$fw $ver" "$cid" "$lvl" "$title"
    printf '      checks=%s  findings=%s  crosswalk=%s\n' "$execs" "$fids" "${xwalk:-n/a}"
    printf '      assessment: %s\n' "$reason"
    printf '      scope bound: %s\n' "$lim"
  done <"$eval_file"
  if ((shown == 0)); then
    printf '  No controls matched the selected filter.\n'
  fi
  ui_rule
  rm -f -- "$eval_file"
  return 0
}

compliance_export_json() { # <sid> [framework_filter]
  local sid=${1:-$AN_SESSION_ID} fw_filter=${2:-ALL}
  local eval_file rc=0
  eval_file=$(tmp_file)
  compliance_evaluate_session "$sid" "$eval_file" "$fw_filter" || rc=$?
  if ((rc != 0)); then
    rm -f -- "$eval_file"
    return "$rc"
  fi

  printf '{\n'
  printf '  "session": "%s",\n' "$(json_escape "$sid")"
  printf '  "framework_filter": "%s",\n' "$(json_escape "${fw_filter^^}")"
  printf '  "summary": {"total": %d, "PASS": %d, "PARTIAL": %d, "FAIL": %d, "NOT_TESTED": %d, "NA": %d},\n' \
    "${COMP_SUMMARY_COUNTS[TOTAL]}" "${COMP_SUMMARY_COUNTS[PASS]}" \
    "${COMP_SUMMARY_COUNTS[PARTIAL]}" "${COMP_SUMMARY_COUNTS[FAIL]}" \
    "${COMP_SUMMARY_COUNTS[NOT TESTED]}" "${COMP_SUMMARY_COUNTS[N/A]}"
  printf '  "controls": [\n'
  local first=1 fw ver cid sec lvl st maxst title execs fids reason lim xwalk
  while IFS=$'\x1f' read -r fw ver cid sec lvl st maxst title execs fids reason lim xwalk; do
    [[ -n $cid ]] || continue
    if ((first)); then first=0; else printf ',\n'; fi
    printf '    {"framework":"%s","version":"%s","control_id":"%s","section":"%s","level":"%s","status":"%s","max_status":"%s","title":"%s","executed_checks":"%s","matched_findings":"%s","assessment":"%s","scope_limit":"%s","legacy_crosswalk":"%s"}' \
      "$(json_escape "$fw")" "$(json_escape "$ver")" "$(json_escape "$cid")" \
      "$(json_escape "$sec")" "$(json_escape "$lvl")" "$(json_escape "$st")" \
      "$(json_escape "$maxst")" "$(json_escape "$title")" "$(json_escape "$execs")" \
      "$(json_escape "$fids")" "$(json_escape "$reason")" "$(json_escape "$lim")" \
      "$(json_escape "$xwalk")"
  done <"$eval_file"
  printf '\n  ]\n}\n'
  rm -f -- "$eval_file"
  return 0
}

compliance_export_csv() { # <sid> [framework_filter]
  local sid=${1:-$AN_SESSION_ID} fw_filter=${2:-ALL}
  local eval_file rc=0
  eval_file=$(tmp_file)
  compliance_evaluate_session "$sid" "$eval_file" "$fw_filter" || rc=$?
  if ((rc != 0)); then
    rm -f -- "$eval_file"
    return "$rc"
  fi

  printf 'session,framework,version,control_id,section,level,status,max_status,title,executed_checks,matched_findings,assessment,scope_limit,legacy_crosswalk\n'
  local fw ver cid sec lvl st maxst title execs fids reason lim xwalk
  while IFS=$'\x1f' read -r fw ver cid sec lvl st maxst title execs fids reason lim xwalk; do
    [[ -n $cid ]] || continue
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
      "$(csv_escape "$sid")" "$(csv_escape "$fw")" "$(csv_escape "$ver")" \
      "$(csv_escape "$cid")" "$(csv_escape "$sec")" "$(csv_escape "$lvl")" \
      "$(csv_escape "$st")" "$(csv_escape "$maxst")" "$(csv_escape "$title")" \
      "$(csv_escape "$execs")" "$(csv_escape "$fids")" "$(csv_escape "$reason")" \
      "$(csv_escape "$lim")" "$(csv_escape "$xwalk")"
  done <"$eval_file"
  rm -f -- "$eval_file"
  return 0
}

compliance_export_markdown() { # <sid> [framework_filter]
  local sid=${1:-$AN_SESSION_ID} fw_filter=${2:-ALL}
  local eval_file rc=0
  eval_file=$(tmp_file)
  compliance_evaluate_session "$sid" "$eval_file" "$fw_filter" || rc=$?
  if ((rc != 0)); then
    rm -f -- "$eval_file"
    return "$rc"
  fi

  printf '# AUTHFORGE Compliance Assessment Report\n\n'
  # shellcheck disable=SC2016  # Intentional literal Markdown backticks.
  printf '- **Session ID**: `%s`\n' "$sid"
  # shellcheck disable=SC2016  # Intentional literal Markdown backticks.
  printf '- **Framework Filter**: `%s`\n' "${fw_filter^^}"
  printf '- **Control Counts**: Total=%d, PASS=%d, PARTIAL=%d, FAIL=%d, NOT TESTED=%d, N/A=%d\n' \
    "${COMP_SUMMARY_COUNTS[TOTAL]}" "${COMP_SUMMARY_COUNTS[PASS]}" \
    "${COMP_SUMMARY_COUNTS[PARTIAL]}" "${COMP_SUMMARY_COUNTS[FAIL]}" \
    "${COMP_SUMMARY_COUNTS[NOT TESTED]}" "${COMP_SUMMARY_COUNTS[N/A]}"
  # shellcheck disable=SC2016  # Intentional literal Markdown backticks.
  printf '- **Verification Bound**: All 40 controls carry `max_status=PARTIAL` because offline descriptors, local datasets, and single-request lab probes cannot prove full runtime or enterprise-wide compliance.\n\n'
  printf '## Control Matrix\n\n'
  printf '| Framework | Control ID | Level | Status | Max Status | Title | Executed Checks | Findings | Assessment & Scope Limitation |\n'
  printf '|---|---|---|---|---|---|---|---|---|\n'
  local fw ver cid sec lvl st maxst title execs fids reason lim xwalk
  while IFS=$'\x1f' read -r fw ver cid sec lvl st maxst title execs fids reason lim xwalk; do
    [[ -n $cid ]] || continue
    # shellcheck disable=SC2016  # Intentional literal Markdown backticks.
    printf '| %s %s | `%s` | %s | **%s** | %s | %s | `%s` | `%s` | %s *(Limit: %s)* |\n' \
      "$(md_escape "$fw")" "$(md_escape "$ver")" "$(md_escape "$cid")" \
      "$(md_escape "$lvl")" "$(md_escape "$st")" "$(md_escape "$maxst")" \
      "$(md_escape "$title")" "$(md_escape "$execs")" "$(md_escape "$fids")" \
      "$(md_escape "$reason")" "$(md_escape "$lim")"
  done <"$eval_file"
  rm -f -- "$eval_file"
  return 0
}

compliance_export_txt() { # <sid> [framework_filter]
  local sid=${1:-$AN_SESSION_ID} fw_filter=${2:-ALL}
  AN_NO_COLOR=1 ui_init
  compliance_report_terminal "$sid" "$fw_filter" 0
}
