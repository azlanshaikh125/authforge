#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034  # globals are shared across sourced files by design
# AUTHFORGE lib: Risk Intelligence Engine, correlation, deduplication,
# false-positive suppression, cryptographic evidence manifest, and multi-format reporting.
#
# SECURITY: All fields pass through log_redact before storage or export.
# Streaming awk pipelines (mawk + gawk compatible) process large finding datasets
# without loading unbounded arrays into Bash memory.
[[ -n "${_AN_RISK:-}" ]] && return 0
_AN_RISK=1

RISK_TOTAL_RAW=0
RISK_UNIQUE_COUNT=0
RISK_ACTIVE_COUNT=0
RISK_SUPPRESSED_COUNT=0
RISK_DUP_GROUPS=0
RISK_DUP_EXTRA=0
RISK_CORR_COUNT=0
RISK_MAX_SCORE="0.0"
RISK_AVG_SCORE="0.0"
RISK_POSTURE_INDEX=100
RISK_OVERALL_RATING="CLEAN"

declare -gA RISK_SEV_COUNTS=([CRITICAL]=0 [HIGH]=0 [MEDIUM]=0 [LOW]=0 [INFO]=0)
declare -gA RISK_PRI_COUNTS=([P1-IMMEDIATE]=0 [P2-HIGH]=0 [P3-MEDIUM]=0 [P4-LOW]=0 [P5-INFO]=0 [SUPPRESSED]=0)
declare -ga RISK_CORRELATIONS=()

_risk_reset() {
  RISK_TOTAL_RAW=0
  RISK_UNIQUE_COUNT=0
  RISK_ACTIVE_COUNT=0
  RISK_SUPPRESSED_COUNT=0
  RISK_DUP_GROUPS=0
  RISK_DUP_EXTRA=0
  RISK_CORR_COUNT=0
  RISK_MAX_SCORE="0.0"
  RISK_AVG_SCORE="0.0"
  RISK_POSTURE_INDEX=100
  RISK_OVERALL_RATING="CLEAN"
  RISK_SEV_COUNTS=([CRITICAL]=0 [HIGH]=0 [MEDIUM]=0 [LOW]=0 [INFO]=0)
  RISK_PRI_COUNTS=([P1-IMMEDIATE]=0 [P2-HIGH]=0 [P3-MEDIUM]=0 [P4-LOW]=0 [P5-INFO]=0 [SUPPRESSED]=0)
  RISK_CORRELATIONS=()
  return 0
}

# Resolve session ID (explicit or latest). Validates session ID format.
risk_resolve_session() { # <outvar> [sid]
  local -n _out_sid=$1
  local s=${2:-}
  if [[ -z $s ]]; then
    if [[ -n ${AN_SESSION_ID:-} && -f "$AN_DATA_DIR/reports/$AN_SESSION_ID/findings.dat" ]]; then
      s=$AN_SESSION_ID
    else
      s=$(session_latest)
    fi
  fi
  [[ -n $s ]] || an_die "$EX_VALIDATION" "no sessions found"
  [[ $s =~ ^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$ ]] || an_die "$EX_VALIDATION" "invalid session id: $s"
  [[ -f "$AN_DATA_DIR/reports/$s/findings.dat" ]] || an_die "$EX_VALIDATION" "unknown session: $s"
  _out_sid=$s
  return 0
}

# Evaluate a findings.dat file (+ optional suppressions.dat) and write enriched,
# deduplicated, correlated, prioritized records to <out_enriched_file>.
risk_evaluate_file() { # <findings_file> <out_enriched_file> [suppressions_file]
  _risk_reset
  local ffile=$1 out_file=$2 sfile=${3:-}
  : >"$out_file"
  if [[ ! -s $ffile ]]; then return 0; fi

  if [[ -z $sfile ]]; then
    local dir=${ffile%/*}
    if [[ -f "$dir/suppressions.dat" ]]; then sfile="$dir/suppressions.dat"; fi
  fi

  local raw_evaluated corr_file summary_file
  raw_evaluated=$(tmp_file)
  corr_file=$(tmp_file)
  summary_file=$(tmp_file)

  LC_ALL=C awk \
    -v FS='\x1f' -v OFS='\x1f' \
    -v sfile="$sfile" -v corr_out="$corr_file" -v sum_out="$summary_file" '
    BEGIN {
      if (sfile != "") {
        while ((getline line < sfile) > 0) {
          sub(/\r$/, "", line)
          n = split(line, sp, "\x1f")
          if (n >= 3 && sp[1] != "") {
            sup_stat[sp[1]] = sp[2]
            sup_reas[sp[1]] = sp[3]
          }
        }
        close(sfile)
      }
    }
    {
      sub(/\r$/, "")
      if (length($0) == 0) next
      id = $1; ts = $2; mod = $3; sev = $4; conf = $5; basis = $6
      title = $7; detail = $8; rem = $9; evid = $10
      if (id == "" || (sev != "INFO" && sev != "LOW" && sev != "MEDIUM" && sev != "HIGH" && sev != "CRITICAL")) next

      total_raw++

      fp = mod "\x1c" sev "\x1c" conf "\x1c" basis "\x1c" title "\x1c" evid
      if (fp in fp_idx) {
        idx = fp_idx[fp]
        u_occ[idx]++
        if (id in sup_stat && !(u_id[idx] in sup_stat)) {
          sup_stat[u_id[idx]] = sup_stat[id]
          sup_reas[u_id[idx]] = sup_reas[id]
        }
        next
      }
      u_cnt++
      idx = u_cnt
      fp_idx[fp] = idx
      u_id[idx] = id; u_ts[idx] = ts; u_mod[idx] = mod; u_sev[idx] = sev
      u_conf[idx] = conf; u_basis[idx] = basis; u_title[idx] = title
      u_detail[idx] = detail; u_rem[idx] = rem; u_evid[idx] = evid
      u_occ[idx] = 1

      is_sup = (id in sup_stat) ? 1 : 0
      if (!is_sup) {
        if (mod == "password" && (sev == "HIGH" || sev == "MEDIUM")) has_weak_pw++
        if (mod == "hash" && (sev == "CRITICAL" || sev == "HIGH")) has_weak_hash++
        if (evid ~ /setting=(policy_|hash_)/) has_policy_gap++
        if (evid ~ /(dataset=|file=|matches=|broken=|unsalted=|low_cost=)/ && (sev == "CRITICAL" || sev == "HIGH" || sev == "MEDIUM")) has_dataset_weak++
        if (evid ~ /(reused_values=|reused_hashes=)/) has_reuse++
        if (evid ~ /unsalted=/) has_unsalted++
        if (mod == "wordlist") has_wordlist++
        if (mod == "mfa" && (sev == "CRITICAL" || sev == "HIGH")) has_weak_mfa++
        if (mod == "pwreset" && (sev == "CRITICAL" || sev == "HIGH")) has_weak_pwreset++
        if (mod == "session_sec" && (sev == "CRITICAL" || sev == "HIGH")) has_weak_sess++
        if ((mod == "proto_audit" || mod == "auth_intel") && (sev == "CRITICAL" || sev == "HIGH")) has_transport_weak++
        if (mod == "web_auth" && (evid ~ /missing=Secure/ || evid ~ /ratelimit_headers=0/)) has_web_weak++
        if (evid ~ /ratelimit_headers=0/) has_no_rl++
      }
    }
    END {
      corr_n = 0
      boost_pw_hash = 0; boost_pol_ds = 0; boost_reuse = 0; boost_wl = 0
      boost_mfa_pwr = 0; boost_sess = 0; boost_trans = 0; boost_rl = 0
      if (has_weak_pw > 0 && has_weak_hash > 0) {
        corr_n++
        boost_pw_hash = 0.6
        printf "CORR-01\x1fCRITICAL\x1fHIGH\x1fCompound Offline Cracking Exposure\x1fWeak or common passwords (%d finding(s)) co-occur with weak, broken, or legacy password hashes (%d finding(s)), multiplying offline recovery speed.\x1fPrioritize migrating password storage to Argon2id/bcrypt (cost>=12) while forcing password rotation with common-password blocklist enforcement.\n", has_weak_pw, has_weak_hash > corr_out
      }
      if (has_policy_gap > 0 && has_dataset_weak > 0) {
        corr_n++
        boost_pol_ds = 0.4
        printf "CORR-02\x1fHIGH\x1fHIGH\x1fPolicy-to-Dataset Enforcement Gap\x1fPermissive policy configuration (%d finding(s)) directly correlates with observed credential or hash weaknesses in audited datasets (%d finding(s)).\x1fHarden profile settings (enable blocklist, raise minimum length/KDF work factors) and re-audit existing credentials.\n", has_policy_gap, has_dataset_weak > corr_out
      }
      if ((has_reuse > 0 && has_unsalted > 0) || has_reuse >= 2) {
        corr_n++
        boost_reuse = 0.4
        printf "CORR-03\x1fHIGH\x1fHIGH\x1fSystemic Secret Reuse & Collision Amplification\x1fCredential or hash reuse (%d finding(s)) combined with unsalted/shared storage (%d finding(s)) enables single-compromise lateral movement across accounts.\x1fEnforce unique per-credential salts and require unique passwords across all accounts.\n", has_reuse, has_unsalted > corr_out
      }
      if (has_wordlist > 0 && (has_weak_pw > 0 || has_policy_gap > 0)) {
        corr_n++
        boost_wl = 0.2
        printf "CORR-04\x1fMEDIUM\x1fMEDIUM\x1fWordlist Policy Surface Exposure\x1fAudited wordlist characteristics (%d finding(s)) overlap with active password policy or credential weaknesses.\x1fIncorporate cleaned, deduplicated wordlists into pre-authentication blocklist screening.\n", has_wordlist > corr_out
      }
      if (has_weak_mfa > 0 && has_weak_pwreset > 0) {
        corr_n++
        boost_mfa_pwr = 0.5
        printf "CORR-05\x1fCRITICAL\x1fHIGH\x1fCompound Account-Recovery & MFA Weaknesses\x1fHigh-severity MFA weaknesses (%d finding(s)) co-occur with weak password-reset recovery controls (%d finding(s)), weakening account-recovery boundaries.\x1fEnforce phishing-resistant MFA, re-authentication on MFA changes, high-entropy hashed reset tokens, and session revocation on reset.\n", has_weak_mfa, has_weak_pwreset > corr_out
      }
      if (has_weak_sess > 0 && (has_weak_mfa > 0 || has_weak_pwreset > 0)) {
        corr_n++
        boost_sess = 0.4
        printf "CORR-06\x1fHIGH\x1fHIGH\x1fSession Hijacking & Lifecycle Persistence Risk\x1fInsecure session controls (%d finding(s)) combined with MFA or password-reset gaps amplify post-authentication persistence.\x1fHarden cookie flags (Secure/HttpOnly/SameSite), rotate IDs on login, and revoke active sessions on password reset.\n", has_weak_sess > corr_out
      }
      if (has_transport_weak > 0 && (has_web_weak > 0 || has_weak_sess > 0)) {
        corr_n++
        boost_trans = 0.5
        printf "CORR-07\x1fCRITICAL\x1fHIGH\x1fCleartext or Weak Transport + Credential/Cookie Exposure\x1fTransport/protocol weaknesses (%d finding(s)) co-occur with cookie or session weaknesses, exposing credentials or session cookies in transit.\x1fEnforce HTTPS (TLS 1.2+), HSTS, and Secure/HttpOnly/SameSite cookie flags.\n", has_transport_weak > corr_out
      }
      if (has_no_rl > 0 && (has_weak_pw > 0 || has_weak_mfa > 0)) {
        corr_n++
        boost_rl = 0.3
        printf "CORR-08\x1fHIGH\x1fMEDIUM\x1fUnthrottled Online Guessing Surface\x1fAbsent rate-limit headers on the authentication endpoint co-occur with weak password or MFA controls.\x1fEnforce server-side rate limiting, progressive backoff, and common-password blocklists.\n" > corr_out
      }

      dup_groups = 0; dup_extra = 0
      act_cnt = 0; sup_cnt = 0
      max_sc = 0.0; sum_sc = 0.0
      pen_sum = 0.0

      for (i = 1; i <= u_cnt; i++) {
        id = u_id[i]; ts = u_ts[i]; mod = u_mod[i]; sev = u_sev[i]
        conf = u_conf[i]; basis = u_basis[i]; title = u_title[i]
        detail = u_detail[i]; rem = u_rem[i]; evid = u_evid[i]; occ = u_occ[i]

        if (occ > 1) {
          dup_groups++
          dup_extra += (occ - 1)
        }

        if (sev == "CRITICAL") { base_w = 9.8; s_rank = 4; band_max = 10.0 }
        else if (sev == "HIGH") { base_w = 8.0; s_rank = 3; band_max = 8.9 }
        else if (sev == "MEDIUM") { base_w = 5.5; s_rank = 2; band_max = 6.9 }
        else if (sev == "LOW") { base_w = 3.0; s_rank = 1; band_max = 3.9 }
        else { base_w = 1.0; s_rank = 0; band_max = 1.9 }

        if (conf == "HIGH") { conf_w = 1.00; c_rank = 3 }
        else if (conf == "MEDIUM") { conf_w = 0.88; c_rank = 2 }
        else { conf_w = 0.75; c_rank = 1 }

        if (basis == "verified") { basis_w = 1.00; b_rank = 2 }
        else { basis_w = 0.90; b_rank = 1 }

        if (sev == "CRITICAL" || evid ~ /(match=exact|matches=|broken=|cleartext|empty_password|reset_send_password_in_email=1|mfa_enabled=0|auth=Basic)/) {
          lik = "VERY_HIGH"; lik_w = 1.00
        } else if (sev == "HIGH" || evid ~ /(unsalted|legacy|reused_|match=variant|rotate_login=0|Host|Secure|HttpOnly|scheme=http)/) {
          lik = "HIGH"; lik_w = 0.85
        } else if (sev == "MEDIUM" || evid ~ /(low_cost|cost=|setting=|missing=)/) {
          lik = "MEDIUM"; lik_w = 0.70
        } else {
          lik = "LOW"; lik_w = 0.55
        }

        if (sev == "CRITICAL" || evid ~ /(dataset=|total=|setting=hash_allow_legacy=1|setting=policy_block_common=0|mfa_enabled=0|reset_send_password_in_email=1|auth=Basic)/) {
          if (sev == "CRITICAL" || sev == "HIGH") { imp = "CRITICAL"; imp_w = 1.00 }
          else { imp = "HIGH"; imp_w = 0.88 }
        } else if (mod == "password" || mod == "hash" || mod == "mfa" || mod == "session_sec" || mod == "pwreset" || mod == "proto_audit" || mod == "web_auth" || mod == "auth_intel") {
          if (sev == "HIGH" || sev == "MEDIUM") { imp = "HIGH"; imp_w = 0.88 }
          else { imp = "MEDIUM"; imp_w = 0.72 }
        } else {
          if (sev == "HIGH" || sev == "MEDIUM") { imp = "MEDIUM"; imp_w = 0.72 }
          else { imp = "LOW"; imp_w = 0.55 }
        }

        c_boost = 0.0
        if (boost_pw_hash > 0 && (mod == "password" || mod == "hash") && s_rank >= 2) c_boost += boost_pw_hash
        if (boost_pol_ds > 0 && evid ~ /(setting=|dataset=)/) c_boost += boost_pol_ds
        if (boost_reuse > 0 && evid ~ /(reused_|unsalted=)/) c_boost += boost_reuse
        if (boost_wl > 0 && mod == "wordlist") c_boost += boost_wl
        if (boost_mfa_pwr > 0 && (mod == "mfa" || mod == "pwreset") && s_rank >= 2) c_boost += boost_mfa_pwr
        if (boost_sess > 0 && (mod == "session_sec" || mod == "mfa" || mod == "pwreset") && s_rank >= 2) c_boost += boost_sess
        if (boost_trans > 0 && (mod == "proto_audit" || mod == "auth_intel" || mod == "web_auth") && s_rank >= 2) c_boost += boost_trans
        if (boost_rl > 0 && (mod == "web_auth" || mod == "password" || mod == "mfa")) c_boost += boost_rl

        sc = base_w * (0.45 + 0.30 * lik_w + 0.25 * imp_w) * conf_w * basis_w + c_boost
        if (sc > band_max) sc = band_max
        if (sc < 0.1) sc = 0.1

        status = "active"
        s_reason = ""
        if (id in sup_stat) {
          status = sup_stat[id]
          s_reason = sup_reas[id]
          pri = "SUPPRESSED"
          sort_grp = 0
          sup_cnt++
          pri_c["SUPPRESSED"]++
        } else {
          act_cnt++
          sev_c[sev]++
          if (sc > max_sc) max_sc = sc
          sum_sc += sc
          if (sev == "CRITICAL") pen_sum += 28
          else if (sev == "HIGH") pen_sum += 16
          else if (sev == "MEDIUM") pen_sum += 7
          else if (sev == "LOW") pen_sum += 2
          else pen_sum += 0.5

          if (sc >= 8.5 || sev == "CRITICAL") { pri = "P1-IMMEDIATE"; sort_grp = 5 }
          else if (sc >= 6.5 || (sev == "HIGH" && sc >= 5.5)) { pri = "P2-HIGH"; sort_grp = 4 }
          else if (sc >= 3.5 || sev == "MEDIUM") { pri = "P3-MEDIUM"; sort_grp = 3 }
          else if (sc >= 1.8 || sev == "LOW") { pri = "P4-LOW"; sort_grp = 2 }
          else { pri = "P5-INFO"; sort_grp = 1 }
          pri_c[pri]++
        }

        sc_int = int(sc * 10 + 0.5)
        printf "%d|%03d|%d|%d|%d|%05d\x1f%s\x1f%.1f\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%d\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\n", \
          sort_grp, sc_int, s_rank, c_rank, b_rank, occ, \
          pri, sc, id, ts, mod, sev, conf, lik, imp, basis, status, occ, title, detail, rem, evid, s_reason
      }

      avg_sc = (act_cnt > 0) ? (sum_sc / act_cnt) : 0.0
      posture = int(100 - pen_sum + 0.5)
      if (posture < 0) posture = 0
      if (posture > 100) posture = 100

      if (act_cnt == 0) overall = "CLEAN"
      else if (sev_c["CRITICAL"] > 0 || max_sc >= 9.0) overall = "CRITICAL"
      else if (sev_c["HIGH"] > 0 || max_sc >= 7.0) overall = "HIGH"
      else if (sev_c["MEDIUM"] > 0 || max_sc >= 4.0) overall = "MEDIUM"
      else if (sev_c["LOW"] > 0 || max_sc >= 2.0) overall = "LOW"
      else overall = "INFO"

      printf "%d|%d|%d|%d|%d|%d|%d|%.1f|%.1f|%d|%s|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d\n", \
        total_raw+0, u_cnt+0, act_cnt+0, sup_cnt+0, dup_groups+0, dup_extra+0, corr_n+0, \
        max_sc, avg_sc, posture, overall, \
        sev_c["CRITICAL"]+0, sev_c["HIGH"]+0, sev_c["MEDIUM"]+0, sev_c["LOW"]+0, sev_c["INFO"]+0, \
        pri_c["P1-IMMEDIATE"]+0, pri_c["P2-HIGH"]+0, pri_c["P3-MEDIUM"]+0, pri_c["P4-LOW"]+0, pri_c["P5-INFO"]+0, pri_c["SUPPRESSED"]+0 > sum_out
    }' "$ffile" >"$raw_evaluated"

  if [[ -s $raw_evaluated ]]; then
    LC_ALL=C sort -t $'\x1f' -k1,1r -T "$AN_TMPDIR" -- "$raw_evaluated" | cut -d $'\x1f' -f2- >"$out_file"
  fi

  if [[ -s $summary_file ]]; then
    local c_crit c_high c_med c_low c_info p1 p2 p3 p4 p5 psup
    IFS='|' read -r \
      RISK_TOTAL_RAW RISK_UNIQUE_COUNT RISK_ACTIVE_COUNT RISK_SUPPRESSED_COUNT \
      RISK_DUP_GROUPS RISK_DUP_EXTRA RISK_CORR_COUNT \
      RISK_MAX_SCORE RISK_AVG_SCORE RISK_POSTURE_INDEX RISK_OVERALL_RATING \
      c_crit c_high c_med c_low c_info p1 p2 p3 p4 p5 psup <"$summary_file"
    RISK_SEV_COUNTS=([CRITICAL]=$c_crit [HIGH]=$c_high [MEDIUM]=$c_med [LOW]=$c_low [INFO]=$c_info)
    RISK_PRI_COUNTS=([P1-IMMEDIATE]=$p1 [P2-HIGH]=$p2 [P3-MEDIUM]=$p3 [P4-LOW]=$p4 [P5-INFO]=$p5 [SUPPRESSED]=$psup)
  fi

  if [[ -s $corr_file ]]; then
    local cid csev cconf ctitle cdetail crem
    while IFS=$'\x1f' read -r cid csev cconf ctitle cdetail crem; do
      [[ -n $cid ]] || continue
      RISK_CORRELATIONS+=("${cid}${AN_FS}${csev}${AN_FS}${cconf}${AN_FS}${ctitle}${AN_FS}${cdetail}${AN_FS}${crem}")
    done <"$corr_file"
  fi

  rm -f -- "$raw_evaluated" "$corr_file" "$summary_file"
  return 0
}

# False-positive / risk-acceptance suppression workflow ---------------------
risk_suppress_add() { # <sid> <finding_id> <false_positive|risk_accepted> <reason>
  local sid=$1 fid=$2 st=$3 reason=$4
  [[ $fid =~ ^AN-[a-z0-9_]+-[0-9]{3,}$ ]] || an_die "$EX_VALIDATION" "invalid finding id format: $fid"
  case $st in false_positive | risk_accepted) ;; *) an_die "$EX_VALIDATION" "invalid suppression status: $st" ;; esac
  reason=$(str_trim "$reason")
  [[ -n $reason ]] || an_die "$EX_VALIDATION" "suppression requires a non-empty --reason"

  local ffile="$AN_DATA_DIR/reports/$sid/findings.dat"
  [[ -f $ffile ]] || an_die "$EX_VALIDATION" "unknown session: $sid"
  if ! grep -q "^${fid}"$'\x1f' "$ffile" 2>/dev/null; then
    an_die "$EX_VALIDATION" "finding $fid not found in session $sid"
  fi

  local sfile="$AN_DATA_DIR/reports/$sid/suppressions.dat"
  local clean_reason ts tmp_s
  clean_reason=$(field_clean "$reason" | log_redact)
  ts=$(log_ts)
  tmp_s=$(tmp_file)
  if [[ -f $sfile ]]; then
    awk -v FS='\x1f' -v target="$fid" '$1 != target { print $0 }' "$sfile" >"$tmp_s"
  fi
  printf '%s\x1f%s\x1f%s\x1f%s\n' "$fid" "$st" "$clean_reason" "$ts" >>"$tmp_s"
  (umask 077; cat "$tmp_s" >"$sfile")
  rm -f -- "$tmp_s"
  log_info "finding suppression recorded session=$sid id=$fid status=$st"
  risk_manifest_update "$sid"
  return 0
}

risk_suppress_remove() { # <sid> <finding_id>
  local sid=$1 fid=$2
  [[ $fid =~ ^AN-[a-z0-9_]+-[0-9]{3,}$ ]] || an_die "$EX_VALIDATION" "invalid finding id format: $fid"
  local sfile="$AN_DATA_DIR/reports/$sid/suppressions.dat"
  [[ -f $sfile ]] || an_die "$EX_VALIDATION" "no suppressions recorded for session $sid"
  if ! grep -q "^${fid}"$'\x1f' "$sfile" 2>/dev/null; then
    an_die "$EX_VALIDATION" "finding $fid is not suppressed in session $sid"
  fi
  local tmp_s
  tmp_s=$(tmp_file)
  awk -v FS='\x1f' -v target="$fid" '$1 != target { print $0 }' "$sfile" >"$tmp_s"
  (umask 077; cat "$tmp_s" >"$sfile")
  rm -f -- "$tmp_s"
  log_info "finding suppression removed session=$sid id=$fid"
  risk_manifest_update "$sid"
  return 0
}

risk_suppress_list() { # <sid>
  local sid=$1
  local sfile="$AN_DATA_DIR/reports/$sid/suppressions.dat"
  if [[ ! -s $sfile ]]; then
    printf 'No suppressions recorded for session %s.\n' "$sid"
    return 0
  fi
  local fid st reason ts
  printf 'Suppressions for session %s:\n' "$sid"
  ui_rule
  while IFS=$'\x1f' read -r fid st reason ts; do
    [[ -n $fid ]] || continue
    printf '  %-18s %-16s %s  (reason: %s)\n' "$fid" "[$st]" "$ts" "$reason"
  done <"$sfile"
  ui_rule
  return 0
}

# Evidence tracking & cryptographic SHA-256 integrity manifest --------------
risk_manifest_update() { # <sid>
  local sid=${1:-$AN_SESSION_ID}
  [[ -n $sid ]] || return 0
  local rdir="$AN_DATA_DIR/reports/$sid"
  local edir="$AN_DATA_DIR/evidence/$sid"
  [[ -d $rdir && -d $edir ]] || return 0

  local mfile="$edir/manifest.sha256"
  local tmp_m
  tmp_m=$(tmp_file)
  local rel f sum
  shopt -s nullglob
  for f in "$rdir/findings.dat" "$rdir/suppressions.dat" "$rdir"/report.* "$edir/evidence.log"; do
    [[ -f $f && ! -L $f ]] || continue
    rel=${f#"$AN_DATA_DIR"/}
    sum=$(sha256sum -- "$f" | awk '{print $1}')
    printf '%s  %s\n' "$sum" "$rel" >>"$tmp_m"
  done
  shopt -u nullglob
  (umask 077; cat "$tmp_m" >"$mfile")
  rm -f -- "$tmp_m"
  return 0
}

risk_manifest_verify() { # <sid>
  local sid=$1
  local mfile="$AN_DATA_DIR/evidence/$sid/manifest.sha256"
  if [[ ! -s $mfile ]]; then
    printf '%s integrity manifest missing for session %s\n' "$(ui_status_badge FAIL)" "$sid"
    return "$EX_VALIDATION"
  fi
  local fails=0 checked=0 line exp_hash rel full actual_hash
  printf 'Integrity verification for session: %s\n' "$sid"
  ui_rule
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%$'\r'}
    [[ -n $line ]] || continue
    if [[ ! $line =~ ^([0-9a-fA-F]{64})[[:space:]]+(.+)$ ]]; then
      printf '  %s malformed manifest entry\n' "$(ui_status_badge FAIL)"
      fails=$((fails + 1))
      continue
    fi
    exp_hash=${BASH_REMATCH[1],,}
    rel=${BASH_REMATCH[2]}
    full="$AN_DATA_DIR/$rel"
    checked=$((checked + 1))
    if ! validate_path_within "$full" "$AN_DATA_DIR" || [[ ! -f $full || -L $full ]]; then
      printf '  %s %s (missing or unsafe file)\n' "$(ui_status_badge FAIL)" "$rel"
      fails=$((fails + 1))
      continue
    fi
    actual_hash=$(sha256sum -- "$full" | awk '{print tolower($1)}')
    if [[ $actual_hash == "$exp_hash" ]]; then
      printf '  %s %s (sha256=%s...)\n' "$(ui_status_badge PASS)" "$rel" "${actual_hash:0:16}"
    else
      printf '  %s %s (TAMPERED: expected %s..., got %s...)\n' \
        "$(ui_status_badge FAIL)" "$rel" "${exp_hash:0:16}" "${actual_hash:0:16}"
      fails=$((fails + 1))
    fi
  done <"$mfile"
  ui_rule
  printf 'Integrity result: %d file(s) verified, %d failure(s)\n' "$checked" "$fails"
  if ((fails > 0 || checked == 0)); then return "$EX_VALIDATION"; fi
  return 0
}

# Professional terminal risk report -----------------------------------------
risk_report_terminal() { # <sid> <findings_file>
  local sid=$1 ffile=$2
  local enriched
  enriched=$(tmp_file)
  risk_evaluate_file "$ffile" "$enriched"
  risk_manifest_update "$sid"

  local mfile="$AN_DATA_DIR/evidence/$sid/manifest.sha256"
  local mhash="n/a"
  if [[ -f $mfile ]]; then mhash=$(sha256sum -- "$mfile" | awk '{print substr($1,1,16)}'); fi

  printf 'AUTHFORGE RISK INTELLIGENCE REPORT\n'
  ui_rule
  printf '  %-24s %s\n' "Session ID" "$sid"
  printf '  %-24s %s\n' "Overall risk rating" "$(ui_risk_badge "$RISK_OVERALL_RATING")"
  printf '  %-24s %s / 100   (peak risk score: %s / 10.0, mean: %s / 10.0)\n' \
    "Security posture index" "$RISK_POSTURE_INDEX" "$RISK_MAX_SCORE" "$RISK_AVG_SCORE"
  printf '  %-24s total=%d unique=%d active=%d suppressed=%d\n' \
    "Finding counts" "$RISK_TOTAL_RAW" "$RISK_UNIQUE_COUNT" "$RISK_ACTIVE_COUNT" "$RISK_SUPPRESSED_COUNT"
  printf '  %-24s %d duplicate group(s) (%d redundant instance(s) collapsed)\n' \
    "Deduplication" "$RISK_DUP_GROUPS" "$RISK_DUP_EXTRA"
  printf '  %-24s CRITICAL=%d HIGH=%d MEDIUM=%d LOW=%d INFO=%d\n' \
    "Active by severity" \
    "${RISK_SEV_COUNTS[CRITICAL]}" "${RISK_SEV_COUNTS[HIGH]}" "${RISK_SEV_COUNTS[MEDIUM]}" \
    "${RISK_SEV_COUNTS[LOW]}" "${RISK_SEV_COUNTS[INFO]}"
  printf '  %-24s P1=%d P2=%d P3=%d P4=%d P5=%d\n' \
    "Active by priority" \
    "${RISK_PRI_COUNTS[P1-IMMEDIATE]}" "${RISK_PRI_COUNTS[P2-HIGH]}" "${RISK_PRI_COUNTS[P3-MEDIUM]}" \
    "${RISK_PRI_COUNTS[P4-LOW]}" "${RISK_PRI_COUNTS[P5-INFO]}"
  printf '  %-24s %d compound risk chain(s) detected\n' "Correlations" "$RISK_CORR_COUNT"
  printf '  %-24s sha256:%s...\n' "Evidence manifest" "$mhash"
  ui_rule

  if ((RISK_CORR_COUNT > 0)); then
    printf '\nCORRELATED RISK CHAINS\n'
    ui_rule
    local c cid csev cconf ctitle cdetail crem
    for c in "${RISK_CORRELATIONS[@]}"; do
      IFS=$'\x1f' read -r cid csev cconf ctitle cdetail crem <<<"$c"
      printf '  %s %s %s (confidence=%s)\n' "$(ui_risk_badge "$csev")" "$cid" "$ctitle" "$cconf"
      printf '      %s\n' "$cdetail"
      printf '      remediation: %s\n' "$crem"
    done
    ui_rule
  fi

  printf '\nPRIORITIZED FINDINGS & REMEDIATION QUEUE\n'
  ui_rule
  if [[ ! -s $enriched ]]; then
    printf '  No findings recorded in this session.\n'
  else
    local pri score id ts mod sev conf lik imp basis status occ title detail rem evid sreason
    while IFS=$'\x1f' read -r pri score id ts mod sev conf lik imp basis status occ title detail rem evid sreason; do
      if [[ $status != "active" ]]; then
        printf '  [SUPPRESSED:%s] %s (%s) %s\n' "$status" "$id" "$sev" "$title"
        printf '      reason: %s\n' "$sreason"
        continue
      fi
      printf '  %s [%-12s] score=%-4s %s  %s\n' "$(ui_risk_badge "$sev")" "$pri" "$score" "$id" "$title"
      printf '      module=%s confidence=%s likelihood=%s impact=%s basis=%s occurrences=%s\n' \
        "$mod" "$conf" "$lik" "$imp" "$basis" "$occ"
      printf '      %s\n' "$detail"
      if [[ -n $evid ]]; then printf '      evidence: %s\n' "$evid"; fi
      printf '      remediation: %s\n' "$rem"
    done <"$enriched"
  fi
  ui_rule
  rm -f -- "$enriched"
  return 0
}
