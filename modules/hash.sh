#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034  # globals are shared across sourced files by design
# AUTHFORGE module: Hash Intelligence Engine (menu 03) -- Milestone 1.
# Implemented: identify (alias: analyze), policy-check, policy-review, check-file.
# Offline only. Hashes are read from a hidden prompt, stdin, or dataset file -- never argv.

mod_hash_info() { printf '03|Hash Intelligence Engine|Format identification, cost parameter and legacy-hash audit|ready'; }

_hash_usage() {
  cat <<'USAGE'
Usage: authforge [global opts] hash <subcommand> [args]

  identify           Identify and audit one hash (hidden prompt, or first line of stdin)
  analyze            Alias for identify
  policy-check       Check one hash against the active hash policy profile
  policy-review      Review active hash policy parameters against modern guidance
  check-file FILE    Streaming audit of a hash dataset (raw, user:hash, shadow, or pwdump)

Hashes are never accepted as command-line arguments (they would leak via `ps`).
USAGE
}

_hash_read_one() { # <outvar>
  local -n _dst=$1
  ui_read_secret _dst "Hash (input hidden): " || an_die "$EX_VALIDATION" "no input"
  _dst=${_dst%$'\r'}
  _dst=$(str_trim "$_dst")
  if [[ -z $_dst ]]; then an_die "$EX_VALIDATION" "empty hash input"; fi
  if ((${#_dst} > 2048)); then an_die "$EX_VALIDATION" "input exceeds 2048 characters"; fi
  return 0
}

_hash_rule() { # <PASS|FAIL|REVIEW|NOT TESTED> <text>
  printf '  %s %s\n' "$(ui_status_badge "$1")" "$2"
}

_hash_print_analysis() {
  printf 'Hash intelligence analysis  (digest is never displayed, logged or stored)\n'
  ui_rule
  printf '  %-22s %s\n' "Identified format" "$HI_FORMAT"
  printf '  %-22s %s\n' "Algorithm family" "$HI_FAMILY"
  printf '  %-22s %s\n' "Candidates / modes" "$HI_CANDIDATES"
  if ((HI_AMBIGUOUS)); then
    printf '  %-22s yes (heuristic match by length/charset)\n' "Ambiguity"
  else
    printf '  %-22s no (verified structural prefix)\n' "Ambiguity"
  fi
  printf '  %-22s %s\n' "Salt present" "$HI_SALTED"
  printf '  %-22s %s\n' "Cost / work factor" "$HI_COST_DESC"
  printf '  %-22s %s\n' "Reference mode" "$HI_HASHCAT_MODE"
  printf '  %-22s %s   [%s]\n' "Security tier" "$HI_TIER" "$HI_BASIS"
  if ((${#HI_ISSUES[@]})); then
    printf '  %-22s %s\n' "Issues detected" "${HI_ISSUES[*]}"
  else
    printf '  %-22s none\n' "Issues detected"
  fi
  ui_rule
  return 0
}

_hash_emit_single_findings() {
  if [[ $HI_FORMAT == "unknown" ]]; then
    findings_add LOW LOW heuristic "Unrecognized hash format" \
      "The supplied input did not match any known modular crypt, PHC, LDAP, or raw digest format." \
      "Verify the hash extraction format or inspect the storage scheme specification." || true
    return 0
  fi

  case $HI_TIER in
    broken)
      findings_add CRITICAL HIGH "$HI_BASIS" "Cryptographically broken password storage scheme ($HI_FORMAT)" \
        "Format $HI_FORMAT ($HI_CANDIDATES) is cryptographically broken or stores cleartext/empty markers, permitting rapid offline recovery." \
        "Migrate immediately to Argon2id (m>=19 MiB, t>=2), yescrypt, or bcrypt (cost>=12) and invalidate legacy credentials." \
        "format=$HI_FORMAT; tier=$HI_TIER; salted=$HI_SALTED" || true ;;
    weak)
      findings_add HIGH "$((HI_AMBIGUOUS ? 0 : 1))" "$HI_BASIS" "Weak or unsalted password hash ($HI_FORMAT)" \
        "Format $HI_FORMAT ($HI_CANDIDATES) lacks per-credential salting or key-stretching work factors." \
        "Replace fast single-pass digests with a salted memory-hard KDF (Argon2id) or iterated KDF (bcrypt/PBKDF2-HMAC-SHA256)." \
        "format=$HI_FORMAT; salted=$HI_SALTED; ambiguous=$HI_AMBIGUOUS" 2>/dev/null ||
      findings_add HIGH MEDIUM "$HI_BASIS" "Weak or unsalted password hash ($HI_FORMAT)" \
        "Format $HI_FORMAT ($HI_CANDIDATES) lacks per-credential salting or key-stretching work factors." \
        "Replace fast single-pass digests with a salted memory-hard KDF (Argon2id) or iterated KDF (bcrypt/PBKDF2-HMAC-SHA256)." \
        "format=$HI_FORMAT; salted=$HI_SALTED; ambiguous=$HI_AMBIGUOUS" || true ;;
    legacy)
      local sev="MEDIUM"
      if [[ ${AN_CFG[hash_allow_legacy]:-0} == 0 ]]; then sev="HIGH"; fi
      findings_add "$sev" HIGH "$HI_BASIS" "Legacy password hashing algorithm ($HI_FORMAT)" \
        "Format $HI_FORMAT uses an older hashing construction ($HI_COST_DESC) that is fast to accelerate on modern GPUs." \
        "Plan an online re-hash migration to Argon2id or bcrypt (cost>=12) upon next user authentication." \
        "format=$HI_FORMAT; cost=$HI_COST_DESC; allow_legacy=${AN_CFG[hash_allow_legacy]:-0}" || true ;;
    suboptimal)
      findings_add MEDIUM HIGH verified "Password KDF cost parameters below policy threshold ($HI_FORMAT)" \
        "Algorithm $HI_FORMAT is modern, but its configured work factor ($HI_COST_DESC) is below the active policy floor (${HI_ISSUES[*]})." \
        "Increase KDF work factors (memory, iterations, or cost) to match current hardware and policy baselines." \
        "format=$HI_FORMAT; cost=$HI_COST_DESC; issues=${HI_ISSUES[*]}" || true ;;
  esac
  return 0
}

_hash_cmd_identify() {
  local h
  _hash_read_one h
  hash_analyze "$h"
  unset h
  _hash_print_analysis
  _hash_emit_single_findings
  return 0
}

_hash_cmd_policy_check() {
  local h fails=0
  _hash_read_one h
  hash_analyze "$h"
  unset h
  printf 'Hash policy check against profile: %s\n' "${AN_PROFILE:-default}"
  ui_rule

  if [[ $HI_FORMAT == "unknown" ]]; then
    _hash_rule FAIL "recognized hash format (got unknown)"
    ui_rule
    printf 'Result: 1 rule(s) failed\n'
    _hash_emit_single_findings
    return 0
  fi
  _hash_rule PASS "recognized format: $HI_FORMAT ($HI_BASIS)"

  if [[ $HI_SALTED == "yes" || $HI_SALTED == "embedded" || $HI_SALTED == "n/a" ]]; then
    _hash_rule PASS "salted storage ($HI_SALTED)"
  else
    _hash_rule FAIL "salted storage required (observed unsalted $HI_FORMAT)"
    fails=$((fails + 1))
  fi

  local allow_leg=${AN_CFG[hash_allow_legacy]:-0}
  if [[ $HI_TIER == "broken" || $HI_TIER == "weak" ]]; then
    _hash_rule FAIL "algorithm security tier acceptable (observed $HI_TIER)"
    fails=$((fails + 1))
  elif [[ $HI_TIER == "legacy" && $allow_leg == 0 ]]; then
    _hash_rule FAIL "legacy algorithms disallowed by policy (observed $HI_FORMAT)"
    fails=$((fails + 1))
  else
    _hash_rule PASS "algorithm family permitted ($HI_FORMAT)"
  fi

  case $HI_FORMAT in
    bcrypt)
      local mb=${AN_CFG[hash_min_bcrypt_cost]:-12}
      if ((HI_BCRYPT_COST >= 10#$mb)); then
        _hash_rule PASS "bcrypt cost >= $mb (observed $HI_BCRYPT_COST)"
      else
        _hash_rule FAIL "bcrypt cost >= $mb (observed $HI_BCRYPT_COST)"
        fails=$((fails + 1))
      fi ;;
    argon2id | argon2i | argon2d)
      local mm=${AN_CFG[hash_min_argon2_mib]:-19} mt=${AN_CFG[hash_min_argon2_time]:-2}
      if ((HI_ARGON2_MIB >= 10#$mm)); then
        _hash_rule PASS "Argon2 memory >= ${mm} MiB (observed ${HI_ARGON2_MIB} MiB)"
      else
        _hash_rule FAIL "Argon2 memory >= ${mm} MiB (observed ${HI_ARGON2_MIB} MiB)"
        fails=$((fails + 1))
      fi
      if ((HI_ARGON2_TIME >= 10#$mt)); then
        _hash_rule PASS "Argon2 time cost >= $mt (observed $HI_ARGON2_TIME)"
      else
        _hash_rule FAIL "Argon2 time cost >= $mt (observed $HI_ARGON2_TIME)"
        fails=$((fails + 1))
      fi ;;
    pbkdf2-* | django-pbkdf2-*)
      local mp=${AN_CFG[hash_min_pbkdf2_iterations]:-310000}
      if ((HI_ITERATIONS >= 10#$mp)); then
        _hash_rule PASS "PBKDF2 iterations >= $mp (observed $HI_ITERATIONS)"
      else
        _hash_rule FAIL "PBKDF2 iterations >= $mp (observed $HI_ITERATIONS)"
        fails=$((fails + 1))
      fi ;;
    sha512crypt | sha256crypt)
      local ms=${AN_CFG[hash_min_shacrypt_rounds]:-100000}
      if ((HI_ITERATIONS >= 10#$ms)); then
        _hash_rule PASS "SHA-crypt rounds >= $ms (observed $HI_ITERATIONS)"
      else
        _hash_rule FAIL "SHA-crypt rounds >= $ms (observed $HI_ITERATIONS)"
        fails=$((fails + 1))
      fi ;;
  esac

  ui_rule
  printf 'Result: %d rule(s) failed\n' "$fails"
  if ((fails > 0)); then _hash_emit_single_findings; fi
  return 0
}

_hash_cmd_policy_review() {
  local leg=${AN_CFG[hash_allow_legacy]:-0}
  local bc=${AN_CFG[hash_min_bcrypt_cost]:-12}
  local pb=${AN_CFG[hash_min_pbkdf2_iterations]:-310000}
  local am=${AN_CFG[hash_min_argon2_mib]:-19}
  local at=${AN_CFG[hash_min_argon2_time]:-2}
  local sc=${AN_CFG[hash_min_shacrypt_rounds]:-100000}

  printf 'Hash policy review for profile: %s\n' "${AN_PROFILE:-default}"
  printf 'Guidance basis: OWASP Password Storage Cheat Sheet + NIST SP 800-63B\n'
  ui_rule

  if [[ $leg == 0 ]]; then
    _hash_rule PASS "legacy hash schemes disallowed (hash_allow_legacy=0)"
  else
    _hash_rule FAIL "legacy hash schemes permitted (hash_allow_legacy=1)"
    findings_add HIGH HIGH verified "Hash policy permits legacy algorithms" \
      "hash_allow_legacy=1 allows fast or deprecated schemes such as md5crypt, APR1, and SHA-1/PBKDF2-SHA1." \
      "Set hash_allow_legacy=0 and enforce migration to Argon2id, yescrypt, or bcrypt." \
      "setting=hash_allow_legacy=1" || true
  fi

  if ((10#$bc < 10)); then
    _hash_rule FAIL "minimum bcrypt cost $bc is below 10"
    findings_add MEDIUM HIGH verified "Minimum bcrypt cost below acceptable floor" \
      "hash_min_bcrypt_cost=$bc is below the commonly accepted floor of 10 (12+ recommended)." \
      "Raise hash_min_bcrypt_cost to at least 12." \
      "setting=hash_min_bcrypt_cost=$bc" || true
  elif ((10#$bc < 12)); then
    _hash_rule REVIEW "minimum bcrypt cost $bc meets floor (10) but 12+ is recommended"
    findings_add LOW MEDIUM heuristic "Minimum bcrypt cost is modest" \
      "hash_min_bcrypt_cost=$bc; OWASP guidance recommends cost >= 12 where latency budgets permit." \
      "Consider raising hash_min_bcrypt_cost to 12." \
      "setting=hash_min_bcrypt_cost=$bc" || true
  else
    _hash_rule PASS "minimum bcrypt cost $bc (>= 12)"
  fi

  if ((10#$pb < 100000)); then
    _hash_rule FAIL "minimum PBKDF2 iterations $pb is below 100000"
    findings_add MEDIUM HIGH verified "Minimum PBKDF2 iteration count is critically low" \
      "hash_min_pbkdf2_iterations=$pb is far below modern PBKDF2-HMAC-SHA256 guidance (310,000+)." \
      "Raise hash_min_pbkdf2_iterations to at least 310000 (or 600000 for strict compliance)." \
      "setting=hash_min_pbkdf2_iterations=$pb" || true
  elif ((10#$pb < 310000)); then
    _hash_rule REVIEW "minimum PBKDF2 iterations $pb is below 310000"
  else
    _hash_rule PASS "minimum PBKDF2 iterations $pb (>= 310000)"
  fi

  if ((10#$am < 19)); then
    _hash_rule FAIL "minimum Argon2 memory ${am} MiB is below 19 MiB"
    findings_add MEDIUM HIGH verified "Minimum Argon2 memory cost below OWASP baseline" \
      "hash_min_argon2_mib=$am MiB is below the 19 MiB (19456 KiB) baseline for Argon2id." \
      "Raise hash_min_argon2_mib to at least 19 (46 MiB recommended for higher assurance)." \
      "setting=hash_min_argon2_mib=$am" || true
  else
    _hash_rule PASS "minimum Argon2 memory ${am} MiB (>= 19 MiB)"
  fi

  if ((10#$at < 2)); then
    _hash_rule REVIEW "minimum Argon2 time cost $at is below 2 iterations"
  else
    _hash_rule PASS "minimum Argon2 time cost $at (>= 2)"
  fi

  if ((10#$sc < 50000)); then
    _hash_rule FAIL "minimum SHA-crypt rounds $sc is below 50000 (default 5000 is weak)"
    findings_add MEDIUM HIGH verified "Minimum SHA-crypt rounds configured too low" \
      "hash_min_shacrypt_rounds=$sc permits low-round SHA-256/SHA-512 crypt hashes." \
      "Require at least 100000 rounds for SHA-crypt or migrate to yescrypt/Argon2id." \
      "setting=hash_min_shacrypt_rounds=$sc" || true
  else
    _hash_rule PASS "minimum SHA-crypt rounds $sc (>= 50000)"
  fi
  ui_rule
  return 0
}

# Streaming batch analysis of a hash dataset file (mawk & gawk compatible).
_hash_cmd_check_file() {
  local file=${1:-}
  [[ -n $file ]] || an_die "$EX_USAGE" "check-file requires a FILE argument"
  validate_regular_file "$file" || an_die "$EX_VALIDATION" "not a readable regular file: $file"
  local mode
  mode=$(stat -c '%a' -- "$file")
  if [[ ${mode: -1} != 0 ]]; then log_warn "input file is world-accessible (mode $mode); restrict it"; fi

  local min_b=${AN_CFG[hash_min_bcrypt_cost]:-12}
  local min_pbkdf2=${AN_CFG[hash_min_pbkdf2_iterations]:-310000}
  local min_a2_mib=${AN_CFG[hash_min_argon2_mib]:-19}
  local min_a2_t=${AN_CFG[hash_min_argon2_time]:-2}
  local min_sha=${AN_CFG[hash_min_shacrypt_rounds]:-100000}
  local allow_leg=${AN_CFG[hash_allow_legacy]:-0}

  local tok_file summary_out
  tok_file=$(tmp_file)

  summary_out=$(LC_ALL=C awk \
    -v min_b="$min_b" -v min_p="$min_pbkdf2" -v min_am="$min_a2_mib" \
    -v min_at="$min_a2_t" -v min_s="$min_sha" -v tok_out="$tok_file" '
    function is_hex(s,    i, c) {
      if (length(s) == 0) return 0
      return (s ~ /^[0-9a-fA-F]+$/)
    }
    {
      sub(/\r$/, "")
      gsub(/^[ \t]+|[ \t]+$/, "")
      if (length($0) == 0 || substr($0, 1, 1) == "#") next
      total++
      tok = $0
      # Check PWDUMP user:uid:LM(32):NTLM(32):...
      ncolon = split($0, parts, ":")
      if (ncolon >= 4 && parts[2] ~ /^[0-9]+$/ && length(parts[3]) == 32 && is_hex(parts[3]) && length(parts[4]) == 32 && is_hex(parts[4])) {
        lm = tolower(parts[3]); nt = tolower(parts[4])
        print "pwdump:" lm ":" nt > tok_out
        fmt["lm-ntlm-pwdump"]++
        unsalted++
        if (lm != "aad3b435b51404eeaad3b435b51404ee") { broken++; lm_active++ }
        else if (nt == "31d6cfe0d16ae931b73c59d7e0c089c0") { broken++; empty_pw++ }
        else { weak++ }
        next
      }
      if ($0 !~ /^scrypt:/ && ncolon >= 2) {
        c2 = parts[2]
        if (substr(c2, 1, 1) == "$" || substr(c2, 1, 1) == "{" || substr(c2, 1, 1) == "*" || substr(c2, 1, 1) == "!" || c2 ~ /^pbkdf2_/ || (length(c2) >= 13 && c2 ~ /^[.\/0-9A-Za-z]+$/)) {
          tok = c2
        }
      }
      if (tok == "!" || tok == "*" || tok == "!!" || tok == "!*" || tok ~ /^!+\$/) {
        fmt["account-locked"]++
        locked++
        next
      }
      print tok > tok_out
      if (tok ~ /^\$argon2(id|i|d)\$/) {
        if (tok ~ /^\$argon2id\$/) fmt["argon2id"]++
        else if (tok ~ /^\$argon2i\$/) fmt["argon2i"]++
        else fmt["argon2d"]++
        salted++
        m_kib = 0; t_cost = 0
        if (match(tok, /m=[0-9]+/)) m_kib = substr(tok, RSTART+2, RLENGTH-2) + 0
        if (match(tok, /t=[0-9]+/)) t_cost = substr(tok, RSTART+2, RLENGTH-2) + 0
        if (int(m_kib / 1024) < min_am || t_cost < min_at) { suboptimal++; low_cost++ }
        else strong++
      } else if (tok ~ /^\$(y|gy)\$/) {
        fmt["yescrypt"]++; salted++; strong++
      } else if (tok ~ /^\$(7|scrypt)\$/ || tok ~ /^scrypt:[0-9]+:/) {
        fmt["scrypt"]++; salted++; strong++
      } else if (tok ~ /^\$2[abxy]\$[0-9][0-9]\$/ && length(tok) == 60) {
        fmt["bcrypt"]++; salted++
        bc = substr(tok, 5, 2) + 0
        if (tok ~ /^\$2x\$/) { legacy++ }
        else if (bc < min_b) { suboptimal++; low_cost++ }
        else strong++
      } else if (tok ~ /^\$pbkdf2-(sha256|sha512|sha1)\$/ || tok ~ /^pbkdf2_(sha256|sha1)\$/) {
        salted++
        np = split(tok, pp, "$")
        iter = (tok ~ /^\$/) ? (pp[3] + 0) : (pp[2] + 0)
        if (tok ~ /sha1/) { fmt["pbkdf2-sha1"]++; legacy++ }
        else {
          fmt["pbkdf2-sha256/512"]++
          if (iter < min_p) { suboptimal++; low_cost++ }
          else acceptable++
        }
      } else if (tok ~ /^\$(5|6)\$/) {
        if (tok ~ /^\$6\$/) fmt["sha512crypt"]++; else fmt["sha256crypt"]++
        salted++
        r = 5000
        if (match(tok, /rounds=[0-9]+\$/)) r = substr(tok, RSTART+7, RLENGTH-8) + 0
        if (r < min_s) { suboptimal++; low_cost++ }
        else acceptable++
      } else if (tok ~ /^\$(1|apr1)\$/) {
        if (tok ~ /^\$1\$/) fmt["md5crypt"]++; else fmt["apr1"]++
        salted++; legacy++
      } else if (tok ~ /^\$(3\$|NT\$)/) {
        fmt["bsd-nthash"]++; unsalted++; weak++
      } else if (tok ~ /^\{(SSHA|SSHA256|SSHA512)\}/) {
        fmt["ldap-ssha"]++; salted++; legacy++
      } else if (tok ~ /^\{(SHA|SHA256|SHA512|MD5)\}/) {
        fmt["ldap-unsalted"]++; unsalted++; weak++
      } else if (tok ~ /^\{SMD5\}/) {
        fmt["ldap-smd5"]++; salted++; weak++
      } else if (tok ~ /^\{CLEARTEXT\}/) {
        fmt["ldap-cleartext"]++; unsalted++; broken++
      } else if (substr(tok, 1, 1) == "*" && length(tok) == 41 && is_hex(substr(tok, 2))) {
        fmt["mysql5"]++; unsalted++; weak++
      } else if (length(tok) == 13 && tok ~ /^[.\/0-9A-Za-z]+$/ && !is_hex(tok)) {
        fmt["des-crypt"]++; salted++; broken++; ambig++
      } else if (is_hex(tok)) {
        hl = length(tok)
        unsalted++; ambig++
        if (hl == 16) { fmt["mysql323-or-lm"]++; broken++ }
        else if (hl == 32) {
          fmt["raw-md5-or-ntlm"]++
          tl = tolower(tok)
          if (tl == "aad3b435b51404eeaad3b435b51404ee" || tl == "31d6cfe0d16ae931b73c59d7e0c089c0") { broken++; empty_pw++ }
          else weak++
        } else if (hl == 40) { fmt["raw-sha1"]++; weak++ }
        else if (hl == 56) { fmt["raw-sha224"]++; weak++ }
        else if (hl == 64) { fmt["raw-sha256"]++; weak++ }
        else if (hl == 96) { fmt["raw-sha384"]++; weak++ }
        else if (hl == 128) { fmt["raw-sha512"]++; weak++ }
        else { fmt["unknown"]++; unk++ }
      } else {
        fmt["unknown"]++; unk++
      }
    }
    END {
      fstr = ""
      for (k in fmt) fstr = fstr (fstr == "" ? "" : ", ") k "=" fmt[k]
      if (fstr == "") fstr = "none"
      printf "%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%s\n", \
        total+0, strong+0, acceptable+0, suboptimal+0, legacy+0, weak+0, broken+0, unk+0, locked+0, \
        salted+0, unsalted+0, ambig+0, low_cost+0, lm_active+0, fstr
    }' "$file")

  local total strong acceptable suboptimal legacy weak broken unk locked salted unsalted ambig low_cost lm_active fstr
  IFS='|' read -r total strong acceptable suboptimal legacy weak broken unk locked salted unsalted ambig low_cost lm_active fstr <<<"$summary_out"

  local dup_vals=0 dup_entries=0
  if [[ -s $tok_file ]]; then
    read -r dup_vals dup_entries < <(LC_ALL=C sort -T "$AN_TMPDIR" -- "$tok_file" | uniq -c | awk '$1>1{d++; e+=$1} END{print d+0, e+0}')
  fi
  rm -f -- "$tok_file"

  printf 'Hash dataset analysis: %s  (hashes and accounts are never printed)\n' "${file##*/}"
  ui_rule
  printf '  %-26s %s\n' "Non-empty entries" "$total"
  printf '  %-26s %s\n' "Format breakdown" "$fstr"
  printf '  %-26s strong=%s acceptable=%s suboptimal=%s legacy=%s weak=%s broken=%s unknown=%s\n' \
    "Security tier breakdown" "$strong" "$acceptable" "$suboptimal" "$legacy" "$weak" "$broken" "$unk"
  printf '  %-26s salted=%s unsalted=%s locked=%s\n' "Salt & lock coverage" "$salted" "$unsalted" "$locked"
  printf '  %-26s %s entries (raw hex/traditional crypt)\n' "Ambiguous raw digests" "$ambig"
  printf '  %-26s %s entries below profile work-factor thresholds\n' "Under-costed KDFs" "$low_cost"
  printf '  %-26s %s distinct hash(es) reused, covering %s entries\n' "Duplicate hash reuse" "$dup_vals" "$dup_entries"
  ui_rule

  if ((broken > 0)); then
    findings_add CRITICAL HIGH verified "Dataset contains cryptographically broken or empty-marker hashes" \
      "$broken of $total entries use broken schemes (LM, DES-crypt, MySQL323, cleartext, or empty NTLM/LM markers)." \
      "Disable LM/DES storage immediately, force password resets for affected accounts, and migrate to Argon2id or bcrypt." \
      "dataset=${file##*/}; broken=$broken; lm_active=$lm_active; total=$total" || true
  fi
  if ((unsalted > 0)); then
    local ub="verified"
    if ((ambig == unsalted)); then ub="heuristic"; fi
    findings_add HIGH HIGH "$ub" "Dataset contains unsalted password digests" \
      "$unsalted of $total entries lack per-password salts, enabling precomputed rainbow-table and multi-target attacks." \
      "Migrate all unsalted digests to a salted KDF (Argon2id, yescrypt, or bcrypt)." \
      "dataset=${file##*/}; unsalted=$unsalted; ambiguous=$ambig; total=$total" || true
  fi
  if ((legacy > 0)); then
    local lsev="MEDIUM"
    if ((allow_leg == 0)); then lsev="HIGH"; fi
    findings_add "$lsev" HIGH verified "Dataset contains legacy password hashes" \
      "$legacy of $total entries use deprecated schemes (md5crypt, APR1, PBKDF2-SHA1, LDAP SSHA, or bcrypt \$2x\$)." \
      "Upgrade legacy hashes to Argon2id or bcrypt (cost>=12) during authentication or via forced rotation." \
      "dataset=${file##*/}; legacy=$legacy; allow_legacy=$allow_leg; total=$total" || true
  fi
  if ((low_cost > 0)); then
    findings_add MEDIUM HIGH verified "Dataset contains KDF hashes below policy cost thresholds" \
      "$low_cost entries use modern KDFs (bcrypt/Argon2/PBKDF2/SHA-crypt) with cost parameters below the active profile." \
      "Re-hash credentials with updated cost parameters upon next login." \
      "dataset=${file##*/}; low_cost=$low_cost; total=$total" || true
  fi
  if ((dup_vals > 0)); then
    findings_add MEDIUM HIGH verified "Identical password hashes reused across dataset entries" \
      "$dup_vals distinct hash value(s) appear across $dup_entries entries, indicating shared passwords or unsalted hash collisions." \
      "Enforce unique per-credential salts and require affected accounts to rotate shared passwords." \
      "dataset=${file##*/}; reused_hashes=$dup_vals; entries=$dup_entries" || true
  fi
  return 0
}

mod_hash_main() {
  local sub=${1:-}
  shift || true
  AN_MODULE="hash"
  case $sub in
    identify | analyze) session_run_check "hash:identify" "stdin_hash" "mode=single_hash" _hash_cmd_identify ;;
    policy-check) session_run_check "hash:policy-check" "stdin_hash" "profile=${AN_PROFILE:-default}" _hash_cmd_policy_check ;;
    policy-review) session_run_check "hash:policy-review" "profile:${AN_PROFILE:-default}" "allow_legacy=${AN_CFG[hash_allow_legacy]:-0};min_bcrypt=${AN_CFG[hash_min_bcrypt_cost]:-12};min_argon2_mib=${AN_CFG[hash_min_argon2_mib]:-19}" _hash_cmd_policy_review ;;
    check-file) session_run_check "hash:check-file" "dataset:${1:+${1##*/}}" "dataset=${1:+${1##*/}}" _hash_cmd_check_file "$@" ;;
    "" | help | -h | --help) _hash_usage ;;
    *) an_die "$EX_USAGE" "hash: unknown subcommand '$sub'" ;;
  esac
}

mod_hash_menu() {
  AN_MODULE="hash"
  local c f
  while :; do
    ui_banner
    printf '\n  HASH INTELLIGENCE ENGINE\n'
    ui_rule
    printf '  [1] Identify and analyze a hash (hidden input)\n'
    printf '  [2] Check a hash against the active policy\n'
    printf '  [3] Review the active hash policy profile\n'
    printf '  [4] Analyze a hash dataset file\n'
    printf '  [b] Back\n\n'
    read -r -p "Select: " c || return 0
    case $c in
      1) (session_run_check "hash:identify" "stdin_hash" "mode=single_hash" _hash_cmd_identify) || true; ui_pause ;;
      2) (session_run_check "hash:policy-check" "stdin_hash" "profile=${AN_PROFILE:-default}" _hash_cmd_policy_check) || true; ui_pause ;;
      3) (session_run_check "hash:policy-review" "profile:${AN_PROFILE:-default}" "allow_legacy=${AN_CFG[hash_allow_legacy]:-0}" _hash_cmd_policy_review) || true; ui_pause ;;
      4) read -r -p "Path to hash dataset file: " f || return 0; (session_run_check "hash:check-file" "dataset:${f##*/}" "dataset=${f##*/}" _hash_cmd_check_file "$f") || true; ui_pause ;;
      b | B | q | Q) return 0 ;;
      *) printf 'Invalid selection.\n' ;;
    esac
  done
}
