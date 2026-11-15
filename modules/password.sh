#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034  # globals are shared across sourced files by design
# AUTHFORGE module: Password Security Engine (menu 02) -- Milestone 0 scope.
# Implemented: analyze, policy-check, policy-review, check-file, generate.
# Offline only. Passwords are read from a hidden prompt or stdin, never argv.

mod_password_info() { printf '02|Password Security Engine|Strength/entropy, common-password and policy analysis|partial'; }

_pw_dataset() { # prints resolved dataset path, or nothing if unavailable
  local p=${AN_CFG[common_passwords_file]}
  if [[ $p != /* ]]; then p="$AN_ROOT/$p"; fi
  if validate_regular_file "$p"; then printf '%s' "$p"; fi
  return 0
}

_pw_usage() {
  cat <<'USAGE'
Usage: authforge [global opts] password <subcommand> [args]

  analyze            Analyze one password (hidden prompt, or first line of stdin)
  policy-check       Check one password against the active policy profile
  policy-review      Review the active policy profile itself against guidance
  check-file FILE    Aggregate analysis of an authorized dataset (one secret per line)
  generate [-l N] [-n COUNT]   Generate random passwords (default 20 chars)

Passwords are never accepted as command-line arguments (they would leak via `ps`).
USAGE
}

_pw_read_one() { # <outvar> : reads one secret into the named variable
  local -n _dst=$1
  ui_read_secret _dst "Password (input hidden): " || an_die "$EX_VALIDATION" "no input"
  _dst=${_dst%$'\r'}
  if [[ -z $_dst ]]; then an_die "$EX_VALIDATION" "empty password"; fi
  if ((${#_dst} > 1024)); then an_die "$EX_VALIDATION" "input exceeds 1024 characters"; fi
  return 0
}

_pw_print_analysis() {
  local ds=$1
  printf 'Password analysis  (value is never displayed, logged or stored)\n'
  ui_rule
  printf '  %-22s %s\n' "Length" "$PWA_LEN"
  printf '  %-22s %s (pool size %d)\n' "Character classes" "$(pw_class_names)" "$PW_POOL"
  printf '  %-22s %s bits   [model: uniform random over class pool]\n' "Naive entropy" "$PWA_NAIVE"
  printf '  %-22s %s bits   [after pattern/dictionary penalties]\n' "Estimated entropy" "$PWA_EFF"
  printf '  %-22s %s   [heuristic]\n' "Rating" "$PWA_RATING"
  if ((PWA_DATASET_OK)); then
    printf '  %-22s %s   [dataset: %s]\n' "Common-password match" "$PWA_COMMON" "${ds##*/}"
  else
    printf '  %-22s %s\n' "Common-password match" "$(ui_status_badge 'NOT TESTED') dataset unavailable"
  fi
  if ((${#PW_PATTERNS[@]})); then
    printf '  %-22s %s\n' "Patterns detected" "${PW_PATTERNS[*]}"
  else
    printf '  %-22s none\n' "Patterns detected"
  fi
  ui_rule
  printf 'Entropy figures are estimates under documented assumptions (docs/entropy-model.md),\n'
  printf 'not a guarantee of resistance to any specific attack.\n'
  return 0
}

_pw_emit_analysis_findings() {
  local ds=$1
  case $PWA_COMMON in
    exact)
      findings_add HIGH HIGH verified "Password found in common-password dataset" \
        "The analyzed password is present (case-insensitive) in a local common-password list and would be guessed almost immediately." \
        "Reject this value; enforce a blocklist check at password creation and require a different secret." \
        "dataset=${ds##*/}; match=exact" || true ;;
    variant)
      findings_add MEDIUM MEDIUM heuristic "Password is a trivial variant of a common password" \
        "After lower-casing, leet-substitution or removing trailing digits/symbols the value matches a common-password entry." \
        "Reject predictable variants; encourage long passphrases rather than mangled dictionary words." \
        "dataset=${ds##*/}; match=variant" || true ;;
  esac
  local min=${AN_CFG[policy_min_entropy_bits]}
  if awk -v e="$PWA_EFF" -v m="$min" 'BEGIN{exit !(e<m)}'; then
    findings_add MEDIUM LOW heuristic "Estimated password entropy below policy threshold" \
      "Estimated ${PWA_EFF} bits is below the configured minimum of ${min} bits (heuristic estimate; see docs/entropy-model.md)." \
      "Increase length and avoid predictable patterns." || true
  fi
  return 0
}

_pw_cmd_analyze() {
  local pw ds
  _pw_read_one pw
  ds=$(_pw_dataset)
  pw_analyze "$pw" "$ds"
  unset pw
  _pw_print_analysis "$ds"
  _pw_emit_analysis_findings "$ds"
  return 0
}

_pw_rule() { # <PASS|FAIL|NOT TESTED> <text>
  printf '  %s %s\n' "$(ui_status_badge "$1")" "$2"
}

_pw_cmd_policy_check() {
  local pw ds fails=0 len classes
  _pw_read_one pw
  ds=$(_pw_dataset)
  pw_analyze "$pw" "$ds"
  unset pw
  len=$PWA_LEN classes=$PW_NCLASSES
  printf 'Policy check against profile: %s\n' "${AN_PROFILE:-default}"
  ui_rule
  local min=${AN_CFG[policy_min_length]} max=${AN_CFG[policy_max_length]} req=${AN_CFG[policy_require_classes]}

  if ((len >= 10#$min)); then _pw_rule PASS "minimum length >= $min"; else
    _pw_rule FAIL "minimum length >= $min (observed $len)"; fails=$((fails + 1))
    findings_add LOW HIGH verified "Password shorter than policy minimum" \
      "Observed length $len is below policy_min_length=$min." "Use a longer password or passphrase." \
      "rule=policy_min_length; required=$min; observed=$len" || true
  fi
  if ((len <= 10#$max)); then _pw_rule PASS "maximum length <= $max"; else
    _pw_rule FAIL "maximum length <= $max (observed $len)"; fails=$((fails + 1)); fi
  if ((classes >= req)); then _pw_rule PASS "character classes >= $req"; else
    _pw_rule FAIL "character classes >= $req (observed $classes)"; fails=$((fails + 1)); fi
  if [[ ${AN_CFG[policy_block_common]} == 1 ]]; then
    if ((!PWA_DATASET_OK)); then _pw_rule 'NOT TESTED' "common-password blocklist (dataset unavailable)"
    elif [[ $PWA_COMMON == none ]]; then _pw_rule PASS "not in common-password blocklist"
    else
      _pw_rule FAIL "in common-password blocklist ($PWA_COMMON match)"; fails=$((fails + 1))
      _pw_emit_analysis_findings "$ds"
    fi
  fi
  local me=${AN_CFG[policy_min_entropy_bits]}
  if awk -v e="$PWA_EFF" -v m="$me" 'BEGIN{exit !(e>=m)}'; then _pw_rule PASS "estimated entropy >= $me bits [heuristic]"; else
    _pw_rule FAIL "estimated entropy >= $me bits (est. $PWA_EFF) [heuristic]"; fails=$((fails + 1)); fi
  ui_rule
  printf 'Result: %d rule(s) failed\n' "$fails"
  return 0
}

# Review the policy parameters themselves (heuristic, guidance-based).
_pw_cmd_policy_review() {
  local min=${AN_CFG[policy_min_length]} max=${AN_CFG[policy_max_length]}
  local req=${AN_CFG[policy_require_classes]} blk=${AN_CFG[policy_block_common]}
  printf 'Policy review for profile: %s\n' "${AN_PROFILE:-default}"
  printf 'Guidance basis: NIST SP 800-63B principles + OWASP Authentication Cheat Sheet\n'
  printf '(control-level mappings with pinned versions arrive in Milestone 5)\n'
  ui_rule
  if ((10#$min < 8)); then
    _pw_rule FAIL "minimum length $min is below 8"
    findings_add HIGH MEDIUM heuristic "Minimum password length below commonly accepted floor" \
      "policy_min_length=$min; mainstream guidance sets 8 as an absolute floor and favours longer values." \
      "Raise the minimum length (12-15+ is common) and allow long passphrases." "setting=policy_min_length=$min" || true
  elif ((10#$min < 12)); then
    _pw_rule REVIEW "minimum length $min meets the floor but is modest"
    findings_add LOW LOW heuristic "Minimum password length is modest" \
      "policy_min_length=$min meets the 8-character floor; length is the dominant strength factor." \
      "Consider 12-15+ depending on whether MFA is enforced." "setting=policy_min_length=$min" || true
  else _pw_rule PASS "minimum length $min"; fi

  if ((10#$max < 64)); then
    _pw_rule FAIL "maximum length $max is below 64"
    findings_add LOW MEDIUM heuristic "Maximum password length restricts passphrases" \
      "policy_max_length=$max; guidance recommends permitting at least 64 characters." \
      "Allow at least 64 characters (no truncation)." "setting=policy_max_length=$max" || true
  else _pw_rule PASS "maximum length $max (>= 64)"; fi

  if ((req >= 3)); then
    _pw_rule REVIEW "composition rules ($req classes) may reduce usability without improving strength"
    findings_add INFO MEDIUM heuristic "Mandatory composition rules configured" \
      "policy_require_classes=$req; current guidance discourages composition rules in favour of length and blocklists." \
      "Prefer length requirements plus a breached/common-password blocklist." "setting=policy_require_classes=$req" || true
  else _pw_rule PASS "no heavy composition rules"; fi

  if [[ $blk == 1 ]]; then _pw_rule PASS "common-password blocklist enabled"; else
    _pw_rule FAIL "common-password blocklist disabled"
    findings_add MEDIUM HIGH verified "Common-password blocklist disabled in policy" \
      "policy_block_common=0, so known-weak passwords are not rejected at creation." \
      "Enable blocklist screening against a current local dataset." "setting=policy_block_common=0" || true
  fi
  return 0
}

_pw_cmd_check_file() {
  local file=${1:-}
  [[ -n $file ]] || an_die "$EX_USAGE" "check-file requires a FILE argument"
  validate_regular_file "$file" || an_die "$EX_VALIDATION" "not a readable regular file: $file"
  local mode
  mode=$(stat -c '%a' -- "$file")
  if [[ ${mode: -1} != 0 ]]; then log_warn "input file is world-accessible (mode $mode); restrict it"; fi

  local ds norm_file
  ds=$(_pw_dataset)
  norm_file=$(tmp_file)
  LC_ALL=C awk '{ sub(/\r$/, ""); if (length($0) > 0) print $0 }' "$file" >"$norm_file"

  printf 'Dataset analysis: %s  (secrets are never printed)\n' "${file##*/}"
  ui_rule

  local stats total vw w f s vs
  stats=$(LC_ALL=C awk '
    { n++; pool = 0
      if ($0 ~ /[a-z]/) pool += 26
      if ($0 ~ /[A-Z]/) pool += 26
      if ($0 ~ /[0-9]/) pool += 10
      if ($0 ~ /[^A-Za-z0-9]/) pool += 33
      b = length($0) * log(pool) / log(2)
      if (b < 28) a[0]++; else if (b < 36) a[1]++; else if (b < 60) a[2]++; else if (b < 128) a[3]++; else a[4]++ }
    END { printf "%d %d %d %d %d %d", n+0, a[0]+0, a[1]+0, a[2]+0, a[3]+0, a[4]+0 }' "$norm_file")
  read -r total vw w f s vs <<<"$stats"
  printf '  %-26s %s\n' "Non-empty entries" "$total"
  printf '  %-26s very weak=%s weak=%s fair=%s strong=%s very strong=%s\n' \
    "Naive entropy distribution" "$vw" "$w" "$f" "$s" "$vs"
  printf '  %-26s (character-class model only; no pattern analysis in batch mode)\n' ""

  local dup_vals dup_entries
  read -r dup_vals dup_entries < <(LC_ALL=C sort -T "$AN_TMPDIR" -- "$norm_file" | uniq -c | awk '$1>1{d++; e+=$1} END{print d+0, e+0}')
  printf '  %-26s %s distinct value(s) reused, covering %s entries\n' "Reuse/duplicates" "$dup_vals" "$dup_entries"

  local common=-1
  if [[ -n $ds ]]; then
    common=$(grep -Fixc -f "$ds" -- "$norm_file" || true)
    printf '  %-26s %s entries match %s\n' "Common-password matches" "$common" "${ds##*/}"
  else
    printf '  %-26s %s dataset unavailable\n' "Common-password matches" "$(ui_status_badge 'NOT TESTED')"
  fi
  rm -f -- "$norm_file"
  ui_rule

  if ((common > 0)); then
    findings_add HIGH HIGH verified "Dataset contains passwords from the common-password list" \
      "$common of $total entries match a known common password." \
      "Force resets for the affected accounts and enforce blocklist screening." \
      "dataset=${ds##*/}; matches=$common; total=$total" || true
  fi
  if ((dup_vals > 0)); then
    findings_add MEDIUM MEDIUM verified "Password reuse detected within the dataset" \
      "$dup_vals distinct password(s) are shared by $dup_entries entries; shared secrets amplify the impact of one compromise." \
      "Require unique passwords per account and consider reset campaigns for reused values." \
      "reused_values=$dup_vals; entries=$dup_entries" || true
  fi
  if ((vw + w > 0)); then
    findings_add MEDIUM LOW heuristic "Dataset contains low naive-entropy passwords" \
      "$((vw + w)) entries rate weak or very weak under the character-class model (heuristic)." \
      "Review with the single-password analyzer; enforce length-based policy." || true
  fi
  return 0
}

_pw_cmd_generate() {
  local len=20 count=1
  while (($#)); do
    case $1 in
      -l | --length) len=${2:-}; shift ;;
      -n | --count) count=${2:-}; shift ;;
      *) an_die "$EX_USAGE" "generate: unknown option $1" ;;
    esac
    shift
  done
  validate_uint "$len" 8 128 || an_die "$EX_VALIDATION" "length must be 8..128"
  validate_uint "$count" 1 50 || an_die "$EX_VALIDATION" "count must be 1..50"
  local i
  for ((i = 0; i < count; i++)); do pw_generate "$((10#$len))"; printf '\n'; done
  return 0
}

mod_password_main() {
  local sub=${1:-}
  shift || true
  AN_MODULE=password
  case $sub in
    analyze) session_run_check "password:analyze" "stdin_secret" "mode=single_password" _pw_cmd_analyze ;;
    policy-check) session_run_check "password:policy-check" "stdin_secret" "profile=${AN_PROFILE:-default}" _pw_cmd_policy_check ;;
    policy-review) session_run_check "password:policy-review" "profile:${AN_PROFILE:-default}" "min_len=${AN_CFG[policy_min_length]};max_len=${AN_CFG[policy_max_length]};classes=${AN_CFG[policy_require_classes]};block_common=${AN_CFG[policy_block_common]}" _pw_cmd_policy_review ;;
    check-file) session_run_check "password:check-file" "dataset:${1:+${1##*/}}" "dataset=${1:+${1##*/}}" _pw_cmd_check_file "$@" ;;
    generate) _pw_cmd_generate "$@" ;;
    "" | help | -h | --help) _pw_usage ;;
    *) an_die "$EX_USAGE" "password: unknown subcommand '$sub'" ;;
  esac
}

mod_password_menu() {
  AN_MODULE=password
  local c f
  while :; do
    ui_banner
    printf '\n  PASSWORD SECURITY ENGINE\n'
    ui_rule
    printf '  [1] Analyze a password (hidden input)\n'
    printf '  [2] Check a password against the active policy\n'
    printf '  [3] Review the active policy profile\n'
    printf '  [4] Analyze a password dataset file\n'
    printf '  [5] Generate a random password\n'
    printf '  [b] Back\n\n'
    read -r -p "Select: " c || return 0
    case $c in
      1) (session_run_check "password:analyze" "stdin_secret" "mode=single_password" _pw_cmd_analyze) || true; ui_pause ;;
      2) (session_run_check "password:policy-check" "stdin_secret" "profile=${AN_PROFILE:-default}" _pw_cmd_policy_check) || true; ui_pause ;;
      3) (session_run_check "password:policy-review" "profile:${AN_PROFILE:-default}" "min_len=${AN_CFG[policy_min_length]};max_len=${AN_CFG[policy_max_length]}" _pw_cmd_policy_review) || true; ui_pause ;;
      4) read -r -p "Path to dataset file: " f || return 0; (session_run_check "password:check-file" "dataset:${f##*/}" "dataset=${f##*/}" _pw_cmd_check_file "$f") || true; ui_pause ;;
      5) _pw_cmd_generate; ui_pause ;;
      b | B | q | Q) return 0 ;;
      *) printf 'Invalid selection.\n' ;;
    esac
  done
}
