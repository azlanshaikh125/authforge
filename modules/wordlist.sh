#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034  # globals are shared across sourced files by design
# AUTHFORGE module: Wordlist Analytics Engine (menu 04) -- Milestone 1.
# Implemented: analyze, compare, clean.
# Offline only. Streams large wordlists without printing or logging candidate secrets.

mod_wordlist_info() { printf '04|Wordlist Analytics Engine|Streaming statistics, encoding, deduplication and policy simulation|ready'; }

_wl_usage() {
  cat <<'USAGE'
Usage: authforge [global opts] wordlist <subcommand> [args]

  analyze FILE                          Streaming statistical, encoding, duplicate and policy report
  compare FILE1 FILE2                   Compute overlap and unique coverage between two wordlists
  clean FILE -o OUT [--min-length N] [--max-length M]
                                        Normalize (strip CRLF/control chars) and deduplicate into OUT (0600)

Wordlist entries are never displayed, logged, or stored in findings.
USAGE
}

_wl_check_input() { # <file>
  local f=$1
  validate_regular_file "$f" || an_die "$EX_VALIDATION" "not a readable regular file: $f"
  local mode
  mode=$(stat -c '%a' -- "$f")
  if [[ ${mode: -1} != 0 ]]; then log_warn "input file is world-accessible (mode $mode); restrict it"; fi
  return 0
}

_wl_cmd_analyze() {
  local file=${1:-}
  [[ -n $file ]] || an_die "$EX_USAGE" "analyze requires a FILE argument"
  _wl_check_input "$file"

  local p_min=${AN_CFG[policy_min_length]:-12}
  local p_max=${AN_CFG[policy_max_length]:-128}
  local p_req=${AN_CFG[policy_require_classes]:-0}
  local warn_dup=${AN_CFG[wordlist_warn_dup_pct]:-10}

  wl_analyze_file "$file" "$p_min" "$p_max" "$p_req"

  printf 'Wordlist intelligence report: %s  (entries are never printed)\n' "${file##*/}"
  ui_rule
  printf '  %-28s total=%s non-empty=%s empty=%s\n' "Line counts" "$WLA_TOTAL_LINES" "$WLA_NONEMPTY" "$WLA_EMPTY"
  printf '  %-28s min=%s max=%s avg=%s\n' "Length profile (chars)" "$WLA_MIN_LEN" "$WLA_MAX_LEN" "$WLA_AVG_LEN"
  printf '  %-28s <8=%s 8-11=%s 12-15=%s 16-23=%s >=24=%s\n' \
    "Length distribution" "$WLA_LEN_LT8" "$WLA_LEN_8_11" "$WLA_LEN_12_15" "$WLA_LEN_16_23" "$WLA_LEN_24P"
  printf '  %-28s lower=%s upper=%s digit=%s alnum=%s mixed=%s non-ascii=%s\n' \
    "Character composition" "$WLA_CLS_LOWER" "$WLA_CLS_UPPER" "$WLA_CLS_DIGIT" "$WLA_CLS_ALNUM" "$WLA_CLS_MIXED" "$WLA_CLS_NONASCII"
  printf '  %-28s %s (ASCII=%s UTF-8=%s high-byte=%s ctrl=%s)\n' \
    "Encoding profile" "$WLA_ENCODING" "$WLA_ASCII_ONLY" "$WLA_UTF8_MULTIBYTE" "$WLA_HIGHBYTE_INVALID" "$WLA_CTRL_CHARS"
  printf '  %-28s LF=%s CRLF=%s\n' "Line endings" "$WLA_LF_LINES" "$WLA_CRLF_LINES"
  printf '  %-28s unique=%s reused_values=%s duplicate_entries=%s (%s%% redundant)\n' \
    "Deduplication analysis" "$WLA_UNIQUE" "$WLA_DUP_VALS" "$WLA_DUP_ENTRIES" "$WLA_DUP_PCT"
  printf '  %-28s %s of %s (%s%%) satisfy profile %s (len %s..%s, classes>=%s)\n' \
    "Policy pass-rate" "$WLA_POLICY_PASS" "$WLA_NONEMPTY" "$WLA_POLICY_PCT" "${AN_PROFILE:-default}" "$p_min" "$p_max" "$p_req"
  printf '  %-28s %s\n' "Top structural shapes" "$WLA_TOP_MASKS"
  ui_rule

  if ((WLA_NONEMPTY == 0)); then
    findings_add LOW HIGH verified "Wordlist contains no usable entries" \
      "File ${file##*/} has 0 non-empty entries ($WLA_TOTAL_LINES total lines)." \
      "Populate the wordlist with valid candidate entries before running assessments." \
      "file=${file##*/}; non_empty=0; total_lines=$WLA_TOTAL_LINES" || true
    return 0
  fi

  if awk -v dp="$WLA_DUP_PCT" -v th="$warn_dup" 'BEGIN{exit !(dp >= th && dp > 0)}'; then
    findings_add LOW HIGH verified "Wordlist contains significant duplicate entries" \
      "${file##*/} has ${WLA_DUP_PCT}% redundant lines ($WLA_DUP_VALS distinct value(s) repeated across $WLA_DUP_ENTRIES entries; threshold ${warn_dup}%)." \
      "Run 'authforge wordlist clean' to deduplicate the list and avoid wasted candidate evaluations." \
      "file=${file##*/}; unique=$WLA_UNIQUE; non_empty=$WLA_NONEMPTY; dup_pct=$WLA_DUP_PCT" || true
  fi

  if ((WLA_CRLF_LINES > 0 && WLA_LF_LINES > 0)); then
    findings_add LOW HIGH verified "Wordlist has inconsistent mixed CRLF/LF line endings" \
      "${file##*/} mixes $WLA_CRLF_LINES CRLF line(s) and $WLA_LF_LINES LF line(s), which causes trailing-CR mismatches in tools that do not strip CR." \
      "Normalize line endings with 'authforge wordlist clean'." \
      "file=${file##*/}; crlf=$WLA_CRLF_LINES; lf=$WLA_LF_LINES" || true
  elif ((WLA_CRLF_LINES > 0)); then
    findings_add INFO HIGH verified "Wordlist uses Windows CRLF line endings" \
      "${file##*/} uses CRLF line endings ($WLA_CRLF_LINES lines); some Unix tools treat trailing CR as part of the password." \
      "Convert to LF line endings with 'authforge wordlist clean'." \
      "file=${file##*/}; crlf=$WLA_CRLF_LINES" || true
  fi

  if ((WLA_HIGHBYTE_INVALID > 0 || WLA_CTRL_CHARS > 0)); then
    findings_add LOW HIGH verified "Wordlist contains non-UTF-8 high bytes or control characters" \
      "${file##*/} has $WLA_HIGHBYTE_INVALID invalid/Latin-1 high-byte line(s) and $WLA_CTRL_CHARS line(s) with ASCII control characters." \
      "Inspect encoding (e.g. ISO-8859-1 vs UTF-8) and sanitize with 'authforge wordlist clean'." \
      "file=${file##*/}; high_byte=$WLA_HIGHBYTE_INVALID; ctrl=$WLA_CTRL_CHARS" || true
  fi

  if ((WLA_POLICY_PASS == 0)); then
    findings_add INFO HIGH verified "Wordlist has zero coverage for active password policy" \
      "0 of $WLA_NONEMPTY entries in ${file##*/} meet the active profile requirements (min_length=$p_min, max_length=$p_max, classes>=$p_req)." \
      "Use a passphrase or long-candidate wordlist matching the target policy length floor ($p_min+ chars)." \
      "file=${file##*/}; policy_pass=0; policy_min_length=$p_min" || true
  fi
  return 0
}

_wl_cmd_compare() {
  local f1=${1:-} f2=${2:-}
  [[ -n $f1 && -n $f2 ]] || an_die "$EX_USAGE" "compare requires FILE1 and FILE2 arguments"
  _wl_check_input "$f1"
  _wl_check_input "$f2"

  wl_compare_files "$f1" "$f2"

  printf 'Wordlist comparison: %s vs %s  (entries are never printed)\n' "${f1##*/}" "${f2##*/}"
  ui_rule
  printf '  %-28s %s\n' "Distinct entries in A" "$WLC_UNIQUE_A"
  printf '  %-28s %s\n' "Distinct entries in B" "$WLC_UNIQUE_B"
  printf '  %-28s %s\n' "Entries only in A" "$WLC_ONLY_A"
  printf '  %-28s %s\n' "Entries only in B" "$WLC_ONLY_B"
  printf '  %-28s %s\n' "Shared entries (overlap)" "$WLC_OVERLAP"
  printf '  %-28s %s%%\n' "Coverage of A by B" "$WLC_COV_A_BY_B_PCT"
  printf '  %-28s %s%%\n' "Jaccard similarity" "$WLC_JACCARD_PCT"
  ui_rule
  return 0
}

_wl_cmd_clean() {
  local infile=${1:-} out="" min_l=1 max_l=1024
  [[ -n $infile && $infile != -* ]] || an_die "$EX_USAGE" "clean requires an input FILE and -o OUTPUT"
  shift
  while (($#)); do
    case $1 in
      -o | --output) out=${2:-}; shift ;;
      --min-length) min_l=${2:-}; shift ;;
      --max-length) max_l=${2:-}; shift ;;
      *) an_die "$EX_USAGE" "clean: unknown option $1" ;;
    esac
    shift
  done
  [[ -n $out ]] || an_die "$EX_USAGE" "clean requires -o OUTPUT"
  _wl_check_input "$infile"
  validate_uint "$min_l" 1 1024 || an_die "$EX_VALIDATION" "min-length must be 1..1024"
  validate_uint "$max_l" 1 1024 || an_die "$EX_VALIDATION" "max-length must be 1..1024"
  if ((10#$min_l > 10#$max_l)); then an_die "$EX_VALIDATION" "min-length exceeds max-length"; fi
  [[ ! -e $out ]] || an_die "$EX_VALIDATION" "refusing to overwrite existing file: $out"

  wl_clean_file "$infile" "$out" "$((10#$min_l))" "$((10#$max_l))"
  printf 'Cleaned wordlist written to %s (mode 0600)\n' "$out"
  printf '  Input non-empty entries : %s\n' "$WLCLEAN_IN"
  printf '  Output unique entries   : %s\n' "$WLCLEAN_OUT"
  printf '  Removed (dups/filtered) : %s\n' "$WLCLEAN_REMOVED"
  return 0
}

mod_wordlist_main() {
  local sub=${1:-}
  shift || true
  AN_MODULE=wordlist
  case $sub in
    analyze) _wl_cmd_analyze "$@" ;;
    compare) _wl_cmd_compare "$@" ;;
    clean) _wl_cmd_clean "$@" ;;
    "" | help | -h | --help) _wl_usage ;;
    *) an_die "$EX_USAGE" "wordlist: unknown subcommand '$sub'" ;;
  esac
}

mod_wordlist_menu() {
  AN_MODULE=wordlist
  local c f1 f2 out
  while :; do
    ui_banner
    printf '\n  WORDLIST ANALYTICS ENGINE\n'
    ui_rule
    printf '  [1] Analyze a wordlist file\n'
    printf '  [2] Compare two wordlist files\n'
    printf '  [3] Clean and deduplicate a wordlist\n'
    printf '  [b] Back\n\n'
    read -r -p "Select: " c || return 0
    case $c in
      1) read -r -p "Path to wordlist file: " f1 || return 0; (_wl_cmd_analyze "$f1") || true; ui_pause ;;
      2)
        read -r -p "Path to first wordlist (A): " f1 || return 0
        read -r -p "Path to second wordlist (B): " f2 || return 0
        (_wl_cmd_compare "$f1" "$f2") || true
        ui_pause ;;
      3)
        read -r -p "Path to input wordlist: " f1 || return 0
        read -r -p "Path to output file: " out || return 0
        (_wl_cmd_clean "$f1" -o "$out") || true
        ui_pause ;;
      b | B | q | Q) return 0 ;;
      *) printf 'Invalid selection.\n' ;;
    esac
  done
}
