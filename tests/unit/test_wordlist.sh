#!/usr/bin/env bash
# shellcheck shell=bash disable=SC1091,SC2034
source "$(dirname "${BASH_SOURCE[0]}")/../lib/harness.sh"
sandbox
load_core
tmp_init
trap 'tmp_cleanup; rm -rf "$SB"' EXIT
WL="$TEST_ROOT/fixtures/sample-wordlist.txt"

# 1. Analyze fixture wordlist (10 lines, 2 duplicates: password x2, Summer2024! x2 => 8 unique)
wl_analyze_file "$WL" 12 128 0
assert_eq 10 "$WLA_TOTAL_LINES" "wordlist total lines = 10"
assert_eq 10 "$WLA_NONEMPTY" "wordlist non-empty = 10"
assert_eq 0 "$WLA_EMPTY" "wordlist empty = 0"
assert_eq 6 "$WLA_MIN_LEN" "wordlist min length = 6 (123456)"
assert_eq 28 "$WLA_MAX_LEN" "wordlist max length = 28 (correct-horse-battery-staple)"
assert_eq 8 "$WLA_UNIQUE" "wordlist unique entries = 8"
assert_eq 2 "$WLA_DUP_VALS" "wordlist reused values = 2"
assert_eq 4 "$WLA_DUP_ENTRIES" "wordlist duplicate entries = 4"
assert_eq "20.0" "$WLA_DUP_PCT" "wordlist duplicate percentage = 20.0%"
assert_eq "UTF-8" "$WLA_ENCODING" "wordlist encoding detects valid UTF-8 multibyte (pässwörd1234)"
assert_eq 1 "$WLA_UTF8_MULTIBYTE" "wordlist counts 1 UTF-8 multibyte entry"
assert_eq 5 "$WLA_POLICY_PASS" "wordlist policy pass count (len>=12) = 5"
assert_not_contains "$WLA_TOP_MASKS" "Summer" "top masks contain only abstract shape codes, never words"

# 2. CRLF, empty lines, and invalid high-byte detection
printf 'alpha123\r\nbeta1234\n\ngamma\xffdelta\nctrl\x07bell\n' >"$SB/mixed.txt"
wl_analyze_file "$SB/mixed.txt" 8 64 0
assert_eq 5 "$WLA_TOTAL_LINES" "mixed file total lines = 5"
assert_eq 4 "$WLA_NONEMPTY" "mixed file non-empty = 4"
assert_eq 1 "$WLA_EMPTY" "mixed file empty = 1"
assert_eq 1 "$WLA_CRLF_LINES" "mixed file detects 1 CRLF line"
assert_eq 1 "$WLA_HIGHBYTE_INVALID" "mixed file detects 1 invalid high-byte line"
assert_eq 1 "$WLA_CTRL_CHARS" "mixed file detects 1 control-char line"
assert_eq "MIXED/HIGH-BYTE" "$WLA_ENCODING" "mixed file encoding classified as MIXED/HIGH-BYTE"

# 3. Empty wordlist edge case
: >"$SB/empty.txt"
wl_analyze_file "$SB/empty.txt" 12 128 0
assert_eq 0 "$WLA_NONEMPTY" "empty file non-empty = 0"
assert_eq "EMPTY" "$WLA_ENCODING" "empty file encoding = EMPTY"

# 4. Wordlist comparison
printf 'alpha\nbeta\ngamma\ngamma\n' >"$SB/a.txt"
printf 'beta\r\ndelta\nepsilon\n' >"$SB/b.txt"
wl_compare_files "$SB/a.txt" "$SB/b.txt"
assert_eq 3 "$WLC_UNIQUE_A" "compare: distinct in A = 3"
assert_eq 3 "$WLC_UNIQUE_B" "compare: distinct in B = 3"
assert_eq 2 "$WLC_ONLY_A" "compare: only in A = 2"
assert_eq 2 "$WLC_ONLY_B" "compare: only in B = 2"
assert_eq 1 "$WLC_OVERLAP" "compare: overlap = 1 (beta, CRLF normalized)"
assert_eq "20.0" "$WLC_JACCARD_PCT" "compare: Jaccard = 1/5 = 20.0%"
assert_eq "33.3" "$WLC_COV_A_BY_B_PCT" "compare: coverage of A by B = 33.3%"

# 5. Wordlist cleaning & deduplication
wl_clean_file "$WL" "$SB/cleaned.txt" 8 64
assert_eq 10 "$WLCLEAN_IN" "clean: input non-empty = 10"
assert_eq 7 "$WLCLEAN_OUT" "clean: 7 unique entries >= 8 chars (123456 filtered, 2 dups removed)"
assert_eq 3 "$WLCLEAN_REMOVED" "clean: 3 entries removed"
assert_eq 600 "$(stat -c %a "$SB/cleaned.txt")" "clean: output file mode is 0600"

# 6. Large wordlist streaming performance & accuracy (25,000 lines)
LC_ALL=C awk 'BEGIN {
  for (i = 1; i <= 20000; i++) printf "CandidateWord_%06d!\n", i
  for (i = 1; i <= 5000; i++) printf "CandidateWord_%06d!\n", i
}' >"$SB/large.txt"
wl_analyze_file "$SB/large.txt" 12 128 0
assert_eq 25000 "$WLA_NONEMPTY" "large wordlist: 25,000 non-empty lines streamed"
assert_eq 20000 "$WLA_UNIQUE" "large wordlist: 20,000 unique entries identified"
assert_eq 5000 "$WLA_DUP_VALS" "large wordlist: 5,000 duplicated values identified"

t_summary
