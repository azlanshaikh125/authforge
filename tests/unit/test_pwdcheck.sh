#!/usr/bin/env bash
# shellcheck shell=bash disable=SC1091,SC2034
source "$(dirname "${BASH_SOURCE[0]}")/../lib/harness.sh"
sandbox
load_core
DS="$TEST_ROOT/fixtures/common-passwords-sample.txt"

pw_classes 'abcDEF123!'; assert_eq 95 "$PW_POOL" "pool: lower+upper+digit+symbol = 95"
pw_classes 'abc'; assert_eq 26 "$PW_POOL" "pool: lowercase only = 26"
pw_classes '1234'; assert_eq "1/10" "$PW_NCLASSES/$PW_POOL" "pool: digits only (1 class, pool 10)"
pw_classes 'pässword'; assert_eq 1 "$PW_OTHER" "non-ASCII char flagged as 'other' class"

pat() { pw_find_patterns "$1"; printf '%s' "${PW_PATTERNS[*]}"; }
assert_eq "repeat:6" "$(pat 'xaaaaaay' | tr -d ' ' | sed 's/^.*\(repeat:6\).*$/\1/')" "detects repeated-character run"
assert_contains "$(pat 'abcd9Zq')" "sequence:4" "detects ascending sequence abcd"
assert_contains "$(pat 'Q8432178')" "sequence:" "detects descending sequence 4321 (or 321/ 8432 region)"
assert_contains "$(pat 'xqwertyx')" "keywalk:" "detects keyboard walk qwerty"
assert_contains "$(pat 'Summer2024!')" "suffix:5" "detects word+year+symbol suffix"
assert_eq "" "$(pat 'Zx9#kQ2!vLp7@wMn')" "no patterns in random string"
assert_not_contains "$(pat 'ab12')" "sequence" "short runs (<4) not flagged"

# B-4 regression: overlapping patterns (sequence:4 inside suffix:5 on Summer1234!)
pw_find_patterns 'Summer1234!'
assert_eq 5 "$PW_PAT_COVERED" "REGRESSION B-4: overlapping sequence+suffix covers 5 unique positions, not 9"

assert_eq exact "$(pw_common_match 'PassWord' "$DS")" "common: case-insensitive exact match"
assert_eq variant "$(pw_common_match 'P@ssw0rd!' "$DS")" "common: leet variant caught (@ and 0)"
assert_eq variant "$(pw_common_match 'Summer2024!' "$DS")" "common: word + digits/symbol suffix caught"
assert_eq none "$(pw_common_match 'Zx9#kQ2!vLp7@wMn' "$DS")" "common: random string is clean"
assert_eq none "$(pw_common_match 'a1' "$DS")" "common: too-short stripped candidates ignored"

# B-3 regression: leet symbol ($) at end of root word followed by digits/punctuation
printf 'pass\nadmin\n' >"$SB/custom-ds.txt"
assert_eq variant "$(pw_common_match 'pa$$2024!' "$SB/custom-ds.txt")" "REGRESSION B-3: leet-symbol root pa\$\$2024! matches pass"
assert_eq variant "$(pw_common_match 'adm!n99!' "$SB/custom-ds.txt")" "REGRESSION B-3: leet root adm!n99! matches admin"

pw_analyze 'Zx9#kQ2!vLp7@wMn' "$DS"
assert_eq "$PWA_NAIVE" "$PWA_EFF" "random string: effective == naive entropy"
assert_eq strong "$PWA_RATING" "random 16-char mixed string rated strong"
pw_analyze 'password' "$DS"
assert_eq "20.0" "$PWA_EFF" "exact common password capped at 20 bits"
assert_eq "very weak" "$PWA_RATING" "common password rated very weak"
pw_analyze 'Summer2024!' "$DS"
assert_eq "28.0" "$PWA_EFF" "variant capped at 28 bits"
pw_analyze 'aaaaaaaaaaaa' ""
assert_eq 0 "$PWA_DATASET_OK" "missing dataset => dataset check marked not-run"
awk -v e="$PWA_EFF" 'BEGIN{exit !(e<10)}' && t_ok "repeated chars heavily penalised ($PWA_EFF bits)" || t_fail "repeat penalty ($PWA_EFF)"

assert_eq "very weak" "$(pw_rating 27.9)" "rating boundary <28"
assert_eq weak "$(pw_rating 28.0)" "rating boundary 28"
assert_eq fair "$(pw_rating 36)" "rating boundary 36"
assert_eq strong "$(pw_rating 60)" "rating boundary 60"
assert_eq "very strong" "$(pw_rating 128)" "rating boundary 128"

g=$(pw_generate 24)
assert_eq 24 "${#g}" "generated password has requested length"
[[ $g == *[a-z]* && $g == *[A-Z]* && $g == *[0-9]* && $g == *[^A-Za-z0-9]* ]] && t_ok "generated password contains all four classes" || t_fail "generated classes"
g2=$(pw_generate 24)
[[ $g != "$g2" ]] && t_ok "two generated passwords differ" || t_fail "generated passwords differ"
# crude uniformity sanity: 4000 chars drawn, expect every class represented
big=$(for _ in $(seq 1 200); do pw_generate 20; done)
[[ $big == *[a-z]* && $big == *[0-9]* && $big == *'!'* && $big == *'-'* ]] && t_ok "generator emits full charset over 4000 chars" || t_fail "generator charset coverage"

t_summary
