#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034  # globals are shared across sourced files by design
# AUTHFORGE lib: password analysis primitives.
#
# SECURITY: password values are only ever handled in shell variables and
# builtin printf / stdin pipes. They are NEVER placed on a command line
# (visible via `ps`), written to logs, findings or reports. The entropy
# model and its assumptions are documented in docs/entropy-model.md.
[[ -n "${_AN_PWDCHECK:-}" ]] && return 0
_AN_PWDCHECK=1
shopt -s extglob

readonly PW_SYMBOLS='!"#$%&'"'"'()*+,-./:;<=>?@[\]^_`{|}~'
readonly -a PW_KEY_ROWS=(qwertyuiop asdfghjkl zxcvbnm poiuytrewq lkjhgfdsa mnbvcxz)

# Fixed "attacker cost" (bits) charged for each detected pattern instance.
readonly PW_BITS_REPEAT=2 PW_BITS_SEQUENCE=4 PW_BITS_KEYWALK=6 PW_BITS_SUFFIX=7
# Caps applied when dictionary evidence exists.
readonly PW_CAP_EXACT=20 PW_CAP_VARIANT=28

PW_LOWER=0 PW_UPPER=0 PW_DIGIT=0 PW_SYMBOL=0 PW_OTHER=0 PW_NCLASSES=0 PW_POOL=0
declare -a PW_PATTERNS=()
PW_PAT_COVERED=0 PW_PAT_BITS=0
PWA_LEN=0 PWA_NAIVE=0 PWA_EFF=0 PWA_COMMON=none PWA_RATING="" PWA_DATASET_OK=0

pw_classes() { # <pw> -> sets PW_* class flags, PW_NCLASSES, PW_POOL
  local pw=$1 i c
  PW_LOWER=0 PW_UPPER=0 PW_DIGIT=0 PW_SYMBOL=0 PW_OTHER=0
  for ((i = 0; i < ${#pw}; i++)); do
    c=${pw:i:1}
    case $c in
      [a-z]) PW_LOWER=1 ;;
      [A-Z]) PW_UPPER=1 ;;
      [0-9]) PW_DIGIT=1 ;;
      *) if [[ $PW_SYMBOLS == *"$c"* ]]; then PW_SYMBOL=1; else PW_OTHER=1; fi ;;
    esac
  done
  PW_NCLASSES=$((PW_LOWER + PW_UPPER + PW_DIGIT + PW_SYMBOL + PW_OTHER))
  PW_POOL=$((PW_LOWER * 26 + PW_UPPER * 26 + PW_DIGIT * 10 + PW_SYMBOL * 33 + PW_OTHER * 100))
  return 0
}

pw_class_names() {
  local out=""
  if ((PW_LOWER)); then out+="lower "; fi
  if ((PW_UPPER)); then out+="upper "; fi
  if ((PW_DIGIT)); then out+="digit "; fi
  if ((PW_SYMBOL)); then out+="symbol "; fi
  if ((PW_OTHER)); then out+="other "; fi
  printf '%s' "${out% }"
}

_pw_ord() { printf -v "$1" '%d' "'$2"; }

# pw_find_patterns <pw> -> PW_PATTERNS[], PW_PAT_COVERED, PW_PAT_BITS
# Uses a per-index coverage array so overlapping patterns never double-subtract
# character positions from password length.
pw_find_patterns() {
  local pw=$1 n=${#1} i j m run c a b d prevd lower best k row sub
  local -a cov=()
  PW_PATTERNS=() PW_PAT_COVERED=0 PW_PAT_BITS=0

  # 1) runs of one repeated character (>= 3)
  i=0
  while ((i < n)); do
    c=${pw:i:1} run=1
    while ((i + run < n)) && [[ ${pw:i+run:1} == "$c" ]]; do run=$((run + 1)); done
    if ((run >= 3)); then
      PW_PATTERNS+=("repeat:$run")
      for ((m = i; m < i + run; m++)); do cov[m]=1; done
      PW_PAT_BITS=$((PW_PAT_BITS + PW_BITS_REPEAT))
    fi
    i=$((i + run))
  done

  # 2) alphanumeric ascending/descending sequences (>= 4), e.g. abcd, 4321
  i=0
  while ((i < n - 1)); do
    c=${pw:i:1}
    if [[ ! $c =~ ^[A-Za-z0-9]$ ]]; then i=$((i + 1)); continue; fi
    _pw_ord a "$c"
    j=$((i + 1)) prevd=0
    while ((j < n)); do
      c=${pw:j:1}
      [[ $c =~ ^[A-Za-z0-9]$ ]] || break
      _pw_ord b "$c"
      d=$((b - a))
      if ((d != 1 && d != -1)); then break; fi
      if ((prevd != 0 && d != prevd)); then break; fi
      prevd=$d a=$b j=$((j + 1))
    done
    run=$((j - i))
    if ((run >= 4)); then
      PW_PATTERNS+=("sequence:$run")
      for ((m = i; m < j; m++)); do cov[m]=1; done
      PW_PAT_BITS=$((PW_PAT_BITS + PW_BITS_SEQUENCE))
      i=$j
    else
      i=$((i + 1))
    fi
  done

  # 3) keyboard walks along a row (>= 4), either direction
  lower=${pw,,}
  i=0
  while ((i < n)); do
    best=0
    for row in "${PW_KEY_ROWS[@]}"; do
      for ((k = 4; i + k <= n; k++)); do
        sub=${lower:i:k}
        if [[ $row == *"$sub"* ]]; then
          if ((k > best)); then best=$k; fi
        else
          break
        fi
      done
    done
    if ((best >= 4)); then
      PW_PATTERNS+=("keywalk:$best")
      for ((m = i; m < i + best; m++)); do cov[m]=1; done
      PW_PAT_BITS=$((PW_PAT_BITS + PW_BITS_KEYWALK))
      i=$((i + best))
    else
      i=$((i + 1))
    fi
  done

  # 4) "word + year/digits (+ symbol)" suffix
  if [[ $pw =~ ^(.{2,}[^0-9])((19|20)[0-9]{2}|[0-9]{1,4})([[:punct:]]?)$ ]]; then
    local slen=$((${#BASH_REMATCH[2]} + ${#BASH_REMATCH[4]}))
    local sstart=$((n - slen))
    PW_PATTERNS+=("suffix:$slen")
    for ((m = sstart; m < n; m++)); do cov[m]=1; done
    PW_PAT_BITS=$((PW_PAT_BITS + PW_BITS_SUFFIX))
  fi
  PW_PAT_COVERED=${#cov[@]}
  if ((PW_PAT_COVERED > n)); then PW_PAT_COVERED=$n; fi
  return 0
}

pw_normalize_leet() {
  local s=${1,,}
  s=${s//@/a} s=${s//4/a} s=${s//3/e} s=${s//0/o} s=${s//5/s}
  s=${s//7/t} s=${s//\$/s} s=${s//!/i} s=${s//1/l}
  printf '%s' "$s"
}

# Exact (case-insensitive) membership; password goes via stdin, never argv.
pw_dataset_has() { # <pw> <dataset-file>
  [[ -n $1 ]] || return 1
  printf '%s\n' "$1" | grep -Fixq -f - -- "$2"
}

# pw_common_match <pw> <dataset> -> prints none|exact|variant
pw_common_match() {
  local pw=$1 ds=$2 lower norm cand
  if pw_dataset_has "$pw" "$ds"; then printf 'exact'; return 0; fi
  lower=${pw,,}
  # 1) Strip all trailing digits/punctuation before leet normalization (e.g. P@ssw0rd!)
  local stripped=${lower%%+([0-9[:punct:]])}
  # 2) Strip trailing digits & non-leet punctuation (preserving $ and @ in root, e.g. pa$$2024!)
  local leet_root=${lower%%+([0-9!#%^&*()_+=.,?/-])}
  local leet_root_norm
  leet_root_norm=$(pw_normalize_leet "$leet_root")
  norm=$(pw_normalize_leet "$pw")
  local norm_stripped=${norm%%+([0-9[:punct:]])}
  for cand in "$lower" "$stripped" "$norm" "$(pw_normalize_leet "$stripped")" "$leet_root_norm" "${leet_root_norm%%+([0-9])}" "$norm_stripped"; do
    if [[ -n $cand && ${#cand} -ge 3 && $cand != "$pw" ]] && pw_dataset_has "$cand" "$ds"; then
      printf 'variant'
      return 0
    fi
  done
  printf 'none'
}

pw_rating() { # <bits> -> label (thresholds documented in docs/entropy-model.md)
  local b=${1%.*}
  if ((b < 28)); then printf 'very weak'
  elif ((b < 36)); then printf 'weak'
  elif ((b < 60)); then printf 'fair'
  elif ((b < 128)); then printf 'strong'
  else printf 'very strong'
  fi
}

# pw_analyze <pw> <dataset-or-empty> -> sets PWA_* (and PW_* from sub-steps)
pw_analyze() {
  local pw=$1 ds=${2:-}
  PWA_LEN=${#pw}
  pw_classes "$pw"
  pw_find_patterns "$pw"
  PWA_COMMON=none PWA_DATASET_OK=0
  local cap=0
  if [[ -n $ds && -r $ds ]]; then
    PWA_DATASET_OK=1
    PWA_COMMON=$(pw_common_match "$pw" "$ds")
    case $PWA_COMMON in
      exact) cap=$PW_CAP_EXACT ;;
      variant) cap=$PW_CAP_VARIANT ;;
    esac
  fi
  local out
  out=$(awk -v len="$PWA_LEN" -v pool="$PW_POOL" -v cov="$PW_PAT_COVERED" \
    -v pb="$PW_PAT_BITS" -v cap="$cap" 'BEGIN{
      l2=log(pool)/log(2); naive=len*l2
      eff=(len-cov)*l2+pb; if (eff>naive) eff=naive
      if (cap>0 && eff>cap) eff=cap
      printf "%.1f %.1f", naive, eff }')
  PWA_NAIVE=${out% *}
  PWA_EFF=${out#* }
  PWA_RATING=$(pw_rating "$PWA_EFF")
  return 0
}

# pw_generate <length> -> prints a random password containing all 4 ASCII
# classes. tr -dc over /dev/urandom filters bytes, so selection is unbiased.
pw_generate() {
  local len=$1 pw=""
  local set='A-Za-z0-9!@#%^&*()_=+.,?-'
  while :; do
    pw=$(LC_ALL=C tr -dc "$set" </dev/urandom | head -c "$len" || true)
    ((${#pw} == len)) || continue
    [[ $pw == *[a-z]* && $pw == *[A-Z]* && $pw == *[0-9]* && $pw == *[^A-Za-z0-9]* ]] && break
  done
  printf '%s' "$pw"
}
