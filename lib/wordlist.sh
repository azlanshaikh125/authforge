#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034  # globals are shared across sourced files by design
# AUTHFORGE lib: streaming wordlist analytics, comparison, and cleaning primitives.
#
# SECURITY & PERFORMANCE: Wordlists can contain millions of entries and sensitive
# candidate secrets. Processing uses single-pass LC_ALL=C awk and external sort
# with private temp directories ($AN_TMPDIR). Individual words are NEVER read into
# Bash arrays, passed on argv, or printed to stdout, stderr, logs, or findings.
[[ -n "${_AN_WORDLIST:-}" ]] && return 0
_AN_WORDLIST=1

WLA_TOTAL_LINES=0
WLA_NONEMPTY=0
WLA_EMPTY=0
WLA_MIN_LEN=0
WLA_MAX_LEN=0
WLA_AVG_LEN="0.0"
WLA_LEN_LT8=0
WLA_LEN_8_11=0
WLA_LEN_12_15=0
WLA_LEN_16_23=0
WLA_LEN_24P=0
WLA_CLS_LOWER=0
WLA_CLS_UPPER=0
WLA_CLS_DIGIT=0
WLA_CLS_ALNUM=0
WLA_CLS_MIXED=0
WLA_CLS_NONASCII=0
WLA_CRLF_LINES=0
WLA_LF_LINES=0
WLA_ASCII_ONLY=0
WLA_UTF8_MULTIBYTE=0
WLA_HIGHBYTE_INVALID=0
WLA_CTRL_CHARS=0
WLA_ENCODING="EMPTY"
WLA_POLICY_PASS=0
WLA_POLICY_PCT="0.0"
WLA_UNIQUE=0
WLA_DUP_VALS=0
WLA_DUP_ENTRIES=0
WLA_DUP_PCT="0.0"
WLA_TOP_MASKS="none"

WLC_UNIQUE_A=0
WLC_UNIQUE_B=0
WLC_ONLY_A=0
WLC_ONLY_B=0
WLC_OVERLAP=0
WLC_JACCARD_PCT="0.0"
WLC_COV_A_BY_B_PCT="0.0"

WLCLEAN_IN=0
WLCLEAN_OUT=0
WLCLEAN_REMOVED=0

# Streaming single-pass analysis + external sort deduplication check.
# Compatible with both mawk and gawk.
wl_analyze_file() { # <file> [min_len] [max_len] [req_classes]
  local file=$1
  local p_min=${2:-${AN_CFG[policy_min_length]:-12}}
  local p_max=${3:-${AN_CFG[policy_max_length]:-128}}
  local p_req=${4:-${AN_CFG[policy_require_classes]:-0}}

  local norm_file mask_file awk_out
  norm_file=$(tmp_file)
  mask_file=$(tmp_file)

  awk_out=$(LC_ALL=C awk \
    -v p_min="$p_min" -v p_max="$p_max" -v p_req="$p_req" \
    -v norm_out="$norm_file" -v mask_out="$mask_file" '
    {
      total++
      has_cr = 0
      if (substr($0, length($0), 1) == "\r") {
        has_cr = 1
        crlf++
        sub(/\r$/, "")
      } else {
        lf++
      }
      len = length($0)
      if (len == 0) {
        empty++
        next
      }
      nonempty++
      print $0 > norm_out

      sum_len += len
      if (nonempty == 1 || len < min_l) min_l = len
      if (len > max_l) max_l = len

      if (len < 8) b_lt8++
      else if (len <= 11) b_8_11++
      else if (len <= 15) b_12_15++
      else if (len <= 23) b_16_23++
      else b_24p++

      # Character classes & encoding inspection
      has_l = ($0 ~ /[a-z]/) ? 1 : 0
      has_u = ($0 ~ /[A-Z]/) ? 1 : 0
      has_d = ($0 ~ /[0-9]/) ? 1 : 0
      has_s = ($0 ~ /[!"#$%&'\''()*+,\-.\/:;<=>?@\[\\\]^_`{|}~]/) ? 1 : 0
      has_hi = ($0 ~ /[\200-\377]/) ? 1 : 0
      has_ct = ($0 ~ /[\001-\010\013\014\016-\037\177]/) ? 1 : 0

      if (has_ct) ctrl++
      if (!has_hi) {
        ascii_only++
      } else {
        # Basic structural check for valid UTF-8 multibyte vs raw Latin-1/binary high bytes
        if ($0 ~ /([\302-\337][\200-\277]|[\340-\357][\200-\277][\200-\277]|[\360-\364][\200-\277][\200-\277][\200-\277])/) {
          utf8_mb++
        } else {
          hi_inv++
        }
      }

      ncls = has_l + has_u + has_d + has_s + has_hi
      if (has_hi) cls_nonascii++
      else if (has_l && !has_u && !has_d && !has_s) cls_lower++
      else if (!has_l && has_u && !has_d && !has_s) cls_upper++
      else if (!has_l && !has_u && has_d && !has_s) cls_digit++
      else if ((has_l || has_u) && has_d && !has_s) cls_alnum++
      else cls_mixed++

      if (len >= p_min && len <= p_max && ncls >= p_req) pol_pass++

      # Abstract structural shape (never stores the word itself, only class transitions)
      shape = ""
      if (has_l) shape = shape "L"
      if (has_u) shape = shape "U"
      if (has_d) shape = shape "D"
      if (has_s) shape = shape "S"
      if (has_hi) shape = shape "X"
      bkt = (len < 8) ? "<8" : ((len <= 11) ? "8-11" : ((len <= 15) ? "12-15" : "16+"))
      shapes[shape ":" bkt]++
    }
    END {
      if (nonempty == 0) {
        min_l = 0; max_l = 0; avg_l = 0.0; pol_pct = 0.0; enc = "EMPTY"
      } else {
        avg_l = sum_len / nonempty
        pol_pct = (pol_pass * 100.0) / nonempty
        if (hi_inv > 0) enc = "MIXED/HIGH-BYTE"
        else if (utf8_mb > 0) enc = "UTF-8"
        else enc = "ASCII"
      }
      for (k in shapes) {
        printf "%d %s\n", shapes[k], k > mask_out
      }
      printf "%d|%d|%d|%d|%d|%.1f|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%s|%d|%.1f\n", \
        total+0, nonempty+0, empty+0, min_l+0, max_l+0, avg_l, \
        b_lt8+0, b_8_11+0, b_12_15+0, b_16_23+0, b_24p+0, \
        cls_lower+0, cls_upper+0, cls_digit+0, cls_alnum+0, cls_mixed+0, cls_nonascii+0, \
        crlf+0, lf+0, ascii_only+0, utf8_mb+0, hi_inv+0, ctrl+0, enc, pol_pass+0, pol_pct
    }' "$file")

  IFS='|' read -r \
    WLA_TOTAL_LINES WLA_NONEMPTY WLA_EMPTY WLA_MIN_LEN WLA_MAX_LEN WLA_AVG_LEN \
    WLA_LEN_LT8 WLA_LEN_8_11 WLA_LEN_12_15 WLA_LEN_16_23 WLA_LEN_24P \
    WLA_CLS_LOWER WLA_CLS_UPPER WLA_CLS_DIGIT WLA_CLS_ALNUM WLA_CLS_MIXED WLA_CLS_NONASCII \
    WLA_CRLF_LINES WLA_LF_LINES WLA_ASCII_ONLY WLA_UTF8_MULTIBYTE WLA_HIGHBYTE_INVALID WLA_CTRL_CHARS \
    WLA_ENCODING WLA_POLICY_PASS WLA_POLICY_PCT <<<"$awk_out"

  if [[ -s $mask_file ]]; then
    WLA_TOP_MASKS=$(LC_ALL=C sort -rn "$mask_file" | head -n 3 | awk '{printf "%s%s(%d)", (NR>1?", ":""), $2, $1}')
  else
    WLA_TOP_MASKS="none"
  fi

  if ((WLA_NONEMPTY > 0)) && [[ -s $norm_file ]]; then
    read -r WLA_UNIQUE WLA_DUP_VALS WLA_DUP_ENTRIES < <(
      LC_ALL=C sort -T "$AN_TMPDIR" -- "$norm_file" | uniq -c |
        awk '{u++; if ($1>1){d++; e+=$1}} END{printf "%d %d %d\n", u+0, d+0, e+0}'
    )
    WLA_DUP_PCT=$(awk -v n="$WLA_NONEMPTY" -v u="$WLA_UNIQUE" 'BEGIN{printf "%.1f", ((n-u)*100.0)/n}')
  else
    WLA_UNIQUE=0 WLA_DUP_VALS=0 WLA_DUP_ENTRIES=0 WLA_DUP_PCT="0.0"
  fi

  rm -f -- "$norm_file" "$mask_file"
  return 0
}

# Streaming comparison of two wordlists using sorted unique streams in $AN_TMPDIR.
wl_compare_files() { # <fileA> <fileB>
  local fa=$1 fb=$2 sa sb stats
  sa=$(tmp_file)
  sb=$(tmp_file)
  LC_ALL=C awk '{sub(/\r$/, ""); if (length($0) > 0) print $0}' "$fa" | LC_ALL=C sort -u -T "$AN_TMPDIR" >"$sa"
  LC_ALL=C awk '{sub(/\r$/, ""); if (length($0) > 0) print $0}' "$fb" | LC_ALL=C sort -u -T "$AN_TMPDIR" >"$sb"

  stats=$(LC_ALL=C awk '
    NR == FNR { a[$0] = 1; ua++; next }
    {
      ub++
      if ($0 in a) {
        both++
        delete a[$0]
      } else {
        only_b++
      }
    }
    END {
      only_a = ua - both
      union_cnt = ua + ub - both
      jac = (union_cnt > 0) ? (both * 100.0 / union_cnt) : 0.0
      cov = (ua > 0) ? (both * 100.0 / ua) : 0.0
      printf "%d|%d|%d|%d|%d|%.1f|%.1f\n", ua+0, ub+0, only_a+0, only_b+0, both+0, jac, cov
    }' "$sa" "$sb")

  IFS='|' read -r WLC_UNIQUE_A WLC_UNIQUE_B WLC_ONLY_A WLC_ONLY_B WLC_OVERLAP WLC_JACCARD_PCT WLC_COV_A_BY_B_PCT <<<"$stats"
  rm -f -- "$sa" "$sb"
  return 0
}

# Safe streaming deduplication and normalization into a new 0600 file.
wl_clean_file() { # <infile> <outfile> [min_len] [max_len]
  local infile=$1 outfile=$2 min_l=${3:-1} max_l=${4:-1024}
  local tmp_clean
  tmp_clean=$(tmp_file)

  WLCLEAN_IN=$(LC_ALL=C awk -v min_l="$min_l" -v max_l="$max_l" -v out="$tmp_clean" '
    {
      sub(/\r$/, "")
      gsub(/[\001-\010\013\014\016-\037\177]/, "")
      len = length($0)
      if (len == 0) next
      n++
      if (len >= min_l && len <= max_l) print $0 > out
    }
    END { printf "%d", n+0 }' "$infile")

  (
    umask 077
    if [[ -s $tmp_clean ]]; then
      LC_ALL=C sort -u -T "$AN_TMPDIR" -- "$tmp_clean" >"$outfile"
    else
      : >"$outfile"
    fi
  )
  WLCLEAN_OUT=$(wc -l <"$outfile" | tr -d ' ')
  WLCLEAN_REMOVED=$((WLCLEAN_IN - WLCLEAN_OUT))
  rm -f -- "$tmp_clean"
  return 0
}
