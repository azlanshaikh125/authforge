#!/usr/bin/env bash
# shellcheck shell=bash
# AUTHFORGE lib: pure string helpers (no globals, no I/O except stdout).
[[ -n "${_AN_STRUTIL:-}" ]] && return 0
_AN_STRUTIL=1

str_trim() {
  local s=$1
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

# Escape a string for inclusion inside a JSON string literal.
json_escape() {
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  s=${s//[[:cntrl:]]/ }
  printf '%s' "$s"
}

# Escape a string for RFC 4180 CSV output, neutralizing spreadsheet formula
# injection characters (=, +, -, @) at the start of a field.
csv_escape() {
  local s=$1
  s=${s//$'\n'/ }
  s=${s//$'\r'/ }
  s=${s//$'\t'/ }
  s=${s//[[:cntrl:]]/ }
  if [[ $s =~ ^[=+\-@] ]]; then
    s="'$s"
  fi
  s=${s//\"/\"\"}
  printf '"%s"' "$s"
}

# Escape a string for inclusion inside a Markdown pipe table cell.
md_escape() {
  local s=$1
  s=${s//$'\n'/ }
  s=${s//$'\r'/ }
  s=${s//$'\t'/ }
  s=${s//[[:cntrl:]]/ }
  s=${s//|/\\|}
  printf '%s' "$s"
}

# Collapse control separators so a value is safe inside a findings record field.
field_clean() {
  local s=$1
  s=${s//$'\t'/ }
  s=${s//$'\n'/ }
  s=${s//$'\r'/ }
  s=${s//$'\x1f'/ }
  printf '%s' "$s"
}

str_repeat() { # str_repeat <char> <count>
  local out="" i
  for ((i = 0; i < $2; i++)); do out+=$1; done
  printf '%s' "$out"
}

in_array() { # in_array <needle> <elem...>
  local n=$1 e
  shift
  for e in "$@"; do
    if [[ $e == "$n" ]]; then return 0; fi
  done
  return 1
}
