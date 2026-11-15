#!/usr/bin/env bash
# shellcheck shell=bash
# AUTHFORGE core: strict input validation. Validators return 0/1, print nothing.
# Policy:
#   - Only canonical dotted-quad IPv4 addresses (4 decimal octets 0..255, no leading zeros) are accepted as IPv4.
#   - Ambiguous legacy numeric IPv4 representations (octal leading zeros such as 0177.0.0.1 or 127.0.0.010,
#     hex octets/integers such as 0x7f.0.0.1 or 0x7f000001, shorthand 1/2/3-part forms such as 127.1 or 127.0.1,
#     and 32-bit integers such as 2130706433) are rejected before DNS resolution.
#   - IPv6 literals (e.g., ::1, [::1]) are unsupported and rejected consistently.
[[ -n "${_AN_VALIDATE:-}" ]] && return 0
_AN_VALIDATE=1

validate_uint() { # validate_uint <value> [min] [max]
  [[ $1 =~ ^[0-9]{1,9}$ ]] || return 1
  local v=$((10#$1))
  if [[ -n ${2:-} && $v -lt $2 ]]; then return 1; fi
  if [[ -n ${3:-} && $v -gt $3 ]]; then return 1; fi
  return 0
}

validate_ipv4() {
  local ip=${1:-} o
  [[ $ip =~ ^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$ ]] || return 1
  local IFS=.
  for o in $ip; do
    if ((10#$o > 255)); then return 1; fi
  done
  return 0
}

# Return 0 (true) if argument is a non-canonical/ambiguous numeric IPv4 representation
# (octal leading zeros, hex octets/integers, 1/2/3-part shorthand, 32-bit decimal integer, or all-numeric labels).
validate_ipv4_ambiguous() {
  local s=${1:-}
  [[ -n $s ]] || return 1
  if validate_ipv4 "$s"; then
    return 1
  fi
  if [[ $s =~ ^(0[xX][0-9A-Fa-f]+|[0-9]+)(\.(0[xX][0-9A-Fa-f]+|[0-9]+))*$ ]]; then
    return 0
  fi
  return 1
}

validate_hostname() {
  local h=${1:-}
  [[ -n $h && ${#h} -le 253 ]] || return 1
  [[ $h != *:* && $h != *\[* && $h != *\]* ]] || return 1
  [[ $h =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$ ]] || return 1
  ! validate_ipv4 "$h" || return 1
  ! validate_ipv4_ambiguous "$h" || return 1
  local last_label=${h##*.}
  [[ ! $last_label =~ ^[0-9]+$ ]] || return 1
  [[ ! $last_label =~ ^0[xX][0-9A-Fa-f]+$ ]] || return 1
  return 0
}

# Validate target as canonical dotted-quad IPv4 literal or RFC-1123 hostname.
# Ambiguous numeric IPv4 forms and IPv6 literals are rejected before DNS resolution.
validate_target() {
  local t=${1:-}
  [[ -n $t && $t != *:* && $t != *\[* && $t != *\]* ]] || return 1
  ! validate_ipv4_ambiguous "$t" || return 1
  validate_ipv4 "$t" || validate_hostname "$t"
}

validate_date_ymd() { [[ $1 =~ ^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$ ]]; }

validate_ident() { [[ $1 =~ ^[a-z][a-z0-9_-]{0,31}$ ]]; }

# Regular, non-symlink, readable file.
validate_regular_file() {
  [[ -f $1 && ! -L $1 && -r $1 ]]
}

# Path must resolve inside a given base directory (no traversal / symlink escape).
validate_path_within() { # validate_path_within <path> <base>
  local p b
  p=$(realpath -m -- "$1") || return 1
  b=$(realpath -m -- "$2") || return 1
  [[ $p == "$b" || $p == "$b"/* ]]
}
