#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034  # globals are shared across sourced files by design
# AUTHFORGE lib: Authorized Lab-Only Authentication Intelligence helpers.
[[ -n "${_AN_AUTH_INTEL:-}" ]] && return 0
_AN_AUTH_INTEL=1

AI_OIDC_FOUND=0
AI_OIDC_ISSUER_HTTPS=0
AI_OIDC_PKCE_S256=0
AI_OIDC_IMPLICIT_FLOW=0
AI_SERVER_BANNER=""

auth_intel_parse_oidc() { # <json_body_file>
  AI_OIDC_FOUND=0
  AI_OIDC_ISSUER_HTTPS=0
  AI_OIDC_PKCE_S256=0
  AI_OIDC_IMPLICIT_FLOW=0
  local f=$1
  [[ -s $f ]] || return 1
  local raw
  raw=$(<"$f")
  if [[ $raw == *'"issuer"'* ]]; then AI_OIDC_FOUND=1; fi
  if [[ $raw =~ \"issuer\"[[:space:]]*:[[:space:]]*\"https:// ]]; then AI_OIDC_ISSUER_HTTPS=1; fi
  if [[ $raw == *'"S256"'* ]]; then AI_OIDC_PKCE_S256=1; fi
  if [[ $raw == *'"token"'* || $raw == *'"id_token token"'* ]]; then AI_OIDC_IMPLICIT_FLOW=1; fi
  return 0
}

# Resets AI_SERVER_BANNER whenever a new HTTP status block begins (M4-AUD-04).
auth_intel_parse_server_header() { # <hdr_file>
  AI_SERVER_BANNER=""
  local f=$1 line low
  [[ -s $f ]] || return 1
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%$'\r'}
    if [[ $line =~ ^HTTP/[0-9.]+\ [0-9]{3} ]]; then
      AI_SERVER_BANNER=""
      continue
    fi
    low=${line,,}
    if [[ $low == server:* ]]; then
      AI_SERVER_BANNER=$(str_trim "${line#*:}")
    fi
  done <"$f"
  return 0
}
