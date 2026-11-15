#!/usr/bin/env bash
# shellcheck shell=bash
# AUTHFORGE core: secure temporary-file handling (private dir, always cleaned).
[[ -n "${_AN_TMP:-}" ]] && return 0
_AN_TMP=1

AN_TMPDIR=""

tmp_init() {
  local old_umask
  old_umask=$(umask)
  umask 077
  AN_TMPDIR=$(mktemp -d "${TMPDIR:-/tmp}/authforge.XXXXXXXX") ||
    an_die "$EX_GENERAL" "cannot create private temp directory"
  umask "$old_umask"
  an_on_cleanup tmp_cleanup
  return 0
}

tmp_cleanup() {
  if [[ -n $AN_TMPDIR && -d $AN_TMPDIR && $AN_TMPDIR == */authforge.* ]]; then
    rm -rf -- "$AN_TMPDIR"
  fi
  return 0
}

tmp_file() { # prints path of a new private file inside AN_TMPDIR
  if [[ -z $AN_TMPDIR || ! -d $AN_TMPDIR ]]; then
    local old_umask
    old_umask=$(umask)
    umask 077
    AN_TMPDIR=$(mktemp -d "${TMPDIR:-/tmp}/authforge.XXXXXXXX")
    umask "$old_umask"
  fi
  mktemp "$AN_TMPDIR/f.XXXXXXXX"
}
