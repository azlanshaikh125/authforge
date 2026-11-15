#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034  # globals are shared across sourced files by design
# AUTHFORGE // ENTERPRISE SECURITY ENGINE
# Authentication security assessment framework (authorized use only).
# Entry point: option parsing, bootstrap, command dispatch.
unset BASH_ENV ENV CDPATH
set -Eeuo pipefail
shopt -s extglob

if ((BASH_VERSINFO[0] < 5)); then
  printf 'authforge: Bash 5+ required (found %s)\n' "$BASH_VERSION" >&2
  exit 4
fi

AN_SELF=$(readlink -f -- "${BASH_SOURCE[0]}")
AN_ROOT=${AN_SELF%/*}
if [[ -z ${AN_DATA_DIR:-} ]]; then
  if [[ -f "$AN_ROOT/.authforge-install.manifest" && ! -L "$AN_ROOT/.authforge-install.manifest" ]]; then
    _an_mdir=$(grep -E '^datadir=' "$AN_ROOT/.authforge-install.manifest" 2>/dev/null | head -n 1 || true)
    _an_mdir=${_an_mdir#datadir=}
    if [[ -n $_an_mdir && $_an_mdir == /* && $_an_mdir != "/" && $_an_mdir != */ && $_an_mdir != *"//"* ]]; then
      AN_DATA_DIR=$_an_mdir
    else
      AN_DATA_DIR="${XDG_STATE_HOME:-${HOME:-/tmp}/.local/state}/authforge"
    fi
    unset _an_mdir
  elif [[ ! -w $AN_ROOT || ! -O $AN_ROOT ]]; then
    AN_DATA_DIR="${XDG_STATE_HOME:-${HOME:-/tmp}/.local/state}/authforge"
  else
    AN_DATA_DIR=$AN_ROOT
  fi
fi
AN_PROFILE=""
AN_MODULE=core
export AN_ROOT

# Load order matters: constants -> helpers -> logging -> ui -> errors -> rest -> libs.
for _f in core/constants lib/strutil core/log core/ui core/errors core/tmp core/validate \
  core/config core/deps core/session core/findings core/authz core/plugin core/menu \
  lib/pwdcheck lib/hashid lib/wordlist lib/risk lib/mfa lib/session_audit lib/pwreset \
  lib/proto_audit lib/auth_intel lib/web_auth lib/compliance lib/evidence; do
  # shellcheck source=/dev/null
  source "$AN_ROOT/$_f.sh"
done
unset _f

usage() {
  cat <<EOF
$AN_NAME $AN_VERSION - authentication security assessment framework

Usage: authforge [options] <command> [args]

Commands:
  menu                     Interactive TUI (default when run on a terminal)
  password <sub>           Password Security Engine (see: password help)
  hash <sub>               Hash Intelligence Engine (see: hash help)
  wordlist <sub>           Wordlist Analytics Engine (see: wordlist help)
  mfa <sub>                MFA Security Assessment (see: mfa help)
  session-audit <sub>      Session Security Analysis (see: session-audit help)
  pwreset <sub>            Password Reset Security Audit (see: pwreset help)
  auth-intel <sub>         Authentication Intelligence (authorized lab; see: auth-intel help)
  proto-audit <sub>        Authentication Protocol Audit (authorized lab; see: proto-audit help)
  web-auth <sub>           Web Authentication Assessment (authorized lab; see: web-auth help)
  risk <sub>               Risk Intelligence Engine (see: risk help)
  compliance <sub>         Compliance Assessment Engine (see: compliance help)
  evidence <sub>           Evidence Management Engine (see: evidence help)
  findings list|export|verify
                           Inspect, export (json|csv|md|txt) or verify session findings
  sessions                 List audit sessions
  modules                  List loaded modules and plugins
  doctor                   System diagnostics and dependency check
  config show|validate|backup|restore DIR
  authz-check <target>     Verify online-assessment authorization (no traffic sent)
  version | help

Options:
  -c, --config FILE        Use an alternative configuration file
  -p, --profile NAME       Load profile from profiles/NAME.profile
  -v, --verbose            Verbose console logging
  -q, --quiet              Suppress warnings and info
  -d, --debug              Debug logging (never traces secrets)
      --no-color           Disable colors
      --fail-on SEVERITY   Exit 10 if a finding >= SEVERITY (INFO|LOW|MEDIUM|HIGH|CRITICAL)
      --allow-online       Permit online checks (also requires --scope)
      --scope FILE         Authorization scope file for online checks
  -h, --help | -V, --version

Exit codes: 0 ok, 2 usage, 3 config, 4 dependency, 5 authorization,
            6 validation, 10 findings threshold, 130 interrupted.

Passwords, hashes, recovery codes, and tokens are never accepted as arguments. For authorized use only.
EOF
}

cmd_findings() {
  local sub=${1:-list} sid="" fmt=json out=""
  shift || true
  while (($#)); do
    case $1 in
      --session) sid=${2:-}; shift ;;
      --format) fmt=${2:-}; shift ;;
      -o | --output) out=${2:-}; shift ;;
      *) an_die "$EX_USAGE" "findings: unknown option $1" ;;
    esac
    shift
  done
  if [[ -z $sid ]]; then sid=$(session_latest); fi
  [[ -n $sid ]] || an_die "$EX_VALIDATION" "no sessions found"
  [[ $sid =~ ^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$ ]] || an_die "$EX_VALIDATION" "invalid session id"
  local file="$AN_DATA_DIR/reports/$sid/findings.dat"
  [[ -f $file ]] || an_die "$EX_VALIDATION" "unknown session: $sid"
  case $sub in
    list) findings_print "$file" ;;
    export)
      case $fmt in
        json | csv | md | markdown | txt) ;;
        *) an_die "$EX_USAGE" "unsupported export format '$fmt' (use json|csv|md|txt)" ;;
      esac
      if [[ -n $out ]]; then
        [[ ! -e $out ]] || an_die "$EX_VALIDATION" "refusing to overwrite existing file: $out"
        (
          umask 077
          case $fmt in
            json) findings_export_json "$sid" "$file" >"$out" ;;
            csv) findings_export_csv "$sid" "$file" >"$out" ;;
            md | markdown) findings_export_markdown "$sid" "$file" >"$out" ;;
            txt) findings_export_txt "$sid" "$file" >"$out" ;;
          esac
        )
        risk_manifest_update "$sid"
        printf 'Wrote %s\n' "$out"
      else
        case $fmt in
          json) findings_export_json "$sid" "$file" ;;
          csv) findings_export_csv "$sid" "$file" ;;
          md | markdown) findings_export_markdown "$sid" "$file" ;;
          txt) findings_export_txt "$sid" "$file" ;;
        esac
        risk_manifest_update "$sid"
      fi ;;
    verify)
      local rc=0
      risk_manifest_verify "$sid" || rc=$?
      if ((rc != 0)); then exit "$rc"; fi ;;
    *) an_die "$EX_USAGE" "findings: unknown subcommand '$sub'" ;;
  esac
}

cmd_config() {
  local sub=${1:-show}
  shift || true
  case $sub in
    show) config_show ;;
    validate) config_validate_all ;;
    backup) config_backup ;;
    restore)
      [[ -n ${1:-} ]] || an_die "$EX_USAGE" "config restore requires a backup directory"
      config_restore "$1" && printf 'Configuration restored from %s\n' "$1" ;;
    *) an_die "$EX_USAGE" "config: unknown subcommand '$sub'" ;;
  esac
}

main() {
  local conf="" profile="" fail_on="" rc
  while (($#)); do
    case $1 in
      -h | --help) usage; exit 0 ;;
      -V | --version) printf '%s %s\n' "$AN_NAME" "$AN_VERSION"; exit 0 ;;
      -v | --verbose) AN_VERBOSE=1 ;;
      -q | --quiet) AN_QUIET=1 ;;
      -d | --debug) AN_DEBUG=1 ;;
      --no-color) AN_NO_COLOR=1 ;;
      --allow-online) AN_ALLOW_ONLINE=1 ;;
      -c | --config | -p | --profile | --fail-on | --scope)
        (($# >= 2)) || an_usage_error "option $1 requires an argument"
        case $1 in
          -c | --config) conf=$2 ;;
          -p | --profile) profile=$2 ;;
          --fail-on) fail_on=$2 ;;
          --scope) AN_SCOPE_FILE=$2 ;;
        esac
        shift ;;
      --) shift; break ;;
      -*) an_usage_error "unknown option: $1" ;;
      *) break ;;
    esac
    shift
  done

  if [[ -n $fail_on ]]; then
    in_array "$fail_on" "${AN_SEVERITIES[@]}" || an_usage_error "invalid --fail-on severity: $fail_on"
  fi

  local cmd=${1:-}
  shift || true
  if [[ -z $cmd ]]; then
    if [[ -t 0 && -t 1 ]]; then cmd=menu; else usage >&2; exit "$EX_USAGE"; fi
  fi
  case $cmd in
    help) usage; exit 0 ;;
    version) printf '%s %s\n' "$AN_NAME" "$AN_VERSION"; exit 0 ;;
  esac

  an_install_traps
  ui_init
  local missing
  if ! missing=$(deps_check_required); then
    an_die "$EX_DEPENDENCY" "missing required commands: ${missing//$'\n'/ }"
  fi
  config_init "$conf" "$profile"
  AN_LOG_LEVEL=${AN_CFG[log_level]}
  ui_init
  tmp_init

  # Initialize session BEFORE plugin_load_all so module/plugin load warnings
  # and debug messages are recorded in the session log file (B-1 fix).
  case $cmd in
    menu | password | hash | wordlist | mfa | session-audit | pwreset | auth-intel | proto-audit | web-auth | doctor | authz-check) session_init ;;
  esac

  plugin_load_all

  rc=0
  case $cmd in
    menu) menu_main || rc=$? ;;
    password)
      declare -F mod_password_main >/dev/null || an_die "$EX_GENERAL" "password module not loaded"
      mod_password_main "$@" || rc=$? ;;
    hash)
      declare -F mod_hash_main >/dev/null || an_die "$EX_GENERAL" "hash module not loaded"
      mod_hash_main "$@" || rc=$? ;;
    wordlist)
      declare -F mod_wordlist_main >/dev/null || an_die "$EX_GENERAL" "wordlist module not loaded"
      mod_wordlist_main "$@" || rc=$? ;;
    mfa)
      declare -F mod_mfa_main >/dev/null || an_die "$EX_GENERAL" "mfa module not loaded"
      mod_mfa_main "$@" || rc=$? ;;
    session-audit)
      declare -F mod_session_sec_main >/dev/null || an_die "$EX_GENERAL" "session_sec module not loaded"
      mod_session_sec_main "$@" || rc=$? ;;
    pwreset)
      declare -F mod_pwreset_main >/dev/null || an_die "$EX_GENERAL" "pwreset module not loaded"
      mod_pwreset_main "$@" || rc=$? ;;
    auth-intel)
      declare -F mod_auth_intel_main >/dev/null || an_die "$EX_GENERAL" "auth_intel module not loaded"
      mod_auth_intel_main "$@" || rc=$? ;;
    proto-audit)
      declare -F mod_proto_audit_main >/dev/null || an_die "$EX_GENERAL" "proto_audit module not loaded"
      mod_proto_audit_main "$@" || rc=$? ;;
    web-auth)
      declare -F mod_web_auth_main >/dev/null || an_die "$EX_GENERAL" "web_auth module not loaded"
      mod_web_auth_main "$@" || rc=$? ;;
    risk)
      declare -F mod_risk_main >/dev/null || an_die "$EX_GENERAL" "risk module not loaded"
      mod_risk_main "$@" || rc=$? ;;
    compliance)
      declare -F mod_compliance_main >/dev/null || an_die "$EX_GENERAL" "compliance module not loaded"
      mod_compliance_main "$@" || rc=$? ;;
    evidence)
      declare -F mod_evidence_main >/dev/null || an_die "$EX_GENERAL" "evidence module not loaded"
      mod_evidence_main "$@" || rc=$? ;;
    findings) cmd_findings "$@" || rc=$? ;;
    sessions) session_list || rc=$? ;;
    modules) plugin_list || rc=$? ;;
    doctor) deps_doctor || rc=$? ;;
    config) cmd_config "$@" || rc=$? ;;
    authz-check)
      [[ -n ${1:-} ]] || an_die "$EX_USAGE" "authz-check requires a target"
      # NB: never chain with && here -- it would swallow the refusal status under set -e.
      rc=0
      authz_require_online "$1" || rc=$?
      if ((rc != 0)); then exit "$rc"; fi
      printf '%s authorization verified for %s\n' "$(ui_status_badge PASS)" "$1" ;;
    *) an_usage_error "unknown command: $cmd" ;;
  esac
  if ((rc != 0)); then exit "$rc"; fi

  # Session summary, SHA-256 manifest generation, and threshold-based exit code
  if ((_AN_LEDGER_WRITE_FAILED != 0)); then
    exit "$EX_GENERAL"
  fi
  if [[ -n $AN_SESSION_FINDINGS ]]; then
    risk_manifest_update "$AN_SESSION_ID" || exit "$EX_GENERAL"
  fi
  if [[ -n $AN_SESSION_FINDINGS && -s $AN_SESSION_FINDINGS ]]; then
    local n
    n=$(wc -l <"$AN_SESSION_FINDINGS")
    printf '\nSession %s recorded %d finding(s). Inspect: authforge findings list --session %s\n' \
      "$AN_SESSION_ID" "$n" "$AN_SESSION_ID" >&2
    if [[ -n $fail_on ]]; then
      local max want
      max=$(findings_max_rank "$AN_SESSION_FINDINGS")
      want=$(_sev_rank "$fail_on")
      if ((max >= want)); then exit "$EX_FINDINGS"; fi
    fi
  fi
  exit 0
}

main "$@"
