#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034  # globals are shared across sourced files by design
# AUTHFORGE lib: hash identification, ambiguity detection, cost and security analysis.
#
# SECURITY: hash strings and account names are ONLY handled in shell variables or
# stdin streams. They are NEVER placed on a subprocess command line (argv),
# printed to console, or written to logs, findings, or reports.
[[ -n "${_AN_HASHID:-}" ]] && return 0
_AN_HASHID=1
shopt -s extglob

HI_FORMAT="unknown"
HI_FAMILY="unknown"
HI_CANDIDATES="none"
HI_AMBIGUOUS=0
HI_BASIS="heuristic"
HI_SALTED="no"
HI_SALT_LEN=0
HI_COST_DESC="none"
HI_TIER="unknown"
HI_HASHCAT_MODE="n/a"
HI_BCRYPT_COST=0
HI_ITERATIONS=0
HI_ARGON2_MIB=0
HI_ARGON2_KIB=0
HI_ARGON2_TIME=0
HI_ARGON2_PAR=0
HI_PWDUMP_LM_ACTIVE=0
declare -a HI_ISSUES=()

readonly _HI_EMPTY_LM="aad3b435b51404eeaad3b435b51404ee"
readonly _HI_EMPTY_NTLM="31d6cfe0d16ae931b73c59d7e0c089c0"

_hi_reset() {
  HI_FORMAT="unknown"
  HI_FAMILY="unknown"
  HI_CANDIDATES="none"
  HI_AMBIGUOUS=0
  HI_BASIS="heuristic"
  HI_SALTED="no"
  HI_SALT_LEN=0
  HI_COST_DESC="none"
  HI_TIER="unknown"
  HI_HASHCAT_MODE="n/a"
  HI_BCRYPT_COST=0
  HI_ITERATIONS=0
  HI_ARGON2_MIB=0
  HI_ARGON2_KIB=0
  HI_ARGON2_TIME=0
  HI_ARGON2_PAR=0
  HI_PWDUMP_LM_ACTIVE=0
  HI_ISSUES=()
  return 0
}

# Normalize an input record (raw hash, user:hash, /etc/shadow, or PWDUMP line)
# into the hash token without ever echoing or logging the username or hash.
hash_extract_token() { # <outvar> <raw-line>
  local -n _out_tok=$1
  local raw=${2%$'\r'}
  raw=$(str_trim "$raw")
  _out_tok=$raw
  [[ -n $raw ]] || return 0

  # PWDUMP format: user:uid:LM(32hex):NTLM(32hex):comment:homedir:
  if [[ $raw =~ ^[^:]+:[0-9]+:([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):.*$ ]]; then
    _out_tok="PWDUMP:${BASH_REMATCH[1],,}:${BASH_REMATCH[2],,}"
    return 0
  fi

  # /etc/shadow or user:hash format (avoid splitting scrypt:N:r:p:... or {TAG}...)
  if [[ $raw != scrypt:* && $raw == *:* ]]; then
    local f1 f2 rest
    IFS=':' read -r f1 f2 rest <<<"$raw"
    # If field 2 looks like a hash, lock marker, or modular string, extract field 2
    if [[ $f2 == \$* || $f2 == \{*\}* || $f2 == \** || $f2 == \!* || $f2 =~ ^[0-9a-fA-F]{16,128}$ || $f2 =~ ^[.\/0-9A-Za-z]{13}$ || $f2 == pbkdf2_* ]]; then
      _out_tok=$f2
      return 0
    fi
  fi
  return 0
}

# Identify and evaluate a single hash string against active policy settings.
hash_analyze() { # <raw-hash-or-record>
  _hi_reset
  local raw=$1 tok=""
  hash_extract_token tok "$raw"
  if [[ -z $tok ]]; then return 1; fi

  local min_b=${AN_CFG[hash_min_bcrypt_cost]:-12}
  local min_pbkdf2=${AN_CFG[hash_min_pbkdf2_iterations]:-310000}
  local min_a2_mib=${AN_CFG[hash_min_argon2_mib]:-19}
  local min_a2_t=${AN_CFG[hash_min_argon2_time]:-2}
  local min_sha=${AN_CFG[hash_min_shacrypt_rounds]:-100000}
  local allow_leg=${AN_CFG[hash_allow_legacy]:-0}

  # 1) Account lock / disabled markers (/etc/shadow)
  if [[ $tok == '!' || $tok == '*' || $tok == '!!' || $tok == '!*' || $tok =~ ^\!+\$.* ]]; then
    HI_FORMAT="account-locked"
    HI_FAMILY="account-state"
    HI_CANDIDATES="shadow-locked-account"
    HI_AMBIGUOUS=0
    HI_BASIS="verified"
    HI_SALTED="n/a"
    HI_COST_DESC="locked/disabled"
    HI_TIER="info"
    return 0
  fi

  # 2) PWDUMP LM:NTLM pair (extracted by hash_extract_token)
  if [[ $tok =~ ^PWDUMP:([0-9a-f]{32}):([0-9a-f]{32})$ ]]; then
    local lm=${BASH_REMATCH[1]} nt=${BASH_REMATCH[2]}
    HI_FORMAT="lm-ntlm-pwdump"
    HI_FAMILY="raw-digest"
    HI_CANDIDATES="NTLM (1000), LM (3000)"
    HI_AMBIGUOUS=0
    HI_BASIS="verified"
    HI_SALTED="no"
    HI_COST_DESC="none (single pass MD4/DES)"
    HI_HASHCAT_MODE="1000 (NTLM) / 3000 (LM)"
    HI_ISSUES+=("unsalted_digest")
    if [[ $lm != "$_HI_EMPTY_LM" ]]; then
      HI_PWDUMP_LM_ACTIVE=1
      HI_TIER="broken"
      HI_ISSUES+=("active_lm_hash" "broken_algorithm")
    else
      HI_TIER="weak"
      HI_ISSUES+=("fast_unsalted_ntlm")
    fi
    if [[ $nt == "$_HI_EMPTY_NTLM" ]]; then
      HI_TIER="broken"
      HI_ISSUES+=("empty_password_marker")
    fi
    return 0
  fi

  # 3) Argon2 PHC format: $argon2(id|i|d)$v=19$m=65536,t=3,p=4$<salt>$<hash>
  if [[ $tok =~ ^\$(argon2id|argon2i|argon2d)\$v=[0-9]+\$m=([0-9]+),t=([0-9]+),p=([0-9]+)\$([A-Za-z0-9+/=._-]+)\$([A-Za-z0-9+/=._-]+)$ ]]; then
    HI_FORMAT=${BASH_REMATCH[1]}
    HI_FAMILY="kdf-memory-hard"
    HI_CANDIDATES="$HI_FORMAT (PHC)"
    HI_AMBIGUOUS=0
    HI_BASIS="verified"
    HI_SALTED="yes"
    HI_ARGON2_KIB=$((10#${BASH_REMATCH[2]}))
    HI_ARGON2_MIB=$((HI_ARGON2_KIB / 1024))
    HI_ARGON2_TIME=$((10#${BASH_REMATCH[3]}))
    HI_ARGON2_PAR=$((10#${BASH_REMATCH[4]}))
    HI_SALT_LEN=${#BASH_REMATCH[5]}
    HI_COST_DESC="m=${HI_ARGON2_KIB} KiB (${HI_ARGON2_MIB} MiB), t=${HI_ARGON2_TIME}, p=${HI_ARGON2_PAR}"
    HI_HASHCAT_MODE="34000 (Argon2)"
    HI_TIER="strong"
    if [[ $HI_FORMAT == "argon2d" || $HI_FORMAT == "argon2i" ]]; then
      if [[ $HI_FORMAT == "argon2d" ]]; then
        HI_ISSUES+=("argon2_variant_d_sidechannel")
      fi
    fi
    if ((HI_ARGON2_MIB < 10#$min_a2_mib)); then
      HI_TIER="suboptimal"
      HI_ISSUES+=("low_argon2_memory:${HI_ARGON2_MIB}MiB<${min_a2_mib}MiB")
    fi
    if ((HI_ARGON2_TIME < 10#$min_a2_t)); then
      HI_TIER="suboptimal"
      HI_ISSUES+=("low_argon2_time:${HI_ARGON2_TIME}<${min_a2_t}")
    fi
    if ((HI_SALT_LEN < 16)); then
      HI_TIER="suboptimal"
      HI_ISSUES+=("short_salt:${HI_SALT_LEN}")
    fi
    return 0
  fi

  # 4) yescrypt: $y$<params>$<salt>$<hash> or $gy$...
  if [[ $tok =~ ^\$(y|gy)\$([./A-Za-z0-9]+)\$([./A-Za-z0-9]+)\$([./A-Za-z0-9]{20,})$ ]]; then
    HI_FORMAT="yescrypt"
    HI_FAMILY="kdf-memory-hard"
    HI_CANDIDATES="yescrypt (crypt)"
    HI_AMBIGUOUS=0
    HI_BASIS="verified"
    HI_SALTED="yes"
    HI_SALT_LEN=${#BASH_REMATCH[3]}
    HI_COST_DESC="params=${BASH_REMATCH[2]}"
    HI_HASHCAT_MODE="n/a (John: crypt/yescrypt)"
    HI_TIER="strong"
    return 0
  fi

  # 5) scrypt modular ($7$ or $scrypt$) or Werkzeug/colon scrypt:N:r:p$salt$hash
  if [[ $tok =~ ^\$7\$([./A-Za-z0-9]{11,})\$([./A-Za-z0-9]{20,})$ ]]; then
    HI_FORMAT="scrypt"
    HI_FAMILY="kdf-memory-hard"
    HI_CANDIDATES="scrypt ($7$)"
    HI_AMBIGUOUS=0
    HI_BASIS="verified"
    HI_SALTED="yes"
    HI_SALT_LEN=${#BASH_REMATCH[1]}
    HI_COST_DESC="modular-scrypt"
    HI_HASHCAT_MODE="8900 (scrypt)"
    HI_TIER="strong"
    return 0
  fi
  if [[ $tok =~ ^\$scrypt\$ln=([0-9]+),r=([0-9]+),p=([0-9]+)\$([A-Za-z0-9+/=._-]+)\$([A-Za-z0-9+/=._-]+)$ ]]; then
    HI_FORMAT="scrypt"
    HI_FAMILY="kdf-memory-hard"
    HI_CANDIDATES="scrypt (PHC)"
    HI_AMBIGUOUS=0
    HI_BASIS="verified"
    HI_SALTED="yes"
    HI_SALT_LEN=${#BASH_REMATCH[4]}
    HI_COST_DESC="ln=${BASH_REMATCH[1]}, r=${BASH_REMATCH[2]}, p=${BASH_REMATCH[3]}"
    HI_HASHCAT_MODE="8900 (scrypt)"
    HI_TIER="strong"
    if ((10#${BASH_REMATCH[1]} < 14)); then
      HI_TIER="suboptimal"
      HI_ISSUES+=("low_scrypt_ln:${BASH_REMATCH[1]}<14")
    fi
    return 0
  fi
  if [[ $tok =~ ^scrypt:([0-9]+):([0-9]+):([0-9]+)[\$:]([A-Za-z0-9+/=._-]+)[\$:]([A-Za-z0-9+/=._-]+)$ ]]; then
    HI_FORMAT="scrypt"
    HI_FAMILY="kdf-memory-hard"
    HI_CANDIDATES="scrypt (Werkzeug/modular)"
    HI_AMBIGUOUS=0
    HI_BASIS="verified"
    HI_SALTED="yes"
    HI_SALT_LEN=${#BASH_REMATCH[4]}
    HI_COST_DESC="N=${BASH_REMATCH[1]}, r=${BASH_REMATCH[2]}, p=${BASH_REMATCH[3]}"
    HI_HASHCAT_MODE="8900 (scrypt)"
    HI_TIER="strong"
    if ((10#${BASH_REMATCH[1]} < 16384)); then
      HI_TIER="suboptimal"
      HI_ISSUES+=("low_scrypt_N:${BASH_REMATCH[1]}<16384")
    fi
    return 0
  fi

  # 6) bcrypt ($2a$, $2b$, $2y$, $2x$)
  if [[ $tok =~ ^\$2([abxy])\$([0-9]{2})\$([./A-Za-z0-9]{53})$ ]]; then
    local bver=${BASH_REMATCH[1]} bcost=$((10#${BASH_REMATCH[2]}))
    HI_FORMAT="bcrypt"
    HI_FAMILY="kdf-iterated"
    HI_CANDIDATES="bcrypt (\$2${bver}\$)"
    HI_AMBIGUOUS=0
    HI_BASIS="verified"
    HI_SALTED="yes"
    HI_SALT_LEN=22
    HI_BCRYPT_COST=$bcost
    HI_COST_DESC="cost=$(printf '%02d' "$bcost") (2^${bcost} rounds)"
    HI_HASHCAT_MODE="3200 (bcrypt)"
    HI_TIER="strong"
    if [[ $bver == "x" || $bver == "a" ]]; then
      if [[ $bver == "x" ]]; then
        HI_TIER="legacy"
        HI_ISSUES+=("bcrypt_2x_bug_variant")
      fi
    fi
    if ((bcost < 10#$min_b)); then
      HI_TIER="suboptimal"
      HI_ISSUES+=("low_bcrypt_cost:${bcost}<${min_b}")
    fi
    return 0
  fi

  # 7) PBKDF2 modular ($pbkdf2-sha256$, $pbkdf2-sha512$, $pbkdf2$) and Django pbkdf2_sha256$
  if [[ $tok =~ ^\$pbkdf2-(sha256|sha512|sha1)\$([0-9]+)\$([A-Za-z0-9+/=._-]+)\$([A-Za-z0-9+/=._-]+)$ ]]; then
    local alg=${BASH_REMATCH[1]} iter=$((10#${BASH_REMATCH[2]}))
    HI_FORMAT="pbkdf2-${alg}"
    HI_FAMILY="kdf-iterated"
    HI_CANDIDATES="PBKDF2-HMAC-${alg^^} (Passlib)"
    HI_AMBIGUOUS=0
    HI_BASIS="verified"
    HI_SALTED="yes"
    HI_SALT_LEN=${#BASH_REMATCH[3]}
    HI_ITERATIONS=$iter
    HI_COST_DESC="iterations=${iter}"
    HI_HASHCAT_MODE="10900 (PBKDF2-HMAC-SHA256) / 12100 (SHA512)"
    HI_TIER="acceptable"
    if [[ $alg == "sha1" ]]; then
      HI_TIER="legacy"
      HI_ISSUES+=("legacy_kdf_sha1")
    fi
    if ((iter < 10#$min_pbkdf2)); then
      if [[ $HI_TIER == "acceptable" ]]; then HI_TIER="suboptimal"; fi
      HI_ISSUES+=("low_pbkdf2_iterations:${iter}<${min_pbkdf2}")
    fi
    return 0
  fi
  if [[ $tok =~ ^pbkdf2_(sha256|sha1)\$([0-9]+)\$([A-Za-z0-9+/=._-]+)\$([A-Za-z0-9+/=._-]+)$ ]]; then
    local alg=${BASH_REMATCH[1]} iter=$((10#${BASH_REMATCH[2]}))
    HI_FORMAT="django-pbkdf2-${alg}"
    HI_FAMILY="kdf-iterated"
    HI_CANDIDATES="Django PBKDF2-${alg^^}"
    HI_AMBIGUOUS=0
    HI_BASIS="verified"
    HI_SALTED="yes"
    HI_SALT_LEN=${#BASH_REMATCH[3]}
    HI_ITERATIONS=$iter
    HI_COST_DESC="iterations=${iter}"
    HI_HASHCAT_MODE="10000 (Django PBKDF2-SHA256)"
    HI_TIER="acceptable"
    if [[ $alg == "sha1" ]]; then
      HI_TIER="legacy"
      HI_ISSUES+=("legacy_kdf_sha1")
    fi
    if ((iter < 10#$min_pbkdf2)); then
      if [[ $HI_TIER == "acceptable" ]]; then HI_TIER="suboptimal"; fi
      HI_ISSUES+=("low_pbkdf2_iterations:${iter}<${min_pbkdf2}")
    fi
    return 0
  fi

  # 8) SHA-512 crypt ($6$) and SHA-256 crypt ($5$)
  if [[ $tok =~ ^\$(5|6)\$(rounds=([0-9]+)\$)?([./A-Za-z0-9]{1,16})\$([./A-Za-z0-9]{43}|[./A-Za-z0-9]{86})$ ]]; then
    local id=${BASH_REMATCH[1]} rstr=${BASH_REMATCH[3]:-} salt=${BASH_REMATCH[4]} ddig=${BASH_REMATCH[5]}
    local rounds=5000
    if [[ -n $rstr ]]; then rounds=$((10#$rstr)); fi
    if [[ $id == "6" && ${#ddig} -eq 86 ]]; then
      HI_FORMAT="sha512crypt"
      HI_CANDIDATES="sha512crypt (\$6\$)"
      HI_HASHCAT_MODE="1800 (sha512crypt)"
    elif [[ $id == "5" && ${#ddig} -eq 43 ]]; then
      HI_FORMAT="sha256crypt"
      HI_CANDIDATES="sha256crypt (\$5\$)"
      HI_HASHCAT_MODE="7400 (sha256crypt)"
    else
      return 1
    fi
    HI_FAMILY="crypt-salted"
    HI_AMBIGUOUS=0
    HI_BASIS="verified"
    HI_SALTED="yes"
    HI_SALT_LEN=${#salt}
    HI_ITERATIONS=$rounds
    if [[ -n $rstr ]]; then
      HI_COST_DESC="rounds=${rounds}"
    else
      HI_COST_DESC="rounds=5000 (implicit default)"
    fi
    HI_TIER="acceptable"
    if ((rounds < 10#$min_sha)); then
      HI_TIER="suboptimal"
      HI_ISSUES+=("low_shacrypt_rounds:${rounds}<${min_sha}")
    fi
    if ((HI_SALT_LEN < 8)); then
      HI_ISSUES+=("short_salt:${HI_SALT_LEN}")
    fi
    return 0
  fi

  # 9) MD5-crypt ($1$) and Apache APR1 ($apr1$)
  if [[ $tok =~ ^\$(1|apr1)\$([./A-Za-z0-9]{1,8})\$([./A-Za-z0-9]{22})$ ]]; then
    local id=${BASH_REMATCH[1]} salt=${BASH_REMATCH[2]}
    if [[ $id == "1" ]]; then
      HI_FORMAT="md5crypt"
      HI_CANDIDATES="md5crypt (\$1\$)"
      HI_HASHCAT_MODE="500 (md5crypt)"
    else
      HI_FORMAT="apr1"
      HI_CANDIDATES="Apache APR1 (\$apr1\$)"
      HI_HASHCAT_MODE="1600 (Apache \$apr1\$)"
    fi
    HI_FAMILY="legacy-broken"
    HI_AMBIGUOUS=0
    HI_BASIS="verified"
    HI_SALTED="yes"
    HI_SALT_LEN=${#salt}
    HI_ITERATIONS=1000
    HI_COST_DESC="rounds=1000 (fixed)"
    HI_TIER="legacy"
    HI_ISSUES+=("legacy_kdf")
    if ((allow_leg == 0)); then
      HI_ISSUES+=("legacy_disallowed_by_policy")
    fi
    return 0
  fi

  # 10) BSD NT-Hash ($3$$<32hex> or $NT$<32hex>)
  if [[ $tok =~ ^\$(3\$|NT)\$?([0-9a-fA-F]{32})$ ]]; then
    HI_FORMAT="bsd-nthash"
    HI_FAMILY="legacy-broken"
    HI_CANDIDATES="NTLM / BSD NT-Hash"
    HI_AMBIGUOUS=0
    HI_BASIS="verified"
    HI_SALTED="no"
    HI_COST_DESC="none (single pass MD4)"
    HI_HASHCAT_MODE="1000 (NTLM)"
    HI_TIER="weak"
    HI_ISSUES+=("unsalted_digest" "fast_unsalted_ntlm")
    return 0
  fi

  # 11) LDAP tagged schemes ({SSHA}, {SHA}, {SSHA256}, {SSHA512}, {MD5}, {SMD5}, {CLEARTEXT})
  if [[ $tok =~ ^\{(SSHA|SHA|SSHA256|SHA256|SSHA512|SHA512|SMD5|MD5|CLEARTEXT)\}(.+)$ ]]; then
    local tag=${BASH_REMATCH[1]^^} payload=${BASH_REMATCH[2]}
    HI_AMBIGUOUS=0
    HI_BASIS="verified"
    case $tag in
      CLEARTEXT)
        HI_FORMAT="ldap-cleartext"
        HI_FAMILY="legacy-broken"
        HI_CANDIDATES="LDAP {CLEARTEXT}"
        HI_SALTED="no"
        HI_COST_DESC="none (plaintext)"
        HI_TIER="broken"
        HI_ISSUES+=("cleartext_storage" "broken_algorithm") ;;
      SSHA)
        HI_FORMAT="ldap-ssha"
        HI_FAMILY="ldap-salted"
        HI_CANDIDATES="LDAP {SSHA} (salted SHA-1)"
        HI_SALTED="embedded"
        HI_SALT_LEN=4
        HI_COST_DESC="none (single pass salted SHA-1)"
        HI_HASHCAT_MODE="111 (nsldaps / SSHA-1)"
        HI_TIER="legacy"
        HI_ISSUES+=("legacy_kdf" "single_pass_digest")
        if ((allow_leg == 0)); then HI_ISSUES+=("legacy_disallowed_by_policy"); fi ;;
      SSHA256 | SSHA512)
        HI_FORMAT="ldap-${tag,,}"
        HI_FAMILY="ldap-salted"
        HI_CANDIDATES="LDAP {${tag}} (salted ${tag#S})"
        HI_SALTED="embedded"
        HI_SALT_LEN=8
        HI_COST_DESC="none (single pass salted ${tag#S})"
        HI_HASHCAT_MODE="1411 / 1711 (SSHA-256 / SSHA-512)"
        HI_TIER="legacy"
        HI_ISSUES+=("single_pass_digest")
        if ((allow_leg == 0)); then HI_ISSUES+=("legacy_disallowed_by_policy"); fi ;;
      SHA | SHA256 | SHA512 | MD5)
        HI_FORMAT="ldap-${tag,,}"
        HI_FAMILY="ldap-unsalted"
        HI_CANDIDATES="LDAP {${tag}} (unsalted)"
        HI_SALTED="no"
        HI_COST_DESC="none (single pass unsalted)"
        HI_HASHCAT_MODE="101 (nsldap / SHA-1)"
        HI_TIER="weak"
        HI_ISSUES+=("unsalted_digest" "single_pass_digest") ;;
      SMD5)
        HI_FORMAT="ldap-smd5"
        HI_FAMILY="legacy-broken"
        HI_CANDIDATES="LDAP {SMD5} (salted MD5)"
        HI_SALTED="embedded"
        HI_SALT_LEN=4
        HI_COST_DESC="none (single pass salted MD5)"
        HI_TIER="weak"
        HI_ISSUES+=("broken_algorithm" "single_pass_digest") ;;
    esac
    return 0
  fi

  # 12) MySQL 4.1+ (* followed by 40 hex chars: SHA1(SHA1(pass)))
  if [[ $tok =~ ^\*[0-9a-fA-F]{40}$ ]]; then
    HI_FORMAT="mysql5"
    HI_FAMILY="raw-digest"
    HI_CANDIDATES="MySQL 4.1/5.x double-SHA1"
    HI_AMBIGUOUS=0
    HI_BASIS="verified"
    HI_SALTED="no"
    HI_COST_DESC="none (2x SHA-1, unsalted)"
    HI_HASHCAT_MODE="300 (MySQL4.1/MySQL5)"
    HI_TIER="weak"
    HI_ISSUES+=("unsalted_digest" "single_pass_digest")
    if ((allow_leg == 0)); then HI_ISSUES+=("legacy_disallowed_by_policy"); fi
    return 0
  fi

  # 13) Traditional DES crypt (13 chars from [./0-9A-Za-z], not pure hex)
  if [[ $tok =~ ^[.\/0-9A-Za-z]{13}$ && ! $tok =~ ^[0-9a-fA-F]{13}$ ]]; then
    HI_FORMAT="des-crypt"
    HI_FAMILY="legacy-broken"
    HI_CANDIDATES="Traditional DES crypt(3) (truncates at 8 chars)"
    HI_AMBIGUOUS=1
    HI_BASIS="heuristic"
    HI_SALTED="yes"
    HI_SALT_LEN=2
    HI_ITERATIONS=25
    HI_COST_DESC="rounds=25 (56-bit DES, 8-char truncation)"
    HI_HASHCAT_MODE="1500 (descrypt)"
    HI_TIER="broken"
    HI_ISSUES+=("broken_algorithm" "password_truncation_8" "short_salt:2")
    return 0
  fi

  # 14) Raw hexadecimal digests (ambiguous by length -> basis=heuristic)
  if [[ $tok =~ ^[0-9a-fA-F]+$ ]]; then
    local hlen=${#tok}
    HI_AMBIGUOUS=1
    HI_BASIS="heuristic"
    HI_SALTED="no"
    HI_COST_DESC="none (unsalted raw digest)"
    case $hlen in
      16)
        HI_FORMAT="mysql323-or-lm"
        HI_FAMILY="legacy-broken"
        HI_CANDIDATES="MySQL 3.23 (200), LM half-hash (3000), DES-Oracle"
        HI_HASHCAT_MODE="200 (MySQL323) / 3000 (LM)"
        HI_TIER="broken"
        HI_ISSUES+=("broken_algorithm" "unsalted_digest") ;;
      32)
        HI_FORMAT="raw-md5-or-ntlm"
        HI_FAMILY="raw-digest"
        HI_CANDIDATES="MD5 (0), NTLM (1000), MD4 (900), LM full (3000)"
        HI_HASHCAT_MODE="0 (MD5) / 1000 (NTLM)"
        HI_TIER="weak"
        HI_ISSUES+=("unsalted_digest" "broken_algorithm")
        if [[ ${tok,,} == "$_HI_EMPTY_LM" || ${tok,,} == "$_HI_EMPTY_NTLM" ]]; then
          HI_BASIS="verified"
          HI_AMBIGUOUS=0
          HI_TIER="broken"
          HI_ISSUES+=("empty_password_marker")
        fi ;;
      40)
        HI_FORMAT="raw-sha1"
        HI_FAMILY="raw-digest"
        HI_CANDIDATES="SHA-1 (100), MySQL5 raw (300), RIPEMD-160 (6000)"
        HI_HASHCAT_MODE="100 (SHA1)"
        HI_TIER="weak"
        HI_ISSUES+=("unsalted_digest" "single_pass_digest") ;;
      56)
        HI_FORMAT="raw-sha224"
        HI_FAMILY="raw-digest"
        HI_CANDIDATES="SHA-224 (1300), SHA3-224 (17300)"
        HI_HASHCAT_MODE="1300 (SHA2-224)"
        HI_TIER="weak"
        HI_ISSUES+=("unsalted_digest" "single_pass_digest") ;;
      64)
        HI_FORMAT="raw-sha256"
        HI_FAMILY="raw-digest"
        HI_CANDIDATES="SHA-256 (1400), SHA3-256 (17400), BLAKE2s-256"
        HI_HASHCAT_MODE="1400 (SHA2-256)"
        HI_TIER="weak"
        HI_ISSUES+=("unsalted_digest" "single_pass_digest") ;;
      96)
        HI_FORMAT="raw-sha384"
        HI_FAMILY="raw-digest"
        HI_CANDIDATES="SHA-384 (10800), SHA3-384 (17500)"
        HI_HASHCAT_MODE="10800 (SHA2-384)"
        HI_TIER="weak"
        HI_ISSUES+=("unsalted_digest" "single_pass_digest") ;;
      128)
        HI_FORMAT="raw-sha512"
        HI_FAMILY="raw-digest"
        HI_CANDIDATES="SHA-512 (1700), SHA3-512 (17600), BLAKE2b-512, Whirlpool (6100)"
        HI_HASHCAT_MODE="1700 (SHA2-512)"
        HI_TIER="weak"
        HI_ISSUES+=("unsalted_digest" "single_pass_digest") ;;
      *)
        HI_FORMAT="unknown"
        HI_FAMILY="unknown"
        HI_CANDIDATES="unrecognized ${hlen}-char hex string"
        HI_TIER="unknown" ;;
    esac
    return 0
  fi

  return 0
}
