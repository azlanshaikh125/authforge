#!/usr/bin/env bash
# shellcheck shell=bash disable=SC1091,SC2034
source "$(dirname "${BASH_SOURCE[0]}")/../lib/harness.sh"
sandbox
load_core

# 1. Argon2id (strong vs low memory vs low time)
hash_analyze '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQxMjM0NTY3OA$RdescudvJCsgt3ub+b+dWRWJTmaaJObG'
assert_eq "argon2id" "$HI_FORMAT" "identifies argon2id"
assert_eq "kdf-memory-hard" "$HI_FAMILY" "argon2id family is kdf-memory-hard"
assert_eq "0" "$HI_AMBIGUOUS" "argon2id is unambiguous"
assert_eq "verified" "$HI_BASIS" "argon2id basis is verified"
assert_eq "64" "$HI_ARGON2_MIB" "argon2id parses 64 MiB"
assert_eq "3" "$HI_ARGON2_TIME" "argon2id parses t=3"
assert_eq "strong" "$HI_TIER" "argon2id 64MiB/t=3 rated strong"

hash_analyze '$argon2id$v=19$m=8192,t=1,p=1$c29tZXNhbHQxMjM0NTY3OA$RdescudvJCsgt3ub+b+dWRWJTmaaJObG'
assert_eq "suboptimal" "$HI_TIER" "argon2id 8MiB/t=1 rated suboptimal"
assert_contains "${HI_ISSUES[*]}" "low_argon2_memory" "flags low argon2 memory"
assert_contains "${HI_ISSUES[*]}" "low_argon2_time" "flags low argon2 time cost"

hash_analyze '$argon2d$v=19$m=65536,t=3,p=4$c29tZXNhbHQxMjM0NTY3OA$RdescudvJCsgt3ub+b+dWRWJTmaaJObG'
assert_eq "argon2d" "$HI_FORMAT" "identifies argon2d"
assert_contains "${HI_ISSUES[*]}" "argon2_variant_d_sidechannel" "notes argon2d side-channel consideration"

# 2. yescrypt & scrypt
hash_analyze '$y$j9T$saltsaltsaltsalt$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ'
assert_eq "yescrypt" "$HI_FORMAT" "identifies yescrypt"
assert_eq "strong" "$HI_TIER" "yescrypt rated strong"

hash_analyze 'scrypt:32768:8:1$c29tZXNhbHQxMjM0$abcdef0123456789abcdef0123456789'
assert_eq "scrypt" "$HI_FORMAT" "identifies Werkzeug scrypt"
assert_eq "strong" "$HI_TIER" "scrypt N=32768 rated strong"

hash_analyze 'scrypt:1024:8:1$c29tZXNhbHQxMjM0$abcdef0123456789abcdef0123456789'
assert_eq "suboptimal" "$HI_TIER" "scrypt N=1024 rated suboptimal"
assert_contains "${HI_ISSUES[*]}" "low_scrypt_N" "flags low scrypt N"

# 3. bcrypt ($2b$, $2a$ low cost, $2x$ buggy variant)
hash_analyze '$2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234'
assert_eq "bcrypt" "$HI_FORMAT" "identifies bcrypt"
assert_eq "12" "$HI_BCRYPT_COST" "parses bcrypt cost 12"
assert_eq "strong" "$HI_TIER" "bcrypt cost 12 rated strong"

hash_analyze '$2a$08$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234'
assert_eq "bcrypt" "$HI_FORMAT" "identifies bcrypt 2a"
assert_eq "8" "$HI_BCRYPT_COST" "parses bcrypt cost 8"
assert_eq "suboptimal" "$HI_TIER" "bcrypt cost 8 rated suboptimal against default min 12"
assert_contains "${HI_ISSUES[*]}" "low_bcrypt_cost:8<12" "flags low bcrypt cost"

hash_analyze '$2x$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234'
assert_eq "legacy" "$HI_TIER" "bcrypt 2x rated legacy"
assert_contains "${HI_ISSUES[*]}" "bcrypt_2x_bug_variant" "flags bcrypt 2x variant"

# 4. PBKDF2 (Passlib modular & Django)
hash_analyze '$pbkdf2-sha256$600000$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG'
assert_eq "pbkdf2-sha256" "$HI_FORMAT" "identifies modular pbkdf2-sha256"
assert_eq "600000" "$HI_ITERATIONS" "parses pbkdf2 iterations"
assert_eq "acceptable" "$HI_TIER" "pbkdf2-sha256 600k rated acceptable"

hash_analyze 'pbkdf2_sha256$120000$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG='
assert_eq "django-pbkdf2-sha256" "$HI_FORMAT" "identifies Django pbkdf2_sha256"
assert_eq "suboptimal" "$HI_TIER" "pbkdf2_sha256 120k suboptimal (<310k)"

hash_analyze '$pbkdf2-sha1$400000$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG'
assert_eq "pbkdf2-sha1" "$HI_FORMAT" "identifies pbkdf2-sha1"
assert_eq "legacy" "$HI_TIER" "pbkdf2-sha1 rated legacy"

# 5. SHA-512 crypt ($6$), SHA-256 crypt ($5$), MD5-crypt ($1$), APR1 ($apr1$)
hash_analyze '$6$rounds=200000$saltsalt12345678$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890123456789012345678901234567'
assert_eq "sha512crypt" "$HI_FORMAT" "identifies sha512crypt"
assert_eq "200000" "$HI_ITERATIONS" "parses sha512crypt explicit rounds"
assert_eq "acceptable" "$HI_TIER" "sha512crypt 200k rounds rated acceptable"

hash_analyze '$6$saltsalt12345678$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890123456789012345678901234567'
assert_eq "5000" "$HI_ITERATIONS" "sha512crypt without rounds= defaults to 5000"
assert_eq "suboptimal" "$HI_TIER" "sha512crypt default 5000 rounds rated suboptimal"

hash_analyze '$5$rounds=150000$saltsalt12345678$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTU'
assert_eq "sha256crypt" "$HI_FORMAT" "identifies sha256crypt"
assert_eq "acceptable" "$HI_TIER" "sha256crypt 150k rounds rated acceptable"

hash_analyze '$1$saltsalt$abcdefghijklmnopqrstuu'
assert_eq "md5crypt" "$HI_FORMAT" "identifies md5crypt"
assert_eq "legacy" "$HI_TIER" "md5crypt rated legacy"

hash_analyze '$apr1$saltsalt$abcdefghijklmnopqrstuu'
assert_eq "apr1" "$HI_FORMAT" "identifies Apache apr1"
assert_eq "legacy" "$HI_TIER" "apr1 rated legacy"

# 6. LDAP, MySQL5, DES-crypt, BSD NT-Hash
hash_analyze '{SSHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g='
assert_eq "ldap-ssha" "$HI_FORMAT" "identifies LDAP {SSHA}"
assert_eq "embedded" "$HI_SALTED" "LDAP {SSHA} has embedded salt"
assert_eq "legacy" "$HI_TIER" "LDAP {SSHA} rated legacy"

hash_analyze '{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g='
assert_eq "ldap-sha" "$HI_FORMAT" "identifies LDAP {SHA}"
assert_eq "no" "$HI_SALTED" "LDAP {SHA} is unsalted"
assert_eq "weak" "$HI_TIER" "LDAP {SHA} rated weak"

hash_analyze '{CLEARTEXT}someplaintext'
assert_eq "ldap-cleartext" "$HI_FORMAT" "identifies LDAP {CLEARTEXT}"
assert_eq "broken" "$HI_TIER" "LDAP {CLEARTEXT} rated broken"

hash_analyze '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19'
assert_eq "mysql5" "$HI_FORMAT" "identifies MySQL5"
assert_eq "weak" "$HI_TIER" "MySQL5 rated weak"

hash_analyze 'abJnggxhB/yWI'
assert_eq "des-crypt" "$HI_FORMAT" "identifies traditional DES-crypt"
assert_eq "broken" "$HI_TIER" "DES-crypt rated broken"
assert_eq "1" "$HI_AMBIGUOUS" "DES-crypt marked ambiguous/heuristic"

# 7. Raw hex ambiguity & empty markers
hash_analyze '5f4dcc3b5aa765d61d8327deb882cf99'
assert_eq "raw-md5-or-ntlm" "$HI_FORMAT" "identifies 32-hex as raw-md5-or-ntlm"
assert_eq "1" "$HI_AMBIGUOUS" "32-hex marked ambiguous"
assert_eq "heuristic" "$HI_BASIS" "32-hex basis is heuristic"
assert_eq "weak" "$HI_TIER" "32-hex rated weak"

hash_analyze '31d6cfe0d16ae931b73c59d7e0c089c0'
assert_eq "broken" "$HI_TIER" "empty NTLM marker rated broken"
assert_contains "${HI_ISSUES[*]}" "empty_password_marker" "detects empty NTLM password marker"

hash_analyze '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8'
assert_eq "raw-sha1" "$HI_FORMAT" "identifies 40-hex as raw-sha1"
assert_eq "1" "$HI_AMBIGUOUS" "40-hex marked ambiguous"

hash_analyze '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8'
assert_eq "raw-sha256" "$HI_FORMAT" "identifies 64-hex as raw-sha256"

hash_analyze 'b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86'
assert_eq "raw-sha512" "$HI_FORMAT" "identifies 128-hex as raw-sha512"

# 8. Shadow & PWDUMP wrapper extraction
hash_analyze 'alice:$2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234:19700:0:99999:7:::'
assert_eq "bcrypt" "$HI_FORMAT" "extracts bcrypt hash from /etc/shadow record"
assert_eq "strong" "$HI_TIER" "shadow bcrypt rated strong"

hash_analyze 'svc_locked:!:19700:0:99999:7:::'
assert_eq "account-locked" "$HI_FORMAT" "identifies locked shadow account"
assert_eq "info" "$HI_TIER" "locked shadow account tier is info"

hash_analyze 'backup_admin:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::'
assert_eq "lm-ntlm-pwdump" "$HI_FORMAT" "identifies PWDUMP record"
assert_eq "0" "$HI_PWDUMP_LM_ACTIVE" "detects empty LM marker in PWDUMP"
assert_eq "weak" "$HI_TIER" "PWDUMP with disabled LM rated weak (unsalted NTLM)"

hash_analyze 'legacy_admin:500:0123456789abcdef0123456789abcdef:8846f7eaee8fb117ad06bdd830b7586c:::'
assert_eq "1" "$HI_PWDUMP_LM_ACTIVE" "detects active LM hash in PWDUMP"
assert_eq "broken" "$HI_TIER" "PWDUMP with active LM rated broken"

# 9. Unknown / malformed
hash_analyze 'not_a_valid_hash_format_at_all'
assert_eq "unknown" "$HI_FORMAT" "unrecognized string classified as unknown"

t_summary
