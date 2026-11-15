# Milestone 1 test evidence (generated 2026-11-12)

## Environment
```
GNU bash, version 5.2.15(1)-release (x86_64-pc-linux-gnu)
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
mawk: mawk 1.3.4 20200120
shellcheck: not installed in container environment (skipped by Makefile)
```

## make all
```
syntax OK (31 files)
shellcheck not installed (skipped)
tests/run.sh all
# summary pass=58 fail=0 skip=0   (tests/unit/test_core.sh)
# summary pass=78 fail=0 skip=0   (tests/unit/test_hashid.sh)
# summary pass=35 fail=0 skip=0   (tests/unit/test_pwdcheck.sh)
# summary pass=36 fail=0 skip=0   (tests/unit/test_wordlist.sh)
# summary pass=128 fail=0 skip=0  (tests/integration/test_cli.sh)
# summary pass=16 fail=0 skip=0   (tests/integration/test_tui.sh)
# summary pass=38 fail=0 skip=0   (tests/regression/test_secret_hygiene.sh)
==== TOTAL: 389 passed, 0 failed, 0 skipped, 0 file(s) failing or crashed ====
```

## Issues resolved & regression-tested in Milestone 1
1. **B-1 (`authforge.sh`)**: `session_init` now runs before `plugin_load_all` for session-creating commands so module/plugin load events and permission warnings are recorded in the session log file (`logs/<session_id>.log`).
2. **B-2 (`authforge.sh`, `Makefile`, `tests/run.sh`, `tests/lib/harness.sh`)**: `BASH_ENV`, `ENV`, and `CDPATH` are explicitly unset at startup; `tests/lib/harness.sh` probes `$TMPDIR` and falls back to `$TEST_ROOT/.tmp-test` when `/tmp` is mounted `noexec`.
3. **B-3 (`lib/pwdcheck.sh`)**: `pw_common_match` preserves leet symbols (`$`, `@`) at the end of root words when stripping trailing digits/non-leet punctuation (`pa$$2024!` matches `pass`).
4. **B-4 (`lib/pwdcheck.sh`)**: `pw_find_patterns` tracks covered character indices via a per-index coverage array so overlapping patterns (e.g. `Summer1234!`) never double-subtract character positions.
5. **B-5 (`authforge.sh`)**: `findings_max_rank` receives `"$AN_SESSION_FINDINGS"` explicitly.
6. **CRLF & Redaction Hardening (`core/log.sh`, `modules/password.sh`)**: `log_redact` redacts Argon2, PBKDF2 (Passlib & Django), scrypt, yescrypt, LDAP tagged schemes, and MySQL5 hashes; `password check-file` normalizes CRLF inputs before duplicate and blocklist checks.
