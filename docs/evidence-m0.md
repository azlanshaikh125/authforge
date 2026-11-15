# Milestone 0 test evidence (generated 2026-11-12T08:34:54Z)

## Environment
```
GNU bash, version 5.2.21(1)-release (x86_64-pc-linux-gnu)
version: 0.11.0
PRETTY_NAME="Ubuntu 24.04.5 LTS"
mawk: mawk 1.3.4 20240123
gawk: GNU Awk 5.2.1, API 3.2, PMA Avon 8-g1, (GNU MPFR 4.2.1, GNU MP 6.3.0)
```

## make all
```
syntax OK (25 files)
shellcheck -x -S style authforge.sh core/authz.sh core/config.sh core/constants.sh core/deps.sh core/errors.sh core/findings.sh core/log.sh core/menu.sh core/plugin.sh core/session.sh core/tmp.sh core/ui.sh core/validate.sh lib/pwdcheck.sh lib/strutil.sh modules/password.sh plugins/example_hello.sh
shellcheck -x -S warning tests/run.sh tests/lib/harness.sh tests/unit/test_core.sh tests/unit/test_pwdcheck.sh tests/integration/test_cli.sh tests/integration/test_tui.sh tests/regression/test_secret_hygiene.sh
shellcheck OK
# summary pass=51 fail=0 skip=0
# summary pass=32 fail=0 skip=0
# summary pass=80 fail=0 skip=0
# summary pass=10 fail=0 skip=0
# summary pass=16 fail=0 skip=0
==== TOTAL: 189 passed, 0 failed, 0 skipped, 0 file(s) failing or crashed ====
```

## Same suite with each awk pinned
```
mawk: ==== TOTAL: 189 passed, 0 failed, 0 skipped, 0 file(s) failing or crashed ====
gawk: ==== TOTAL: 189 passed, 0 failed, 0 skipped, 0 file(s) failing or crashed ====
```

## Mutation check (suite must fail when a security property is broken)
| Deliberate regression (scratch copy) | Result |
|---|---|
| `log_redact` made a no-op | 9 tests failed (7 redaction unit tests, stored-findings secret check, plus a collateral SIGTERM-test failure) |
| password passed on `grep` argv | 2 argv-leak tests failed |
| evidence rule removed from `findings_add` | 3 tests failed |
| plugin permission check disabled | 2 loader tests failed |

## Bugs found by the tests during this milestone (all fixed, with regression tests)
1. leet normalisation ran before affix stripping (`P@ssw0rd!` was missed)
2. `authz-check` swallowed the refusal status (`&&` under `set -e`) — a refused authorization exited 0
3. `config restore` overwrote the backup it restored from (1-second timestamp collision)
4. TUI treated out-of-range menu numbers as "not implemented" instead of invalid
