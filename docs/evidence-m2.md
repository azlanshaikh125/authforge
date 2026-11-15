# Milestone 2 test evidence (generated 2026-11-12)

## Environment
```
GNU bash, version 5.2.15(1)-release (x86_64-pc-linux-gnu)
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
mawk: mawk 1.3.4 20200120
sha256sum: sha256sum (GNU coreutils) 9.1
shellcheck: not installed in container environment (skipped by Makefile)
```

## make clean && make all (verified from fresh extraction)
```
find reports logs evidence -mindepth 1 ! -name .gitkeep -delete 2>/dev/null || true
rm -rf backups .tmp-test
syntax OK (34 files)
shellcheck not installed (skipped)
tests/run.sh all
# summary pass=61 fail=0 skip=0   (tests/unit/test_core.sh)
# summary pass=78 fail=0 skip=0   (tests/unit/test_hashid.sh)
# summary pass=35 fail=0 skip=0   (tests/unit/test_pwdcheck.sh)
# summary pass=45 fail=0 skip=0   (tests/unit/test_risk.sh)
# summary pass=36 fail=0 skip=0   (tests/unit/test_wordlist.sh)
# summary pass=163 fail=0 skip=0  (tests/integration/test_cli.sh)
# summary pass=20 fail=0 skip=0   (tests/integration/test_tui.sh)
# summary pass=49 fail=0 skip=0   (tests/regression/test_secret_hygiene.sh)
==== TOTAL: 487 passed, 0 failed, 0 skipped, 0 file(s) failing or crashed ====
```

## Bugs caught and fixed during Milestone 2 development
1. **Per-severity score ceiling enforcement (`lib/risk.sh`)**: Multiple correlation boosts (`+0.6 + +0.4 + +0.4`) on a `HIGH` finding initially pushed its score above `9.0`, causing the session overall rating to report `CRITICAL` even after the only `CRITICAL` finding was suppressed. Fixed by enforcing per-severity band ceilings (`CRITICAL: 10.0`, `HIGH: 8.9`, `MEDIUM: 6.9`, `LOW: 3.9`, `INFO: 1.9`).
2. **TUI Reporting submenu loop (`core/menu.sh`)**: `_menu_reporting` (Menu `13`) was previously a one-shot function followed by an extra `ui_pause` in `menu_main` upon `Back`. Converted `_menu_reporting` into a standard submenu loop matching `02`, `03`, `04`, and `10`.
3. **Deterministic latest-session tracking (`core/session.sh`)**: Added `session_latest` backed by `reports/.latest` so multiple sessions created within the same second resolve deterministically when `--session` is omitted.
4. **Makefile `clean` target**: Added `clean` to `.PHONY` as a safe alias for `clean-data` so `make clean && make all` works cleanly.
