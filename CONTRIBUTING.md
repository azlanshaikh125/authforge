# Contributing to AUTHFORGE

Thank you for contributing to AUTHFORGE. Because AUTHFORGE is a defensive authentication security assessment framework designed for authorized enterprise and lab evaluations, every contribution must uphold strict safety, secret-hygiene, and fail-closed verification rules.

## 1. Core Security & Ethical Non-Goals

- **Authorized Defensive Assessment Only**: AUTHFORGE never implements credential harvesting, password cracking/brute-forcing, MFA bypass, session hijacking, or stealth evasion.
- **Zero Secret Leakage Contract**: Passwords, password hashes, recovery codes, reset tokens, and session cookies must **never** be accepted as command-line arguments (which leak via `ps` / `/proc/<pid>/cmdline`), printed to `stdout`/`stderr`, written to logs, or stored in `findings.dat` / `checks.dat`.
- **Fail-Closed Online Gate (`core/authz.sh`)**: Any network check must call `authz_require_online`, `authz_resolve_target`, and `authz_consume_request` (`--allow-online` + unexpired `--scope FILE` with `test_accounts_only=yes`).

## 2. Bash 5+ & AWK Engineering Standards

1. **Interpreter & Strict Mode**:
   - Target **Bash 5.0+** on Debian / Ubuntu / Kali Linux.
   - Start executable scripts with `unset BASH_ENV ENV CDPATH` and `set -Eeuo pipefail`.
   - Never use `eval`, unquoted variable expansions, or source untrusted configuration files.
2. **Portable `awk` Delimiters (`mawk` and `gawk`)**:
   - Session data files (`findings.dat`, `checks.dat`, `suppressions.dat`, `evidence.log`) use ASCII Unit Separator (`0x1f`) as their field delimiter.
   - Inside `awk` programs, always define `US = sprintf("%c", 31)` in `BEGIN` (do not rely on literal `\x1f` regex/FS escapes, which behave differently in `mawk`).
   - For fixed-column TSV files such as `data/compliance_mappings.dat`, parse rows with `split($0, f, "\t") == 13` so empty optional columns never collapse.
3. **Filesystem & Locking Hygiene**:
   - Validate all directories lexically and via `stat` metadata (`! -L`, expected owner UID, `((8#$mode & 8#022) == 0)`).
   - Use same-directory `mktemp` + `chmod 600` + atomic `mv -f` for state updates.
   - Never run unrestricted `rm -rf` on user-supplied paths.

## 3. Module Architecture Contract

Each module in `modules/<id>.sh` (`id` matching `^[a-z][a-z0-9_]{1,31}$`) must define:

- `mod_<id>_info`: Prints `menu_no|title|summary|status` (`status` in `ready` or `partial`).
- `mod_<id>_main`: CLI entry point dispatching subcommands and recording check execution via `session_run_check "<module>:<subcommand>" "<target_type>" "<detail>" <handler_fn> "$@"`.
- `mod_<id>_menu`: Interactive TUI submenu handler propagating `EX_AUTHZ` (`5`), `EX_VALIDATION` (`6`), and `EX_DEPENDENCY` (`4`).

## 4. Verification Checklist Before Submitting a Patch

Run the full verification suite from the repository root:

```bash
# 1. Bash syntax check across all product and test scripts
make check

# 2. ShellCheck static analysis (style level on product code, warning level on tests)
make lint

# 3. Full unit, integration (CLI + TUI PTY), and secret-hygiene regression suite
bash tests/run.sh all
```

All existing and new tests must pass with `0` failures, and `tests/regression/test_secret_hygiene.sh` must confirm zero secret leakage across console output, logs, findings, reports, and subprocess `argv`.
