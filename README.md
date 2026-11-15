# AUTHFORGE // ENTERPRISE SECURITY ENGINE

Authentication security assessment framework in **Bash 5+** (Kali / Ubuntu / Debian). Offline-first,
modular, authorization-gated. **Status: v0.1.0 — Milestone 5 (M5-P2).**

## Working Capabilities (M0–M5)
| Area | State |
|------|-------|
| Password Security Engine (02): `analyze`, `policy-check`, `policy-review`, `check-file`, `generate` | working |
| Hash Intelligence Engine (03): `identify`/`analyze`, `policy-check`, `policy-review`, `check-file` | working |
| Wordlist Analytics Engine (04): streaming `analyze`, `compare`, deduplicate/`clean` | working |
| MFA Security Assessment (05): offline `audit-config`, `audit-recovery`, `check-codes` | working |
| Session Security Analysis (07): offline `analyze` descriptor & `check-cookie` flag audit | working |
| Password Reset Security Audit (08): offline `analyze` reset-token strength, enumeration & workflow audit | working |
| Authorized Lab Online Checks (01, 06, 09): `auth-intel` (`scan`, `oidc-check`), `proto-audit` (`tls`, `http-auth`), `web-auth` (`headers`, `cookies`, `rate-limit-check`) | working (authz-gated, DNS-pinned, proxy-isolated, strict canonical IPv4 & RFC-1123 hostnames only; ambiguous numeric IPv4 & IPv6 rejected; missing `curl`/`openssl`/`timeout`/`getent` return `EX_DEPENDENCY=4` with `NOT TESTED`) |
| Risk Intelligence Engine (10): CVSS-inspired scoring, prioritization (`P1..P5`), deduplication, correlation (`CORR-01..08`), suppressions | working |
| Compliance Assessment Engine (11): 40-control pinned catalog (`25` OWASP ASVS `5.0.0`, `11` NIST SP `800-63B-4`, `4` CIS `v8.1`; conservative `PARTIAL` maximum positive status; `evaluate`, `gaps`, `catalog`, `export`) | working |
| Evidence Management Engine (12): kernel-`flock` check execution ledger (`checks.dat`), chain-of-custody log (`evidence.log`), SHA-256 manifests (`list`, `manifest`, `verify`), verifiable `.tar.gz` bundles (`bundle`, `verify-bundle`) | working |
| Reporting & Integrity (13): Terminal, JSON, CSV, Markdown (`md`), Plain-Text (`txt`) + SHA-256 manifests (`manifest`, `verify`) | working |
| Safe Launcher (`scripts/authforge-safe.sh`) & Rootless Installer/Uninstaller (`scripts/install.sh`, `scripts/uninstall.sh`) | working (`AN_ROOT` code / `AN_DATA_DIR` state separation, full manifest + SHA-256 + extra-file verification on both reinstall/upgrade and uninstall, preserving user data by default) |
| TUI (15-entry menu, submenus 01–15, resize-aware, UTF-8/ASCII fallback), `doctor`, `config backup`/`restore` | working |

## Quick Start (Repository Checkout Mode)
```bash
make all                                                                             # syntax + lint + full test suite (non-destructive)
./scripts/authforge-safe.sh doctor
./scripts/authforge-safe.sh -p legacy-audit password policy-review
./scripts/authforge-safe.sh --allow-online --scope scope.txt proto-audit tls 127.0.0.1:8443
./scripts/authforge-safe.sh --allow-online --scope scope.txt auth-intel scan http://127.0.0.1:8080/login
./scripts/authforge-safe.sh --allow-online --scope scope.txt web-auth cookies http://127.0.0.1:8080/login
./scripts/authforge-safe.sh risk evaluate
./scripts/authforge-safe.sh compliance evaluate
./scripts/authforge-safe.sh evidence verify
```

> **Warning on `make clean` / `make clean-data`**: Running `make clean` or `make clean-data` is **destructive** to runtime state in the repository checkout—it deletes all generated session directories, `findings.dat`, `checks.dat`, logs, evidence manifests, and configuration backups under `reports/`, `logs/`, `evidence/`, and `backups/` (retaining only `.gitkeep`). Do not run `make clean` if you want to preserve existing assessment sessions.

## Installation & Uninstallation (`scripts/install.sh` / `scripts/uninstall.sh`)

By default, AUTHFORGE installs in rootless user-local mode (`~/.local`), separating immutable code (`AN_ROOT`) from mutable per-user runtime data (`AN_DATA_DIR`):

```bash
# Preview installation paths without modifying the filesystem
./scripts/install.sh --dry-run

# Install to ~/.local/share/authforge (code), ~/.local/bin/authforge (launcher), and ~/.local/state/authforge (data)
./scripts/install.sh
# (Or via Makefile: make install)

# Run the installed CLI (writes sessions/logs/evidence/backups to ~/.local/state/authforge)
~/.local/bin/authforge doctor
~/.local/bin/authforge compliance catalog

# Uninstall code and launcher while PRESERVING ~/.local/state/authforge (reports, logs, evidence, backups)
./scripts/uninstall.sh
# (Or via Makefile: make uninstall)

# Uninstall code, launcher, AND purge the validated user data directory
./scripts/uninstall.sh --purge-data
```

- **Installation Manifest Versioning & V1->V2 Migration**:
  - `scripts/install.sh` writes `.authforge-install.manifest` using `format=authforge-install-manifest-v2`, which records both `DIR <relative-path> <octal-mode>` (e.g., `DIR core 755`) for all `10` runtime subdirectories and `FILE <octal-mode> <sha256> <relative-path>` for every installed file.
  - Both `scripts/install.sh` (when replacing an existing `LIBDIR`) and `scripts/uninstall.sh` verify all `8` required header lines, all `10` subdirectories, all `12` core anchor files, relative path confinement, non-symlink status, ownership (`$(id -u)` or `root`), strict 3-digit octal directory modes (`^[0-7]{3}$` with `(mode & 7022) == 0` and `(mode & 500) == 500`, rejecting 4-digit modes and `setuid`/`setgid`/`sticky` bits on both manifest and disk), exact directory modes (in `v2`), exact file modes and SHA-256 digests, and zero unlisted files on disk.
  - **V1 Compatibility**: If an existing installation uses `format=authforge-install-manifest-v1` (2-token `DIR <relative-path>`), `scripts/install.sh` performs a controlled migration only after verifying the complete `v1` header set, directory ownership/permission safety, every file's mode and SHA-256 digest, and the absence of any unlisted files. Once verified, `install.sh` atomically upgrades the installation to `v2` (rolling back to the untouched `v1` directory if post-swap launcher creation fails). If any check fails, both `install.sh` and `uninstall.sh` exit with `EX_VALIDATION` (`6`) and preserve the existing directory byte-for-byte without deleting or overwriting unverified files.

## Safe Launcher (`scripts/authforge-safe.sh`) & Environment Hygiene
- **Recommended invocation**: Run `./scripts/authforge-safe.sh [args...]` (or the installed `~/.local/bin/authforge [args...]`) directly, or via `env -u LD_PRELOAD -u LD_LIBRARY_PATH -u BASH_ENV -u ENV ./scripts/authforge-safe.sh [args...]`. Direct execution uses `/usr/bin/env -S env -u BASH_ENV -u ENV bash` so `BASH_ENV` and `ENV` are stripped before the launcher's Bash interpreter starts, and verifies that the code root and `authforge.sh` are owned by the current UID or `root` and are not group- or world-writable (`(mode & 022) == 0`).
- **Important warning on `bash scripts/authforge-safe.sh`**: Running `bash scripts/authforge-safe.sh` does **NOT** protect against `BASH_ENV` being processed before the launcher starts, because the caller's `bash` process evaluates `BASH_ENV` during its own startup before reading `scripts/authforge-safe.sh` (bypassing the `#!` shebang). If invoking via `bash`, run `env -u BASH_ENV -u ENV bash scripts/authforge-safe.sh [args...]`.
- **Variables intentionally removed by `scripts/authforge-safe.sh`**:
  - Shell startup & execution hooks: `BASH_ENV`, `ENV`, `PROMPT_COMMAND`, `PS4`, `SHELLOPTS`, `BASHOPTS`, `GLOBIGNORE`
  - Path & lookup overrides: `CDPATH`, `FIGNORE`, `EXECIGNORE`, `HOSTFILE`
  - Dynamic linker variables: `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `LD_DEBUG`, `LD_PROFILE`, `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`
  - Proxy & network/crypto overrides: `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `FTP_PROXY`, `NO_PROXY`, `http_proxy`, `https_proxy`, `all_proxy`, `ftp_proxy`, `no_proxy`, `CURL_HOME`, `OPENSSL_CONF`, `OPENSSL_ENGINES`, `OPENSSL_MODULES` (and forces `NO_PROXY="*"` / `no_proxy="*"`)
  - Exported shell functions: all `BASH_FUNC_*` environment entries
- **Remaining `LD_PRELOAD` limitation**: If `LD_PRELOAD`, `LD_LIBRARY_PATH`, or `LD_AUDIT` is set in the parent environment before `./scripts/authforge-safe.sh` is invoked, the OS dynamic linker (`ld-linux.so`) loads it into the initial `env`/`bash` launcher process at `execve()` time before script commands execute. Unsetting `LD_PRELOAD` inside the launcher prevents child processes (`authforge.sh`, `curl`, `openssl`, `getent`, `timeout`) from inheriting it (unless a preloaded library already hooked `execve`/`unsetenv`). To protect the launcher process itself, unset `LD_PRELOAD` in the parent (`env -u LD_PRELOAD -u LD_LIBRARY_PATH -u BASH_ENV -u ENV ./scripts/authforge-safe.sh`).

## Target Validation & Online Authorization Policy
Online checks fail closed unless `--allow-online`, a valid `--scope FILE`, and (by default) a local/lab target are provided. Only canonical dotted-quad IPv4 literals (`0..255` per octet, no leading zeros) and valid RFC-1123 hostnames (whose final label is neither all-numeric nor hex-numeric) are accepted. Ambiguous legacy numeric IPv4 representations (`0177.0.0.1`, `127.0.0.010`, `127.1`, `127.0.1`, `2130706433`, `0x7f.0.0.1`, `0x7f000001`, etc.) and IPv6 literals (`::1`, `[::1]`) are rejected with `EX_VALIDATION` (`6`) before scope comparison or DNS resolution (`getent`).

Docs: `docs/ARCHITECTURE.md` · `docs/compliance-mapping.md` · `docs/threat-model.md` · `docs/demo-walkthrough.md` · `docs/interview-qa.md` · `CONTRIBUTING.md` · `SECURITY.md` · `docs/entropy-model.md` · `docs/risk-model.md` · `docs/ROADMAP.md`
