# Changelog

All notable changes to AUTHFORGE are documented in this file.

## [0.1.0-m5-p2] - 2026-11-15
### Added & Hardened (Milestone 5 Phase 2 — Installation, Code/Data Separation & Portfolio Docs)
- **Rootless Installer & Manifest-Verifying Uninstaller (`scripts/install.sh`, `scripts/uninstall.sh`, `Makefile`)**:
  - Added `scripts/install.sh` defaulting to user-local installation (`~/.local/share/authforge`, `~/.local/bin/authforge`, `~/.local/state/authforge`) with segment-aware lexical path validation, parent-chain symlink/permission checks, same-directory staging, rollback on failure, and `.authforge-install.manifest` receipt generation.
  - Added `scripts/uninstall.sh` verifying `.authforge-install.manifest` file hashes, refusing if unmanifested or modified files exist, removing files individually via `rm -f` + `rmdir` (never unrestricted `rm -rf`), preserving `AN_DATA_DIR` by default, and supporting `--purge-data` only after independent marker validation.
- **Code (`AN_ROOT`) vs. Mutable Data (`AN_DATA_DIR`) Separation (`authforge.sh`, `core/config.sh`, `scripts/authforge-safe.sh`)**:
  - Updated `authforge.sh` to default `AN_DATA_DIR` to the installed `datadir` (or `~/.local/state/authforge`) when running from an installed or read-only code tree while preserving `AN_DATA_DIR=$AN_ROOT` for repository checkouts.
  - Updated `core/config.sh` (`config_init`, `config_backup`, `config_restore`, `config_validate_all`) to store and atomically restore mutable configurations under `$AN_DATA_DIR/config` and `$AN_DATA_DIR/profiles` when running from an installed or read-only code tree, rejecting symlinked inputs/targets.
  - Hardened `scripts/authforge-safe.sh` to verify ownership (`uid == $(id -u) || uid == 0`) and non-group/world-writable modes (`(mode & 022) == 0`) on `_SAFE_ROOT`, `_SAFE_DIR`, `_SAFE_SELF`, and `authforge.sh`.
- **Documentation, Hygiene & Test Suite (`tests/unit/test_install.sh`, `docs/*.md`, `CONTRIBUTING.md`, `.gitignore`)**:
  - Added `.gitignore`, `CONTRIBUTING.md`, `docs/compliance-mapping.md`, `docs/threat-model.md`, `docs/demo-walkthrough.md`, `docs/interview-qa.md`, and `tests/unit/test_install.sh`.

## [0.1.0-m5-p1] - 2026-11-15
### Added & Hardened (Milestone 5 Phase 1 — Compliance Engine & Evidence Management)
- **40-Control Pinned Compliance Engine (`data/compliance_mappings.dat`, `lib/compliance.sh`, `modules/compliance.sh`)**:
  - Added external 13-column TSV catalog covering `25` OWASP ASVS `5.0.0` controls, `11` NIST SP `800-63B-4` controls, and `4` CIS Critical Security Controls `v8.1` safeguards (`40` controls total), all conservatively capped at `max_status=PARTIAL`.
  - Implemented conservative evaluation for NIST `Sec.3.1.1.1`, `Sec.3.1.1.2`, and `Sec.3.2.5`, online probe validity gates, and stripping of untrusted `target_linked` / `verifier_behavior_established` tokens.
- **Kernel-`flock` Check Ledger & Verifiable Evidence Bundles (`core/session.sh`, `lib/evidence.sh`, `modules/evidence.sh`)**:
  - Added `_session_verify_droot_lexical`, `_session_verify_report_dirs`, `_session_verify_evidence_dirs`, and `session_record_check` using `/usr/bin/flock` and fail-closed `/proc/<BASHPID>/fd/<lock_fd>` descriptor verification.
  - Added fail-closed `evidence_log_event`, atomic same-directory `evidence_manifest_update`, extra-file-detecting `evidence_manifest_verify`, `evidence_export_bundle`, and `evidence_verify_bundle`.

## [0.1.0-m4-p3] - 2026-11-13
### Fixed & Hardened (Milestone 4 Patch 3 — M4-P3)
- **Missing `curl` Dependency Exit Status & TUI Propagation (M4-P3-A)**:
  - Updated `core/authz.sh` (`authz_safe_http`) to check `command -v curl` before consuming a request-budget token and return `EX_DEPENDENCY` (`4`).
  - Updated `modules/proto_audit.sh` (`_pa_cmd_http_auth`), `modules/auth_intel.sh` (`_ai_cmd_scan`, `_ai_cmd_oidc_check`), and `modules/web_auth.sh` (`_wa_fetch`, `_wa_cmd_headers`, `_wa_cmd_cookies`, `_wa_cmd_rate_limit_check`) so that missing `curl` (or missing `getent` on hostname resolution) prints the explicit `[NOT TESTED]` explanation and returns `EX_DEPENDENCY` (`4`) instead of `0`.
  - Updated TUI menu handlers (`mod_proto_audit_menu`, `mod_auth_intel_menu`, `mod_web_auth_menu`) to propagate `EX_DEPENDENCY` (`4`) alongside `EX_AUTHZ` (`5`) and `EX_VALIDATION` (`6`) through `menu_main`.
- **Strict Canonical Numeric IPv4 Validation Before DNS Resolution (M4-P3-B)**:
  - Hardened `validate_ipv4`, added `validate_ipv4_ambiguous`, and updated `validate_hostname` and `validate_target` in `core/validate.sh` to reject ambiguous legacy `inet_aton` numeric IPv4 forms (`0177.0.0.1`, `127.0.0.010`, `010.0.0.1`, `127.1`, `127.0.1`, `2130706433`, `0x7f.0.0.1`, `0x7f000001`, `127.0.0.0x1`, `127.00.0.1`, `1.2.3.4.5`) with `EX_VALIDATION` (`6`) before scope authorization or DNS resolution (`getent`).
  - Hardened `authz_is_lab_target` and `authz_require_online` in `core/authz.sh` so scope `target=` entries are also validated with `validate_target`, guaranteeing validation and scope authorization cannot disagree due to resolver canonicalization.
- **Safe Environment-Sanitizing Launcher (`scripts/authforge-safe.sh` — M4-P3-C)**:
  - Added `scripts/authforge-safe.sh` (included in `Makefile` `SRC` and release archives) using `#!/usr/bin/env -S env -u BASH_ENV -u ENV bash` and `exec /usr/bin/env -u ... /bin/bash --noprofile --norc` to scrub `BASH_ENV`, `ENV`, `PROMPT_COMMAND`, `PS4`, `SHELLOPTS`, `BASHOPTS`, `GLOBIGNORE`, `CDPATH`, `FIGNORE`, `EXECIGNORE`, `HOSTFILE`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `LD_DEBUG`, `LD_PROFILE`, `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`, `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `FTP_PROXY`, `NO_PROXY`, `http_proxy`, `https_proxy`, `all_proxy`, `ftp_proxy`, `no_proxy`, `CURL_HOME`, `OPENSSL_CONF`, `OPENSSL_ENGINES`, `OPENSSL_MODULES`, and `BASH_FUNC_*` variables.
  - Documented safe launcher usage, removed variables, why `bash scripts/authforge-safe.sh` does not prevent the caller's `bash` from processing `BASH_ENV` prior to launcher start, and `LD_PRELOAD` dynamic linker limitations across `README.md`, `SECURITY.md`, and `docs/ARCHITECTURE.md`.
- **Regression & Loopback Verification Suite**:
  - Added unit, CLI integration, TUI integration, and real `socat` loopback tests covering missing `curl` (`EX_DEPENDENCY = 4`), ambiguous numeric IPv4 rejection (`EX_VALIDATION = 6`), and `scripts/authforge-safe.sh` environment sanitization.

## [0.1.0-m4-p1] - 2026-11-13
### Fixed & Hardened (Milestone 4 Security Review Patch — M4-AUD-01 through M4-AUD-08)
- `M4-AUD-01`: Pre-connection DNS resolution and IP pinning (`authz_resolve_target`, `curl --resolve`, `openssl s_client -connect`).
- `M4-AUD-02`: Propagated `EX_AUTHZ` (`5`) on request-budget exhaustion across CLI and TUI callers.
- `M4-AUD-03`: Deduplicated online authorization log messages per session+target.
- `M4-AUD-04`: Reset HTTP header parser state across multi-block HTTP responses.
- `M4-AUD-05`: Enforced consistent IPv6 literal rejection (`EX_VALIDATION = 6`).
- `M4-AUD-06`: Hardened `authz_safe_http` and `proto_probe_tls` against caller-controlled proxy bypass (`--noproxy '*'`, cleared proxy env vars).
- `M4-AUD-07`: Added `timeout` binary dependency check in `proto_probe_tls` (`EX_DEPENDENCY = 4`).
- `M4-AUD-08`: Captured `timeout` (`124`) and `openssl` exit statuses in `proto_probe_tls` and required valid negotiated protocol and non-null cipher in `proto_parse_tls_output`.
