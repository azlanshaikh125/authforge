# Security Policy

AUTHFORGE is for **authorized** assessments only. By design it never implements credential
theft, stealth, MFA bypass, account takeover, or uncontrolled brute force, and online checks are
refused unless an explicit, unexpired scope file names the target and confirms `test_accounts_only=yes`.

## Safe Invocation (`scripts/authforge-safe.sh`) & Environment Boundary
- **Direct execution**: Invoke `./scripts/authforge-safe.sh [args...]` directly. Its shebang (`#!/usr/bin/env -S env -u BASH_ENV -u ENV bash`) strips `BASH_ENV` and `ENV` before the launcher's Bash process starts, and the script then scrubs dangerous environment variables before `exec`-ing `/bin/bash --noprofile --norc authforge.sh "$@"`.
- **Why `bash scripts/authforge-safe.sh` is unsafe when `BASH_ENV` is set**: Running `bash scripts/authforge-safe.sh` invokes the caller's `bash` binary directly (bypassing the script's `#!` shebang). GNU Bash processes `BASH_ENV` during interpreter startup *before* reading `scripts/authforge-safe.sh`. Therefore, `bash scripts/authforge-safe.sh` does **not** protect against `BASH_ENV` being processed before the launcher starts. If you must invoke via `bash`, always run:
  ```bash
  env -u BASH_ENV -u ENV -u LD_PRELOAD -u LD_LIBRARY_PATH bash scripts/authforge-safe.sh [args...]
  ```
- **Environment variables intentionally removed by `scripts/authforge-safe.sh`**:
  - Shell startup & execution hooks: `BASH_ENV`, `ENV`, `PROMPT_COMMAND`, `PS4`, `SHELLOPTS`, `BASHOPTS`, `GLOBIGNORE`
  - Path & lookup overrides: `CDPATH`, `FIGNORE`, `EXECIGNORE`, `HOSTFILE`
  - Dynamic linker variables: `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `LD_DEBUG`, `LD_PROFILE`, `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`
  - Proxy & network/crypto overrides: `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `FTP_PROXY`, `NO_PROXY`, `http_proxy`, `https_proxy`, `all_proxy`, `ftp_proxy`, `no_proxy`, `CURL_HOME`, `OPENSSL_CONF`, `OPENSSL_ENGINES`, `OPENSSL_MODULES` (and enforces `NO_PROXY="*"` / `no_proxy="*"`)
  - Exported shell functions: all `BASH_FUNC_*` variables
- **Remaining limitations (`LD_PRELOAD` and parent process injection)**:
  - If `LD_PRELOAD`, `LD_LIBRARY_PATH`, or `LD_AUDIT` is set in the parent process environment prior to invoking `./scripts/authforge-safe.sh`, the OS dynamic linker (`ld-linux.so`) loads the specified shared object into the initial `env`/`bash` launcher process at `execve()` time before any script lines execute. While `scripts/authforge-safe.sh` removes `LD_PRELOAD` and `LD_LIBRARY_PATH` before `exec`-ing `authforge.sh` (preventing child processes such as `curl`, `openssl`, `getent`, and `timeout` from inheriting them unless the preloaded library hooked `execve`/`unsetenv`), complete protection against an untrusted parent environment requires unsetting `LD_PRELOAD` and `LD_LIBRARY_PATH` in the parent prior to execution (`env -u LD_PRELOAD -u LD_LIBRARY_PATH -u BASH_ENV -u ENV ./scripts/authforge-safe.sh`).

## Target Canonicalization & Numeric IPv4 Policy (M4-P3)
- Only canonical dotted-quad IPv4 addresses (`0..255` per octet, with no leading zeros) and valid RFC-1123 hostnames are accepted by `validate_ipv4`, `validate_hostname`, and `validate_target`.
- Ambiguous legacy `inet_aton` numeric IPv4 representations—including octal octets (`0177.0.0.1`, `127.0.0.010`, `010.0.0.1`), hexadecimal octets or integers (`0x7f.0.0.1`, `0x7f000001`, `127.0.0.0x1`), 1/2/3-part shorthand (`127.1`, `127.0.1`), and 32-bit decimal integers (`2130706433`)—are rejected with `EX_VALIDATION` (`6`) before scope matching or DNS resolution (`getent`), ensuring validation, scope authorization, and resolver canonicalization can never disagree.

## Session Containment, Check Ledger Locking & Install Safety (M5-P1 / M5-P2)
- **Session Path Containment (`core/session.sh`)**: `_session_verify_droot_lexical`, `_session_verify_report_dirs`, and `_session_verify_evidence_dirs` reject non-absolute paths, `/`, trailing `/`, repeated `//`, `.` and `..` segments, symlinks, non-owner UIDs, and group/world-writable modes, and verify `..` `(device, inode)` parent linkage.
- **Check Ledger Locking (`core/session.sh`)**: `session_record_check` acquires an exclusive kernel `flock` on `.checks.lock` and verifies `pre_lmeta == fd_lmeta == post_lmeta` via `/proc/${BASHPID}/fd/${lock_fd}` (failing closed if `/proc` is unavailable).
- **Evidence Manifest & Bundle Verification (`lib/evidence.sh`)**: `evidence_manifest_verify` rejects modified, missing, or unlisted extra files in `reports/<sid>/` and `evidence/<sid>/`. `evidence_verify_bundle` inspects archive entries pre-extraction to reject symlinks, hardlinks, special files, path traversal, absolute paths, and unexpected directories.
- **Installer & Uninstaller Safety (`scripts/install.sh`, `scripts/uninstall.sh`)**: `install.sh` separates immutable code (`AN_ROOT`) from mutable user data (`AN_DATA_DIR`, mode `0700`) and writes `.authforge-install.manifest` (`format=authforge-install-manifest-v2`), recording `DIR <relative-path> <octal-mode>` for all 10 subdirectories and `FILE <octal-mode> <sha256> <relative-path>` for all installed files. Before upgrading or uninstalling an existing `LIBDIR`, both `install.sh` and `uninstall.sh` verify all 8 header fields, all 10 subdirectories (checking ownership, non-symlink status, strict 3-digit octal modes `^[0-7]{3}$` with `(mode & 7022) == 0` and `(mode & 500) == 500`—rejecting 4-digit modes and `setuid`/`setgid`/`sticky` bits even if manifest and disk match—and exact recorded octal directory mode in `v2`), all 12 core anchor files, relative path confinement, exact file modes and SHA-256 digests, and the absence of any unlisted/extra files on disk. Legacy `format=authforge-install-manifest-v1` (`DIR <relative-path>`) installations are migrated to `v2` by `install.sh` (or uninstalled by `uninstall.sh`) only after passing full `v1` header, directory-permission-safety, file-mode/SHA-256, and zero-extra-file verification; `v1` directory entries are never silently reinterpreted as `v2`, and any validation failure aborts with `EX_VALIDATION` (`6`), leaving the existing directory byte-for-byte unchanged.
- **Filesystem Race Boundary**: Standard user-space POSIX scripts cannot eliminate all possible TOCTOU races against a concurrent process running under the same UID or `root`.

## Reporting a Vulnerability
- **Private Reporting Channel**: Do **not** open a public GitHub issue for security vulnerabilities in AUTHFORGE. Report vulnerabilities privately via **GitHub Private Vulnerability Reporting** (`Security` tab -> `Report a vulnerability` on the repository).
- **Maintainer Pre-Release Configuration Checklist**: Before publishing this repository publicly, the maintainer must enable *Private vulnerability reporting* in the GitHub repository settings (`Settings -> Code security and analysis -> Private vulnerability reporting`) or configure a dedicated security advisory contact address in this section.
- Include the AUTHFORGE version, OS/Bash/awk versions, and a minimal reproduction using synthetic data only (never include real credentials, hashes, or tokens).

See `docs/ARCHITECTURE.md` and `docs/threat-model.md` for full architecture and threat model details.
