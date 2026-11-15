# AUTHFORGE Security Engineering & Architecture Interview Q&A

## Q1: Why does AUTHFORGE cap all 40 compliance controls at `PARTIAL` (`max_status = PARTIAL`) instead of reporting `PASS`?
- **Answer**: Static configuration descriptors (`sample-mfa.conf`, `sample-session.conf`), offline password/hash datasets, and single-URL lab HTTP/TLS probes cannot prove that a live production Credential Service Provider (CSP) enforces a control across every authentication endpoint, microservice, or user population. For example, `proto-audit tls` performs a single handshake and checks for a literal `"self-signed certificate"` notice rather than full X.509 path, SAN, and OCSP/CRL revocation validation. Reporting `PASS` from partial evidence creates false assurance; capping positive evaluations at `PARTIAL` while reporting verified violations as `FAIL` (and unexecuted/incomplete probes as `NOT TESTED`) keeps compliance reporting rigorous and auditable.

## Q2: Why do NIST SP 800-63B-4 `Sec.3.1.1.1`, `Sec.3.1.1.2`, and `Sec.3.2.5` evaluate conservatively to `PARTIAL` even when local datasets or profiles have findings?
- **Answer**:
  1. Under NIST SP 800-63B-4 `Sec.3.1.1.2`, password minimum length depends on authentication context (`>= 15` characters for single-factor passwords vs. `>= 8` characters when used with MFA). An unlinked local password/hash file or offline profile does not establish whether a target endpoint uses passwords as a single factor or with MFA, nor does a common password in a local file prove that a live target verifier accepted that password at registration.
  2. Under `Sec.3.2.5`, phishing resistance can be satisfied via channel binding (`Sec.3.2.5.1`) or verifier-name binding such as WebAuthn (`Sec.3.2.5.2`) depending on target AAL (AAL1/AAL2/AAL3).
  3. Therefore, AUTHFORGE records all underlying artifact findings in `findings.dat` (and flags the corresponding OWASP ASVS `5.0.0` / CIS `v8.1` controls), while keeping `Sec.3.1.1.1`, `Sec.3.1.1.2`, and `Sec.3.2.5` at `PARTIAL` when mapped checks complete and stripping any untrusted `target_linked` or `verifier_behavior_established` tokens from `checks.dat`.

## Q3: How does `session_record_check` prevent lockfile symlink races and concurrent ledger corruption?
- **Answer**:
  1. `_session_verify_droot_lexical` and `_session_verify_report_dirs` verify that `$AN_DATA_DIR` and `$AN_SESSION_REPORT_DIR` are non-symlink directories owned by `$(id -u)` with mode `0700` and matching `..` `(device, inode)` parent linkage.
  2. `.checks.lock` is initialized via `mktemp` (`0600`) + hardlink (`ln`) so an existing inode is never clobbered.
  3. After opening `exec {lock_fd}<>"$lockfile"`, `session_record_check` inspects `/proc/${BASHPID}/fd/${lock_fd}` (`stat -L -c '%F|%d|%i|%u|%a'`) with no pathname fallback, verifying `pre_lmeta == fd_lmeta == post_lmeta` before and after acquiring `flock -x -w "$tmo" "$lock_fd"`.
  4. Ledger updates are written to a same-directory `0600` `mktemp` file and atomically renamed over `checks.dat` via `mv -f`. Any failure sets `_AN_LEDGER_WRITE_FAILED=1` so the process cannot exit `0`.

## Q4: Why did M4-P3 introduce `validate_ipv4_ambiguous` before calling `getent`?
- **Answer**: Standard POSIX/BSD `inet_aton` resolvers accept octal leading zeros (`0177.0.0.1` -> `127.0.0.1`), hex octets (`0x7f.0.0.1`), shorthand 2/3-part addresses (`127.1`), and 32-bit integers (`2130706433`). If a string validator treats `0177.0.0.1` as a hostname while `getent` resolves it as `127.0.0.1`, scope comparison and network resolution can disagree. Rejecting all non-canonical numeric IPv4 forms and all-numeric/hex final DNS labels with `EX_VALIDATION` (`6`) prior to scope checking or `getent` eliminates resolver canonicalization mismatches.

## Q5: How does M5-P2 separate code (`AN_ROOT`) from mutable runtime state (`AN_DATA_DIR`) during installation and uninstallation?
- **Answer**:
  1. `scripts/install.sh` installs immutable code into `LIBDIR` (default `~/.local/share/authforge`) with an installation receipt (`.authforge-install.manifest`) and initializes mutable user state in `DATADIR` (default `~/.local/state/authforge`, mode `0700`).
  2. When `authforge.sh` detects `$AN_ROOT/.authforge-install.manifest` (or a read-only/root-owned `$AN_ROOT`), it defaults `AN_DATA_DIR` to the installed `datadir`, and `core/config.sh` routes `config backup` and atomic `config restore` to `$AN_DATA_DIR/config` and `$AN_DATA_DIR/profiles` without writing to `$AN_ROOT`.
  3. `scripts/uninstall.sh` verifies every file hash in `.authforge-install.manifest`, refuses to run if unmanifested or modified files exist in `LIBDIR`, removes files individually via `rm -f` and directories via `rmdir` (never `rm -rf`), and preserves `AN_DATA_DIR` unless `--purge-data` is explicitly passed and validated.
