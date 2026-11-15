# AUTHFORGE End-to-End Demonstration Walkthrough (M0–M5)

This walkthrough demonstrates AUTHFORGE across offline credential/configuration audits, risk correlation, 40-control compliance evaluation, cryptographic evidence bundling, and rootless user-local installation.

## 1. Environment Diagnostics & Safe Launcher Verification

```bash
# Verify syntax and run the full test suite (without deleting existing sessions)
make all

# Run system diagnostics via the environment-sanitizing safe launcher
./scripts/authforge-safe.sh --no-color doctor
```

Expected output highlights:
- `bash 5.x`, all required commands (`awk`, `sed`, `grep`, `flock`, `sha256sum`, etc.), `/dev/urandom`, and writable data directories report `[PASS]`.

## 2. Offline Password, Hash, and Wordlist Audits (M0–M1)

```bash
# Audit password policy under the legacy-audit profile
./scripts/authforge-safe.sh --no-color -p legacy-audit password policy-review

# Batch-audit sample password and hash datasets (secrets/hashes are never printed)
./scripts/authforge-safe.sh --no-color password check-file fixtures/sample-passwords.txt
./scripts/authforge-safe.sh --no-color hash check-file fixtures/sample-hashes.txt

# Analyze wordlist hygiene and overlap with common passwords
./scripts/authforge-safe.sh --no-color wordlist compare fixtures/sample-wordlist.txt fixtures/common-passwords-sample.txt
```

## 3. Offline MFA, Session Management, and Password Reset Audits (M3)

```bash
./scripts/authforge-safe.sh --no-color mfa audit-config fixtures/sample-mfa.conf
./scripts/authforge-safe.sh --no-color mfa audit-recovery fixtures/sample-mfa.conf
./scripts/authforge-safe.sh --no-color session-audit analyze fixtures/sample-session.conf
./scripts/authforge-safe.sh --no-color pwreset analyze fixtures/sample-pwreset.conf
```

## 4. Risk Correlation & Prioritized Remediation Reporting (M2)

```bash
# Evaluate deduplicated findings, CVSS-inspired scores, and compound chains (CORR-01..08)
./scripts/authforge-safe.sh --no-color risk evaluate

# Export Markdown risk report for the latest session
./scripts/authforge-safe.sh --no-color risk report --format md -o /tmp/authforge-risk-report.md
```

## 5. 40-Control Compliance Evaluation & Evidence Bundling (M5-P1)

```bash
# Inspect the pinned 40-control catalog (25 OWASP ASVS 5.0.0 + 11 NIST SP 800-63B-4 + 4 CIS v8.1)
./scripts/authforge-safe.sh --no-color compliance catalog

# Evaluate the latest session against all 40 controls (max positive status = PARTIAL)
./scripts/authforge-safe.sh --no-color compliance evaluate

# Inspect the session check execution ledger (checks.dat) and verify SHA-256 manifest
./scripts/authforge-safe.sh --no-color evidence list
./scripts/authforge-safe.sh --no-color evidence verify

# Package a standalone, verifiable .tar.gz evidence bundle and verify it
./scripts/authforge-safe.sh --no-color evidence bundle -o /tmp/session-evidence.tar.gz
./scripts/authforge-safe.sh --no-color evidence verify-bundle /tmp/session-evidence.tar.gz
rm -f /tmp/authforge-risk-report.md /tmp/session-evidence.tar.gz
```

## 6. Rootless User-Local Installation & Safe Uninstallation (M5-P2)

```bash
# Dry-run user-local installation (~/.local/share/authforge, ~/.local/bin/authforge, ~/.local/state/authforge)
./scripts/install.sh --dry-run

# Install into an isolated test prefix
./scripts/install.sh --libdir /tmp/an-demo-lib --bindir /tmp/an-demo-bin --datadir /tmp/an-demo-data

# Run from the installed launcher (writes session data to /tmp/an-demo-data, keeping /tmp/an-demo-lib read-only-safe)
/tmp/an-demo-bin/authforge --no-color -p default password policy-review
/tmp/an-demo-bin/authforge --no-color compliance evaluate
/tmp/an-demo-bin/authforge --no-color evidence verify

# Uninstall code and launcher while preserving /tmp/an-demo-data
./scripts/uninstall.sh --libdir /tmp/an-demo-lib --bindir /tmp/an-demo-bin --datadir /tmp/an-demo-data
ls -la /tmp/an-demo-data/reports

# Clean up demo data directory
rm -rf /tmp/an-demo-bin /tmp/an-demo-data
```
