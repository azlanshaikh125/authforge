# AUTHFORGE Compliance Mapping & Conservative Evaluation Specification

## 1. Pinned Standards & 40-Control Catalog (`data/compliance_mappings.dat`)

AUTHFORGE M5-P1/M5-P2 evaluates session check execution (`checks.dat`) and deduplicated security findings (`findings.dat`) against an external, 13-column TSV catalog (`data/compliance_mappings.dat`) containing **40 unique controls**:

| Framework | Pinned Version | Control Count | Mapped Control IDs | Legacy Crosswalk |
|---|---|---:|---|---|
| **OWASP ASVS** | `5.0.0` | **25** | `v5.0.0-6.2.1`, `6.2.4`, `6.2.5`, `6.2.9`, `6.3.1`, `6.3.3`, `6.3.8`, `6.4.2`, `6.4.3`, `6.5.1`, `6.5.2`, `6.5.4`, `6.5.5`, `6.6.1`, `3.3.1`, `3.3.2`, `3.3.4`, `3.4.1`, `3.4.3`, `7.2.3`, `7.2.4`, `10.4.6`, `11.4.2`, `12.1.1`, `12.2.2` | OWASP ASVS `4.0.3` |
| **NIST SP 800-63B** | `800-63B-4` | **11** | `Sec.3.1.1.1`, `Sec.3.1.1.2`, `Sec.3.1.2.2`, `Sec.3.1.3.1`, `Sec.3.1.3.3`, `Sec.3.1.4.2`, `Sec.3.2.2`, `Sec.3.2.5`, `Sec.3.2.7`, `Sec.4.2.1.1`, `Sec.5.1.1` | NIST SP `800-63B Rev. 3` |
| **CIS Critical Security Controls** | `v8.1` | **4** | `3.10`, `5.2`, `6.3`, `6.5` | CIS Controls `v8.0` |
| **Total** | — | **40** | `25 + 11 + 4 = 40` controls | — |

## 2. 13-Column TSV Schema (`data/compliance_mappings.dat`)

`compliance_load_catalog` in `lib/compliance.sh` validates that `data/compliance_mappings.dat` is a regular, non-symlink file with no group/world write bits (`(mode & 022) == 0`) and parses each row using `LC_ALL=C awk` with `split($0, f, "\t") == 13`:

1. `framework` (`ASVS`, `NIST`, `CIS`)
2. `version` (`5.0.0`, `800-63B-4`, `v8.1`)
3. `control_id` (unique per framework)
4. `section`
5. `level` (e.g., `L1`/`L2`, `AAL1/AAL2`, `IG1`/`IG2`)
6. `title`
7. `summary`
8. `required_checks` (comma-separated `<module>:<subcommand>` IDs)
9. `fail_gates` (probe/evaluation gate directive; may be empty)
10. `finding_regex` (`|`-separated regex matched against active finding titles)
11. `max_status` (`PARTIAL` for all 40 controls)
12. `scope_limit` (explicit statement of what offline/lab checks cannot prove)
13. `legacy_crosswalk` (ASVS `4.0.3` / NIST `Rev. 3` / CIS `v8.0` reference)

## 3. Conservative Evaluation Rules (`max_status = PARTIAL`)

AUTHFORGE does **not** claim to prove full regulatory compliance or perform automated penetration testing:

1. **Maximum Positive Status Is `PARTIAL`**:
   - Every control in `data/compliance_mappings.dat` has `max_status = PARTIAL` (`0` controls can evaluate to `PASS`).
   - Offline configuration descriptors (`sample-mfa.conf`, `sample-session.conf`, `sample-pwreset.conf`), local password/hash datasets, and bounded single-URL lab probes cannot verify full runtime enforcement across all production endpoints, user populations, or certificate chains.
2. **Conservative NIST SP 800-63B-4 Rules (`Sec.3.1.1.1`, `Sec.3.1.1.2`, `Sec.3.2.5`)**:
   - **`Sec.3.1.1.1` (*Password Authenticators*)**: Covers subscriber/CSP password selection and prohibition of composition rules (blocklist screening belongs to `Sec.3.1.1.2`). Because an offline profile (`policy_require_classes`) does not prove live CSP verifier behavior on subscriber registration, `Sec.3.1.1.1` evaluates to `PARTIAL` when `password:policy-review` completed and `NOT TESTED` otherwise.
   - **`Sec.3.1.1.2` (*Password Verifiers*)**: Requires `>= 15` characters for single-factor passwords and `>= 8` characters for MFA passwords, blocklist comparison at creation/change, no composition rules, and salted (`>= 32-bit`) KDF storage. Because unlinked local datasets and profiles cannot establish whether a target verifier uses passwords as single-factor vs. MFA or whether a live verifier accepted a weak password—and because `max >= 64` and KDF work-factor tuning are `SHOULD` recommendations—`Sec.3.1.1.2` evaluates to `PARTIAL` when mapped checks complete and `NOT TESTED` otherwise, while preserving all underlying findings in `findings.dat`.
   - **`Sec.3.2.5` (*Phishing Resistance*)**: Distinguishes channel binding (`Sec.3.2.5.1`) from verifier-name binding such as WebAuthn (`Sec.3.2.5.2`) across AAL1/AAL2/AAL3. Evaluates to `PARTIAL` when `mfa:audit-config` completes and `NOT TESTED` otherwise.
3. **Untrusted Ledger Metadata Stripping**:
   - Both `session_record_check` (`core/session.sh`) and `compliance_evaluate_session` (`lib/compliance.sh`) strip any `target_linked=*` or `verifier_behavior_established=*` tokens so manually edited `checks.dat` rows cannot force false `FAIL` or `PASS` outcomes.
4. **Online Probe Validity Gates**:
   - If `proto-audit:tls` times out (`tls_handshake_ok=0`), `auth-intel:oidc-check` finds no discovery document (`oidc_found=0`), or `web-auth:cookies` observes zero `Set-Cookie` headers (`cookies_seen=0`), the corresponding controls remain `NOT TESTED`.
