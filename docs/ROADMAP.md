# Roadmap (each milestone ends with: syntax check, ShellCheck, tests, evidence, approval)

| Milestone | Scope |
|-----------|-------|
| **M0 (done)** | Foundation + Password engine (A) + findings model + JSON export + authz gate |
| **M1 (done)** | Hash Intelligence Engine (B) + Wordlist Analytics (C): format ID, ambiguity detection, KDF cost metadata, legacy warnings, streaming dedupe/distribution/encoding/policy reports, compare & clean |
| **M2 (done)** | Risk Engine (10) & Advanced Reporting (13): CVSS-inspired scoring, likelihood/impact/confidence prioritization (`P1..P5`), deduplication, cross-module correlation (`CORR-01..04`), false-positive/risk-acceptance workflow, Terminal/JSON/CSV/Markdown/TXT reports, SHA-256 evidence manifests & integrity checks |
| **M3 (done)** | Offline config reviews: MFA (05), Session (07), Password reset (08) from parsed descriptor files + `CORR-05`/`CORR-06` risk correlation |
| **M4 (done)** | Authorized lab-only protocol, auth-intel & web-auth checks (`06`, `01`, `09`) via fail-closed `authz` gate, local-lab guardrails, request budgets & `CORR-07`/`CORR-08` |
| **M5-P1 (done)** | Compliance engine (`11`: 40 controls across OWASP ASVS `5.0.0`, NIST SP `800-63B-4`, CIS `v8.1` in `data/compliance_mappings.dat` with conservative `PARTIAL` cap) & Evidence management (`12`: kernel-`flock` `checks.dat` ledger, `evidence.log`, SHA-256 manifests, verifiable `.tar.gz` bundles) |
| **M5-P2 (done)** | Rootless installer & manifest-verified uninstaller (`scripts/install.sh`, `scripts/uninstall.sh`), `AN_ROOT`/`AN_DATA_DIR` separation, `.gitignore`, `CONTRIBUTING.md`, and portfolio docs (`docs/compliance-mapping.md`, `docs/threat-model.md`, `docs/demo-walkthrough.md`, `docs/interview-qa.md`) |
